//! Microphone capture and speaker playback via cpal.
//!
//! HARDWARE PATH: this cannot be unit-tested headlessly (no mic/speaker in CI),
//! so it is compile-verified here and must be validated by running on a real
//! device. It builds on the tested helpers in [`crate::frame`] and the codec in
//! [`crate::audio`].
//!
//! Each device opens at its own native rate (a shared-mode device often cannot
//! be forced to another rate), and a [`Resampler`] bridges that rate to the
//! codec's fixed 48 kHz: native -> 48 kHz on capture, 48 kHz -> native on
//! playback. Without it, e.g. a 96 kHz speaker would play our 48 kHz audio an
//! octave high and choppy.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{ErrorKind, SampleFormat, Stream};

use crate::audio::SAMPLE_RATE_HZ;
use crate::frame::{
    downmix_i16_to_mono_into, downmix_to_mono_into, f32_to_i16, i16_to_f32, FrameAccumulator,
    Resampler,
};
use crate::MediaError;

fn codec_err(e: impl std::fmt::Display) -> MediaError {
    MediaError::Codec(e.to_string())
}

/// Names of the available input (microphone) devices, for a settings picker.
/// Empty if the host cannot enumerate; the default device is always usable
/// regardless of whether it appears here.
pub fn input_device_names() -> Vec<String> {
    let host = cpal::default_host();
    match host.input_devices() {
        Ok(devs) => pickable_names(devs.filter(offerable).filter_map(|d| device_name(&d))),
        Err(_) => Vec::new(),
    }
}

/// Names of the available output (speaker) devices, for a settings picker.
pub fn output_device_names() -> Vec<String> {
    let host = cpal::default_host();
    match host.output_devices() {
        Ok(devs) => pickable_names(devs.filter(offerable).filter_map(|d| device_name(&d))),
        Err(_) => Vec::new(),
    }
}

/// On a PipeWire/PulseAudio system, ALSA also exposes the raw hardware PCMs
/// (`hw:`/`plughw:`/`front:`/`hdmi:`/`iec958:`/`dmix:` and every `CARD=`-specific
/// node). The sound server holds that hardware exclusively, so opening a raw PCM
/// directly collides with it -- and picking the same headset's hardware for BOTH
/// capture and playback fails with "device busy". Only the server-routed virtual
/// PCMs (`default`/`pipewire`/`pulse`/`jack`/`sysdefault`) can be shared and can
/// serve input and output at once, so the picker offers only those; the physical
/// device is chosen in the system's audio settings, which is how routing works on
/// a modern Linux desktop.
#[cfg(target_os = "linux")]
fn is_shared_pcm(id: &str) -> bool {
    if id.contains("CARD=") {
        return false; // a specific hardware card, not the shared server node
    }
    let head = id.split(':').next().unwrap_or(id);
    matches!(
        head,
        "default" | "pipewire" | "pulse" | "jack" | "sysdefault"
    )
}

/// Whether to offer this device in the picker (and accept it by name). On Linux
/// only the shareable server-routed PCMs are offered (see [`is_shared_pcm`]);
/// other platforms enumerate real devices that do not have this exclusivity
/// problem, so everything cpal reports is offered.
#[cfg(target_os = "linux")]
fn offerable(d: &cpal::Device) -> bool {
    use cpal::traits::DeviceTrait;
    d.id().map(|id| is_shared_pcm(id.id())).unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn offerable(_d: &cpal::Device) -> bool {
    true
}

/// Devices are selected by name (first match), so a picker entry is only
/// meaningful if its name is unique -- ALSA exposes one truncated name for
/// many subdevices; keep the first. The ALSA `null` device ("Discard all
/// samples...") is a bit bucket no one shares a call through; hide it.
fn pickable_names(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    names
        .filter(|n| !n.starts_with("Discard all samples"))
        .filter(|n| seen.insert(n.clone()))
        .collect()
}

/// The human-readable name of a device, or `None` if it cannot be described
/// (e.g. it was disconnected mid-enumeration). cpal 0.18 exposes the name via
/// the structured [`DeviceDescription`](cpal::DeviceDescription).
fn device_name(device: &cpal::Device) -> Option<String> {
    device.description().ok().map(|d| d.name().to_string())
}

/// Resolve an input device by name, falling back to the host default when the
/// name is `None`, no longer present (e.g. the device was unplugged), or not
/// offerable (a stale preference for a raw hardware PCM we no longer use; see
/// [`offerable`]) -- so a saved raw-device choice can never reintroduce the
/// same-headset "busy" conflict.
fn resolve_input(host: &cpal::Host, name: Option<&str>) -> Option<cpal::Device> {
    if let Some(want) = name {
        if let Ok(mut devs) = host.input_devices() {
            if let Some(d) = devs.find(|d| offerable(d) && device_name(d).as_deref() == Some(want))
            {
                return Some(d);
            }
        }
    }
    host.default_input_device()
}

/// Resolve an output device by name, falling back to the host default (see
/// [`resolve_input`] for why non-offerable names fall back too).
fn resolve_output(host: &cpal::Host, name: Option<&str>) -> Option<cpal::Device> {
    if let Some(want) = name {
        if let Ok(mut devs) = host.output_devices() {
            if let Some(d) = devs.find(|d| offerable(d) && device_name(d).as_deref() == Some(want))
            {
                return Some(d);
            }
        }
    }
    host.default_output_device()
}

/// Captures an input device, emitting mono 48 kHz i16 frames over the returned
/// receiver. Hold the [`AudioCapture`] alive to keep the stream open.
pub struct AudioCapture {
    _stream: Stream,
}

impl AudioCapture {
    /// Capture the host default input device.
    pub fn start() -> Result<(Self, Receiver<Vec<i16>>), MediaError> {
        Self::start_on(None)
    }

    /// Capture a named input device, or the host default when `name` is `None`
    /// or the named device is not present.
    pub fn start_on(name: Option<&str>) -> Result<(Self, Receiver<Vec<i16>>), MediaError> {
        let (tx, rx) = mpsc::channel::<Vec<i16>>();
        Ok((Self::start_on_into(name, tx)?, rx))
    }

    /// Capture into a caller-owned channel. The caller keeps the [`Sender`]'s
    /// receiving end open, so the capture device can be swapped underneath a
    /// running consumer (live device switching) by dropping this [`AudioCapture`]
    /// and starting a new one into a clone of the same sender -- the consumer
    /// never sees the channel close.
    pub fn start_on_into(name: Option<&str>, tx: Sender<Vec<i16>>) -> Result<Self, MediaError> {
        let host = cpal::default_host();
        let device = resolve_input(&host, name)
            .ok_or_else(|| MediaError::Codec("no input device available".into()))?;
        let supported = device.default_input_config().map_err(codec_err)?;
        let sample_format = supported.sample_format();
        let config = supported.config();
        let channels = config.channels as usize;
        // Bridge the device's native rate to the codec's 48 kHz.
        let mut resampler = Resampler::new(config.sample_rate, SAMPLE_RATE_HZ as u32);

        let mut acc = FrameAccumulator::new();
        // Reused scratch buffers so the real-time callback never allocates on the
        // hot path (heap allocation in an audio callback is a classic cause of
        // buffer under/overruns). Only the per-frame `to_vec` into the channel
        // remains, which happens at the 20 ms frame rate, not every callback.
        let mut mono: Vec<f32> = Vec::new();
        let mut native: Vec<i16> = Vec::new();
        let mut resampled: Vec<i16> = Vec::new();
        // Several very different failures arrive here, and conflating them
        // misleads. An xrun (buffer under/overrun) recovers on its own; a route
        // change is auto-rerouted and the stream keeps running; but
        // DeviceNotAvailable/StreamInvalidated mean the device went away
        // (unplugged, or a PipeWire/Bluetooth profile switch) and cpal does NOT
        // restart the stream -- capture is dead until the mic is re-selected.
        // Report the first of each honestly, then stay quiet so a burst does not
        // flood the console (which reads as a hard failure).
        let mut warned_xrun = false;
        let mut warned_changed = false;
        let mut warned_gone = false;
        let mut warned_other = false;
        let on_error = move |e: cpal::Error| match e.kind() {
            ErrorKind::Xrun => {
                if !warned_xrun {
                    warned_xrun = true;
                    eprintln!("input stream xrun: buffer under/overrun (recovering; further xruns silenced)");
                }
            }
            ErrorKind::DeviceChanged => {
                if !warned_changed {
                    warned_changed = true;
                    eprintln!("input audio route changed; capture rerouted and continues");
                }
            }
            ErrorKind::DeviceNotAvailable | ErrorKind::StreamInvalidated => {
                if !warned_gone {
                    warned_gone = true;
                    eprintln!(
                        "input device disconnected: capture stopped (re-select the mic to resume)"
                    );
                }
            }
            _ => {
                if !warned_other {
                    warned_other = true;
                    eprintln!("input stream error: {e}");
                }
            }
        };

        let stream = match sample_format {
            SampleFormat::F32 => device.build_input_stream(
                config,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    downmix_to_mono_into(data, channels, &mut mono);
                    native.clear();
                    native.extend(mono.iter().map(|&s| f32_to_i16(s)));
                    resampled.clear();
                    resampler.process(&native, &mut resampled);
                    acc.push(&resampled, |frame| {
                        let _ = tx.send(frame.to_vec());
                    });
                },
                on_error,
                None,
            ),
            SampleFormat::I16 => device.build_input_stream(
                config,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    // i16 downmixes to mono directly (no f32 round-trip).
                    downmix_i16_to_mono_into(data, channels, &mut native);
                    resampled.clear();
                    resampler.process(&native, &mut resampled);
                    acc.push(&resampled, |frame| {
                        let _ = tx.send(frame.to_vec());
                    });
                },
                on_error,
                None,
            ),
            other => {
                return Err(MediaError::Codec(format!(
                    "unsupported input sample format {other:?}"
                )))
            }
        }
        .map_err(codec_err)?;

        stream.play().map_err(codec_err)?;
        Ok(Self { _stream: stream })
    }
}

/// The shared playback state: the device-rate sample queue the audio callback
/// drains, and the 48 kHz -> device-rate resampler that fills it. Both live
/// behind mutexes because the feeder ([`PlaybackSink::push`]) runs on a
/// different thread than the audio callback.
struct PlaybackInner {
    queue: Mutex<VecDeque<i16>>,
    resampler: Mutex<Resampler>,
}

impl PlaybackInner {
    /// Accept decoded 48 kHz mono samples, resample to the device rate, and
    /// enqueue them for the audio callback.
    fn feed(&self, mono48k: &[i16]) {
        let mut native = Vec::with_capacity(mono48k.len() + 8);
        self.resampler.lock().unwrap().process(mono48k, &mut native);
        self.queue.lock().unwrap().extend(native);
    }
}

/// Plays decoded 48 kHz mono frames on an output device. Hold it alive to keep
/// the stream open; feed it 48 kHz mono via [`AudioPlayback::push`] or a
/// [`PlaybackSink`].
pub struct AudioPlayback {
    _stream: Stream,
    inner: Arc<PlaybackInner>,
}

impl AudioPlayback {
    /// Play on the host default output device.
    pub fn start() -> Result<Self, MediaError> {
        Self::start_on(None)
    }

    /// Play on a named output device, or the host default when `name` is `None`
    /// or the named device is not present.
    pub fn start_on(name: Option<&str>) -> Result<Self, MediaError> {
        let host = cpal::default_host();
        let device = resolve_output(&host, name)
            .ok_or_else(|| MediaError::Codec("no output device available".into()))?;
        let supported = device.default_output_config().map_err(codec_err)?;
        let sample_format = supported.sample_format();
        let config = supported.config();
        let channels = config.channels as usize;

        let inner = Arc::new(PlaybackInner {
            queue: Mutex::new(VecDeque::new()),
            // Decoded audio is 48 kHz; the device consumes at its native rate.
            resampler: Mutex::new(Resampler::new(SAMPLE_RATE_HZ as u32, config.sample_rate)),
        });
        let cb = inner.clone();
        let on_error = |e| eprintln!("output stream error: {e}");

        let stream = match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                config,
                move |out: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let mut q = cb.queue.lock().unwrap();
                    for frame in out.chunks_mut(channels) {
                        let sample = q.pop_front().map(i16_to_f32).unwrap_or(0.0);
                        frame.iter_mut().for_each(|slot| *slot = sample);
                    }
                },
                on_error,
                None,
            ),
            SampleFormat::I16 => device.build_output_stream(
                config,
                move |out: &mut [i16], _: &cpal::OutputCallbackInfo| {
                    let mut q = cb.queue.lock().unwrap();
                    for frame in out.chunks_mut(channels) {
                        let sample = q.pop_front().unwrap_or(0);
                        frame.iter_mut().for_each(|slot| *slot = sample);
                    }
                },
                on_error,
                None,
            ),
            other => {
                return Err(MediaError::Codec(format!(
                    "unsupported output sample format {other:?}"
                )))
            }
        }
        .map_err(codec_err)?;

        stream.play().map_err(codec_err)?;
        Ok(Self {
            _stream: stream,
            inner,
        })
    }

    /// Enqueue decoded 48 kHz mono samples for playback.
    pub fn push(&self, mono48k: &[i16]) {
        self.inner.feed(mono48k);
    }

    /// Drop any audio still queued for playback (stops the current clip at once).
    /// Used to pause/restart a voice message without letting clips pile up.
    pub fn clear(&self) {
        self.inner.queue.lock().unwrap().clear();
    }

    /// A `Send` handle to this device's playback feed, so a decode task on
    /// another thread can feed audio while the (non-`Send`) cpal stream stays
    /// on the thread that created it.
    pub fn sink(&self) -> PlaybackSink {
        PlaybackSink {
            inner: self.inner.clone(),
        }
    }
}

/// A cloneable, `Send` handle for feeding decoded 48 kHz mono samples to an
/// [`AudioPlayback`] from another thread or async task.
#[derive(Clone)]
pub struct PlaybackSink {
    inner: Arc<PlaybackInner>,
}

impl PlaybackSink {
    pub fn push(&self, mono48k: &[i16]) {
        self.inner.feed(mono48k);
    }
}
