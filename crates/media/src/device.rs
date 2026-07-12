//! Microphone capture and speaker playback via cpal.
//!
//! HARDWARE PATH: this cannot be unit-tested headlessly (no mic/speaker in CI),
//! so it is compile-verified here and must be validated by running on a real
//! device. It builds on the tested helpers in [`crate::frame`] and the codec in
//! [`crate::audio`].
//!
//! Assumes the device runs at the codec rate (48 kHz). A device that only
//! offers another rate needs a resampler inserted here (a follow-up); the code
//! warns loudly rather than silently producing wrong-rate audio.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, Stream};

use crate::audio::SAMPLE_RATE_HZ;
use crate::frame::{downmix_to_mono, f32_to_i16, i16_to_f32, FrameAccumulator};
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
        Ok(devs) => devs.filter_map(|d| device_name(&d)).collect(),
        Err(_) => Vec::new(),
    }
}

/// Names of the available output (speaker) devices, for a settings picker.
pub fn output_device_names() -> Vec<String> {
    let host = cpal::default_host();
    match host.output_devices() {
        Ok(devs) => devs.filter_map(|d| device_name(&d)).collect(),
        Err(_) => Vec::new(),
    }
}

/// The human-readable name of a device, or `None` if it cannot be described
/// (e.g. it was disconnected mid-enumeration). cpal 0.18 exposes the name via
/// the structured [`DeviceDescription`](cpal::DeviceDescription).
fn device_name(device: &cpal::Device) -> Option<String> {
    device.description().ok().map(|d| d.name().to_string())
}

/// Resolve an input device by name, falling back to the host default when the
/// name is `None` or no longer present (e.g. the device was unplugged).
fn resolve_input(host: &cpal::Host, name: Option<&str>) -> Option<cpal::Device> {
    if let Some(want) = name {
        if let Ok(mut devs) = host.input_devices() {
            if let Some(d) = devs.find(|d| device_name(d).as_deref() == Some(want)) {
                return Some(d);
            }
        }
    }
    host.default_input_device()
}

/// Resolve an output device by name, falling back to the host default.
fn resolve_output(host: &cpal::Host, name: Option<&str>) -> Option<cpal::Device> {
    if let Some(want) = name {
        if let Ok(mut devs) = host.output_devices() {
            if let Some(d) = devs.find(|d| device_name(d).as_deref() == Some(want)) {
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
        let host = cpal::default_host();
        let device = resolve_input(&host, name)
            .ok_or_else(|| MediaError::Codec("no input device available".into()))?;
        let supported = device.default_input_config().map_err(codec_err)?;
        let sample_format = supported.sample_format();
        let config = supported.config();
        let channels = config.channels as usize;

        if config.sample_rate as usize != SAMPLE_RATE_HZ {
            eprintln!(
                "warning: input device is {} Hz but the codec expects {} Hz; resampling needed",
                config.sample_rate, SAMPLE_RATE_HZ
            );
        }

        let (tx, rx) = mpsc::channel::<Vec<i16>>();
        let mut acc = FrameAccumulator::new();
        let on_error = |e| eprintln!("input stream error: {e}");

        let stream = match sample_format {
            SampleFormat::F32 => device.build_input_stream(
                config,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    let mono = downmix_to_mono(data, channels);
                    let pcm: Vec<i16> = mono.iter().map(|&s| f32_to_i16(s)).collect();
                    acc.push(&pcm, |frame| {
                        let _ = tx.send(frame.to_vec());
                    });
                },
                on_error,
                None,
            ),
            SampleFormat::I16 => device.build_input_stream(
                config,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    let floats: Vec<f32> = data.iter().map(|&s| i16_to_f32(s)).collect();
                    let mono = downmix_to_mono(&floats, channels);
                    let pcm: Vec<i16> = mono.iter().map(|&s| f32_to_i16(s)).collect();
                    acc.push(&pcm, |frame| {
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
        Ok((Self { _stream: stream }, rx))
    }
}

/// Plays decoded mono frames on the default output device. Hold it alive to keep
/// the stream open; feed it with [`AudioPlayback::push`].
pub struct AudioPlayback {
    _stream: Stream,
    queue: Arc<Mutex<VecDeque<i16>>>,
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

        let queue = Arc::new(Mutex::new(VecDeque::<i16>::new()));
        let q = queue.clone();
        let on_error = |e| eprintln!("output stream error: {e}");

        let stream = match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                config,
                move |out: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let mut q = q.lock().unwrap();
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
                    let mut q = q.lock().unwrap();
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
            queue,
        })
    }

    /// Enqueue decoded mono samples for playback.
    pub fn push(&self, mono: &[i16]) {
        self.queue.lock().unwrap().extend(mono.iter().copied());
    }

    /// A `Send` handle to this device's playback queue, so a decode task on
    /// another thread can feed audio while the (non-`Send`) cpal stream stays
    /// on the thread that created it.
    pub fn sink(&self) -> PlaybackSink {
        PlaybackSink {
            queue: self.queue.clone(),
        }
    }
}

/// A cloneable, `Send` handle for feeding decoded mono samples to an
/// [`AudioPlayback`] from another thread or async task.
#[derive(Clone)]
pub struct PlaybackSink {
    queue: Arc<Mutex<VecDeque<i16>>>,
}

impl PlaybackSink {
    pub fn push(&self, mono: &[i16]) {
        self.queue.lock().unwrap().extend(mono.iter().copied());
    }
}
