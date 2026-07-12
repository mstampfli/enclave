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

/// Captures the default input device, emitting mono 48 kHz i16 frames over the
/// returned receiver. Hold the [`AudioCapture`] alive to keep the stream open.
pub struct AudioCapture {
    _stream: Stream,
}

impl AudioCapture {
    pub fn start() -> Result<(Self, Receiver<Vec<i16>>), MediaError> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or_else(|| MediaError::Codec("no default input device".into()))?;
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
    pub fn start() -> Result<Self, MediaError> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or_else(|| MediaError::Codec("no default output device".into()))?;
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
