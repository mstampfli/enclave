//! WASAPI loopback capture of system audio (Windows).
//!
//! [`LoopbackMode::Process`] uses the process-loopback virtual device (the
//! target app and its children only); [`LoopbackMode::System`] captures the
//! default render endpoint mix. Modes, the shared mix ring, and the mono
//! down-mix live in [`super`].
//!
//! Captured audio is force-converted to 48 kHz / stereo / 16-bit by the audio
//! engine (`AUTOCONVERTPCM`) and pushed through [`super::mix_in_stereo_i16`].
//!
//! The device is `!Send` COM, so a capture is created and pumped on one
//! dedicated thread and never crosses threads.
//!
//! HARDWARE PATH: WASAPI loopback cannot be exercised headlessly; this is
//! compile-verified and validated on a real machine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;

use windows::core::{implement, IUnknown, Interface, Ref, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, E_FAIL, HANDLE, HWND};
use windows::Win32::Media::Audio::{
    eConsole, eRender, ActivateAudioInterfaceAsync, IActivateAudioInterfaceAsyncOperation,
    IActivateAudioInterfaceCompletionHandler, IActivateAudioInterfaceCompletionHandler_Impl,
    IAudioCaptureClient, IAudioClient, IMMDevice, IMMDeviceEnumerator, MMDeviceEnumerator,
    AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,
    AUDCLNT_STREAMFLAGS_LOOPBACK, AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
    AUDIOCLIENT_ACTIVATION_PARAMS, AUDIOCLIENT_ACTIVATION_PARAMS_0,
    AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK, AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS,
    PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE, VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK,
    WAVEFORMATEX,
};
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

use super::{mix_in_stereo_i16, AudioMix, LoopbackMode};
use crate::MediaError;

/// Resolve the process id that owns a window (for [`LoopbackMode::Process`]).
pub(super) fn window_pid(hwnd: isize) -> Option<u32> {
    let mut pid = 0u32;
    let handle = HWND(hwnd as *mut std::ffi::c_void);
    // SAFETY: GetWindowThreadProcessId only reads; a stale HWND yields pid 0.
    unsafe { GetWindowThreadProcessId(handle, Some(&mut pid)) };
    (pid != 0).then_some(pid)
}

/// A raw `PROPVARIANT` laid out for `VT_BLOB`. We build it by hand (rather than
/// the crate's `PROPVARIANT`) so nothing tries to `PropVariantClear` it -- that
/// would `CoTaskMemFree` our stack-owned blob. Matches the x64 ABI: 8-byte
/// header, then `BLOB { cbSize, <pad>, pBlobData }`.
#[repr(C)]
struct PropVariantBlob {
    vt: u16,
    _r1: u16,
    _r2: u16,
    _r3: u16,
    cb_size: u32,
    _pad: u32,
    p_blob_data: *mut std::ffi::c_void,
}

const VT_BLOB: u16 = 65;

/// Signals a Win32 event when async interface activation completes.
#[implement(IActivateAudioInterfaceCompletionHandler)]
struct ActivationHandler {
    event: HANDLE,
}

impl IActivateAudioInterfaceCompletionHandler_Impl for ActivationHandler_Impl {
    fn ActivateCompleted(
        &self,
        _op: Ref<'_, IActivateAudioInterfaceAsyncOperation>,
    ) -> windows::core::Result<()> {
        // SAFETY: a valid, still-open event handle owned by the waiting thread.
        unsafe {
            let _ = SetEvent(self.event);
        }
        Ok(())
    }
}

/// A running system-audio loopback capture. Dropping it stops the thread.
pub struct SystemAudioCapture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SystemAudioCapture {
    /// Start capturing `mode` into `mix`. Returns once capture has started, or an
    /// error if activation/initialization failed.
    pub fn start(mode: LoopbackMode, mix: AudioMix) -> Result<Self, MediaError> {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            // SAFETY: the whole WASAPI pipeline is unsafe COM, created and used
            // only on this thread; errors are reported via `init_tx`.
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                match run_loopback(mode, &mix, &s, &init_tx) {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = init_tx.send(Err(e.message()));
                    }
                }
                CoUninitialize();
            }
        });
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                stop,
                thread: Some(thread),
            }),
            Ok(Err(e)) => Err(MediaError::Codec(format!("system audio: {e}"))),
            Err(_) => Err(MediaError::Codec("system audio thread died".into())),
        }
    }
}

impl Drop for SystemAudioCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Acquire an `IAudioClient` for the requested loopback mode.
unsafe fn acquire_client(mode: LoopbackMode) -> windows::core::Result<IAudioClient> {
    match mode {
        LoopbackMode::System => {
            let enumerator: IMMDeviceEnumerator =
                CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
            let device: IMMDevice = enumerator.GetDefaultAudioEndpoint(eRender, eConsole)?;
            device.Activate::<IAudioClient>(CLSCTX_ALL, None)
        }
        LoopbackMode::Process(pid) => {
            let mut params = AUDIOCLIENT_ACTIVATION_PARAMS {
                ActivationType: AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
                Anonymous: AUDIOCLIENT_ACTIVATION_PARAMS_0 {
                    ProcessLoopbackParams: AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS {
                        TargetProcessId: pid,
                        ProcessLoopbackMode: PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE,
                    },
                },
            };
            let prop = PropVariantBlob {
                vt: VT_BLOB,
                _r1: 0,
                _r2: 0,
                _r3: 0,
                cb_size: std::mem::size_of::<AUDIOCLIENT_ACTIVATION_PARAMS>() as u32,
                _pad: 0,
                p_blob_data: std::ptr::addr_of_mut!(params).cast(),
            };
            let event = CreateEventW(None, false, false, PCWSTR::null())?;
            let handler: IActivateAudioInterfaceCompletionHandler =
                ActivationHandler { event }.into();
            let op: IActivateAudioInterfaceAsyncOperation = ActivateAudioInterfaceAsync(
                VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK,
                &IAudioClient::IID,
                Some(std::ptr::addr_of!(prop).cast::<PROPVARIANT>()),
                &handler,
            )?;
            // Wait (bounded) for activation to complete, then read the result.
            let _ = WaitForSingleObject(event, 5000);
            let _ = CloseHandle(event);
            let mut hr = windows::core::HRESULT(0);
            let mut unknown: Option<IUnknown> = None;
            op.GetActivateResult(&mut hr, &mut unknown)?;
            hr.ok()?;
            unknown
                .ok_or_else(|| windows::core::Error::from(E_FAIL))?
                .cast()
        }
    }
}

/// Full capture pipeline: activate, initialize, and pump frames into `mix` until
/// `stop`. Sends `Ok(())` on `init_tx` once streaming has actually started.
unsafe fn run_loopback(
    mode: LoopbackMode,
    mix: &AudioMix,
    stop: &AtomicBool,
    init_tx: &mpsc::Sender<Result<(), String>>,
) -> windows::core::Result<()> {
    let client = acquire_client(mode)?;

    // Force a fixed 48 kHz / stereo / 16-bit PCM format; AUTOCONVERTPCM makes the
    // engine resample the endpoint mix for us (process loopback accepts it too).
    let format = WAVEFORMATEX {
        wFormatTag: 1, // WAVE_FORMAT_PCM
        nChannels: 2,
        nSamplesPerSec: 48_000,
        nAvgBytesPerSec: 48_000 * 4,
        nBlockAlign: 4,
        wBitsPerSample: 16,
        cbSize: 0,
    };
    let flags = AUDCLNT_STREAMFLAGS_LOOPBACK
        | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
        | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    // 200 ms shared buffer, polled below.
    client.Initialize(AUDCLNT_SHAREMODE_SHARED, flags, 2_000_000, 0, &format, None)?;
    let capture: IAudioCaptureClient = client.GetService()?;
    client.Start()?;

    // Streaming is live: unblock the caller.
    let _ = init_tx.send(Ok(()));

    let silent_flag = AUDCLNT_BUFFERFLAGS_SILENT.0 as u32;
    while !stop.load(Ordering::Relaxed) {
        loop {
            let packet = capture.GetNextPacketSize()?;
            if packet == 0 {
                break;
            }
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut frames: u32 = 0;
            let mut fl: u32 = 0;
            capture.GetBuffer(&mut data, &mut frames, &mut fl, None, None)?;
            if frames > 0 && fl & silent_flag == 0 && !data.is_null() {
                // Interleaved stereo i16 -> mono, appended to the bounded ring.
                let stereo = std::slice::from_raw_parts(data.cast::<i16>(), frames as usize * 2);
                mix_in_stereo_i16(mix, stereo);
            }
            capture.ReleaseBuffer(frames)?;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = client.Stop();
    Ok(())
}
