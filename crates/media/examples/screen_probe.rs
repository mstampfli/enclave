//! Hardware check for Linux screen capture.
//!
//! Two modes:
//! - `--self-test`: fully headless proof of the PipeWire leg. Publishes a
//!   synthetic BGRx video source stream with a known pixel pattern, captures
//!   it with `ScreenCapture::start_node` (the same stream code real shares
//!   use), and verifies dimensions and pixel values end to end.
//! - default: the real interactive flow -- opens the XDG portal's system
//!   picker; pick a screen or window and frames are reported for ~5 seconds.
//!
//! Run: `cargo run -p enclave-media --example screen_probe -- --self-test`
//!      `cargo run -p enclave-media --example screen_probe`

#[cfg(target_os = "linux")]
mod probe {
    use enclave_media::{CaptureStatus, ScreenCapture};
    use pipewire as pw;
    use pw::{properties::properties, spa};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const W: usize = 320;
    const H: usize = 240;

    /// The known pattern: BGRx pixel at (x, y) = (x, y, x^y, 255).
    fn expected_bgra(x: usize, y: usize) -> [u8; 4] {
        [(x & 255) as u8, (y & 255) as u8, ((x ^ y) & 255) as u8, 255]
    }

    /// A serialized SPA_PARAM_Buffers pod for whole WxH BGRx frames.
    fn buffers_pod() -> Result<Vec<u8>, String> {
        let stride = (W * 4) as i32;
        let size = stride * H as i32;
        let obj = spa::pod::Object {
            type_: spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
            id: spa::param::ParamType::Buffers.as_raw(),
            properties: vec![
                spa::pod::Property::new(
                    spa::sys::SPA_PARAM_BUFFERS_buffers,
                    spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                        spa::utils::ChoiceFlags::empty(),
                        spa::utils::ChoiceEnum::Range {
                            default: 4,
                            min: 2,
                            max: 16,
                        },
                    ))),
                ),
                spa::pod::Property::new(
                    spa::sys::SPA_PARAM_BUFFERS_blocks,
                    spa::pod::Value::Int(1),
                ),
                spa::pod::Property::new(
                    spa::sys::SPA_PARAM_BUFFERS_size,
                    spa::pod::Value::Int(size),
                ),
                spa::pod::Property::new(
                    spa::sys::SPA_PARAM_BUFFERS_stride,
                    spa::pod::Value::Int(stride),
                ),
                spa::pod::Property::new(
                    spa::sys::SPA_PARAM_BUFFERS_dataType,
                    spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                        spa::utils::ChoiceFlags::empty(),
                        spa::utils::ChoiceEnum::Flags {
                            default: (1 << spa::sys::SPA_DATA_MemPtr)
                                | (1 << spa::sys::SPA_DATA_MemFd),
                            flags: vec![],
                        },
                    ))),
                ),
            ],
        };
        let values = spa::pod::serialize::PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &spa::pod::Value::Object(obj),
        )
        .map_err(|e| format!("{e:?}"))?
        .0
        .into_inner();
        Ok(values)
    }

    /// Publish a BGRx video source stream named `enclave-probe-src`; reports
    /// setup success once connected, then serves frames until process exit.
    fn spawn_source(node_tx: mpsc::Sender<Result<(), String>>) {
        std::thread::spawn(move || {
            let run = || -> Result<(), String> {
                pw::init();
                let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(|e| e.to_string())?;
                let context =
                    pw::context::ContextRc::new(&mainloop, None).map_err(|e| e.to_string())?;
                let core = context.connect_rc(None).map_err(|e| e.to_string())?;

                let stream = pw::stream::StreamBox::new(
                    &core,
                    "enclave-probe-src",
                    properties! {
                        *pw::keys::MEDIA_TYPE => "Video",
                        *pw::keys::MEDIA_CATEGORY => "Playback",
                        *pw::keys::MEDIA_ROLE => "Screen",
                        *pw::keys::NODE_NAME => "enclave-probe-src",
                    },
                )
                .map_err(|e| e.to_string())?;

                let _listener = stream
                    .add_local_listener_with_user_data(())
                    .param_changed(|stream, _, id, param| {
                        // A real producer (the compositor) answers the agreed
                        // format with whole-frame buffer requirements; so do we.
                        if param.is_none() || id != spa::param::ParamType::Format.as_raw() {
                            return;
                        }
                        if let Ok(values) = buffers_pod() {
                            if let Some(pod) = spa::pod::Pod::from_bytes(&values) {
                                let _ = stream.update_params(&mut [pod]);
                            }
                        }
                    })
                    .process(|stream, _| {
                        if let Some(mut buffer) = stream.dequeue_buffer() {
                            let datas = buffer.datas_mut();
                            if datas.is_empty() {
                                return;
                            }
                            let d = &mut datas[0];
                            let stride = W * 4;
                            if let Some(slice) = d.data() {
                                if slice.len() >= stride * H {
                                    for y in 0..H {
                                        for x in 0..W {
                                            let px = expected_bgra(x, y);
                                            let off = y * stride + x * 4;
                                            slice[off..off + 4].copy_from_slice(&px);
                                        }
                                    }
                                }
                            }
                            let chunk = d.chunk_mut();
                            *chunk.offset_mut() = 0;
                            *chunk.stride_mut() = stride as i32;
                            *chunk.size_mut() = (stride * H) as u32;
                        }
                    })
                    .register()
                    .map_err(|e| e.to_string())?;

                // A fixed BGRx format so the capture side has to negotiate it.
                let obj = spa::pod::object!(
                    spa::utils::SpaTypes::ObjectParamFormat,
                    spa::param::ParamType::EnumFormat,
                    spa::pod::property!(
                        spa::param::format::FormatProperties::MediaType,
                        Id,
                        spa::param::format::MediaType::Video
                    ),
                    spa::pod::property!(
                        spa::param::format::FormatProperties::MediaSubtype,
                        Id,
                        spa::param::format::MediaSubtype::Raw
                    ),
                    spa::pod::property!(
                        spa::param::format::FormatProperties::VideoFormat,
                        Id,
                        spa::param::video::VideoFormat::BGRx
                    ),
                    spa::pod::property!(
                        spa::param::format::FormatProperties::VideoSize,
                        Rectangle,
                        spa::utils::Rectangle {
                            width: W as u32,
                            height: H as u32
                        }
                    ),
                    spa::pod::property!(
                        spa::param::format::FormatProperties::VideoFramerate,
                        Fraction,
                        spa::utils::Fraction { num: 30, denom: 1 }
                    ),
                );
                let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
                    std::io::Cursor::new(Vec::new()),
                    &spa::pod::Value::Object(obj),
                )
                .map_err(|e| format!("{e:?}"))?
                .0
                .into_inner();
                let mut params = [spa::pod::Pod::from_bytes(&values).ok_or("format pod parse")?];

                stream
                    .connect(
                        spa::utils::Direction::Output,
                        None,
                        pw::stream::StreamFlags::MAP_BUFFERS,
                        &mut params,
                    )
                    .map_err(|e| e.to_string())?;

                let _ = node_tx.send(Ok(()));
                mainloop.run();
                Ok(())
            };
            if let Err(e) = run() {
                let _ = node_tx.send(Err(e));
            }
        });
    }

    /// One registry roundtrip on a fresh connection: the global id of the
    /// node named `name`, if it is currently published.
    fn find_node_id(name: &str) -> Result<Option<u32>, String> {
        use std::cell::Cell;
        use std::rc::Rc;

        pw::init();
        let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(|e| e.to_string())?;
        let context = pw::context::ContextRc::new(&mainloop, None).map_err(|e| e.to_string())?;
        let core = context.connect_rc(None).map_err(|e| e.to_string())?;
        let registry = core.get_registry_rc().map_err(|e| e.to_string())?;

        let found: Rc<Cell<Option<u32>>> = Rc::new(Cell::new(None));
        let f = found.clone();
        let wanted = name.to_owned();
        let _reg = registry
            .add_listener_local()
            .global(move |g| {
                if g.type_ == pw::types::ObjectType::Node
                    && g.props.map(|p| p.get("node.name")) == Some(Some(wanted.as_str()))
                {
                    f.set(Some(g.id));
                }
            })
            .register();

        let pending = core.sync(0).map_err(|e| e.to_string())?;
        let ml = mainloop.downgrade();
        let _core_l = core
            .add_listener_local()
            .done(move |id, seq| {
                if id == pw::core::PW_ID_CORE && seq == pending {
                    if let Some(m) = ml.upgrade() {
                        m.quit();
                    }
                }
            })
            .register();

        mainloop.run();
        Ok(found.get())
    }

    pub fn self_test() -> bool {
        let (node_tx, node_rx) = mpsc::channel();
        spawn_source(node_tx);
        match node_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                println!("[FAIL] source stream: {e}");
                return false;
            }
            Err(_) => {
                println!("[FAIL] source stream never connected");
                return false;
            }
        }
        // The node shows up in the registry a moment after connect; retry.
        let deadline = Instant::now() + Duration::from_secs(5);
        let node_id = loop {
            match find_node_id("enclave-probe-src") {
                Ok(Some(id)) => break id,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200))
                }
                Ok(None) => {
                    println!("[FAIL] source node never appeared in the registry");
                    return false;
                }
                Err(e) => {
                    println!("[FAIL] registry lookup: {e}");
                    return false;
                }
            }
        };
        println!("source node {node_id} published, capturing it...");

        let cap = match ScreenCapture::start_node(node_id) {
            Ok(c) => c,
            Err(e) => {
                println!("[FAIL] start capture: {e}");
                return false;
            }
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let frame = loop {
            if let Some(f) = cap.latest() {
                break f;
            }
            if Instant::now() > deadline {
                println!("[FAIL] no frame within 10s (status: {:?})", cap.status());
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        if !matches!(cap.status(), CaptureStatus::Live) {
            println!("[FAIL] frames arrived but status is {:?}", cap.status());
            return false;
        }
        if frame.width != W || frame.height != H || frame.bgra.len() != W * H * 4 {
            println!(
                "[FAIL] got {}x{} ({} bytes), wanted {W}x{H}",
                frame.width,
                frame.height,
                frame.bgra.len()
            );
            return false;
        }
        // Spot-check pixels across the frame, including both edges.
        for (x, y) in [
            (0, 0),
            (W - 1, 0),
            (0, H - 1),
            (W - 1, H - 1),
            (17, 93),
            (200, 150),
        ] {
            let off = (y * W + x) * 4;
            let got = &frame.bgra[off..off + 4];
            let want = expected_bgra(x, y);
            if got != want {
                println!("[FAIL] pixel ({x},{y}): got {got:?}, want {want:?}");
                return false;
            }
        }
        println!(
            "[PASS] {}x{} BGRA frames delivered, status Live, pixels exact",
            frame.width, frame.height
        );
        true
    }

    pub fn portal() -> bool {
        println!("opening the system picker; choose a screen or window...");
        let cap = match ScreenCapture::start_index(0) {
            Ok(c) => c,
            Err(e) => {
                println!("[FAIL] start portal capture: {e}");
                return false;
            }
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match cap.status() {
                CaptureStatus::Live => break,
                CaptureStatus::Ended(reason) => {
                    println!("[FAIL] share ended: {reason}");
                    return false;
                }
                CaptureStatus::Starting if Instant::now() > deadline => {
                    println!("[FAIL] no answer from the portal within 120s");
                    return false;
                }
                CaptureStatus::Starting => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let mut frames = 0usize;
        let mut last_seen: Option<(usize, usize)> = None;
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if let Some(f) = cap.latest() {
                frames += 1;
                last_seen = Some((f.width, f.height));
            }
            std::thread::sleep(Duration::from_millis(33));
        }
        match last_seen {
            Some((w, h)) => {
                println!(
                    "[PASS] live share delivered frames for 5s (last {w}x{h}, ~{frames} polls)"
                );
                true
            }
            None => {
                println!("[FAIL] share went live but no frames arrived");
                false
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let self_test = std::env::args().any(|a| a == "--self-test");
    let ok = if self_test {
        probe::self_test()
    } else {
        probe::portal()
    };
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this probe exercises the Linux portal/PipeWire backend only");
}
