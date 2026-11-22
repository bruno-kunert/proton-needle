use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

static REGISTRY: Mutex<Option<RegisteredFixture>> = Mutex::new(None);

fn bounded_file(path: impl AsRef<Path>, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Fixture evidence exceeds bound".into());
    }
    Ok(bytes)
}
fn start_ticks(pid: u32) -> Result<u64, String> {
    let bytes = bounded_file(format!("/proc/{pid}/stat"), 65536)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    text.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .ok_or("Missing process start identity")?
        .parse::<u64>()
        .map_err(|e| e.to_string())
}
fn token() -> String {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    bytes
        .iter()
        .flat_map(|byte| {
            let hex = b"0123456789abcdef";
            [
                char::from(hex[usize::from(*byte >> 4)]),
                char::from(hex[usize::from(*byte & 15)]),
            ]
        })
        .collect()
}
#[derive(Clone)]
struct Pin {
    path: PathBuf,
    device: u64,
    inode: u64,
    kind: u32,
}
impl Pin {
    fn new(path: PathBuf) -> Self {
        let m = fs::symlink_metadata(&path).unwrap();
        assert!(!m.file_type().is_symlink());
        Self {
            path,
            device: m.dev(),
            inode: m.ino(),
            kind: m.mode() & 0o170000,
        }
    }
    fn live(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.device && m.ino() == self.inode && m.mode() & 0o170000 == self.kind
        })
    }
}
struct RegisteredFixture {
    child: OwnedChild,
    root: PathBuf,
    outer: PathBuf,
    wine: PathBuf,
    server: PathBuf,
    helper: PathBuf,
    prefix: PathBuf,
    environment: BTreeMap<String, String>,
    pins: Vec<Pin>,
    ticks: u64,
    proc_environment: Vec<u8>,
    proc_command: Vec<u8>,
    windows: Value,
    session: String,
    instance: String,
}
impl RegisteredFixture {
    fn paths_live(&self) -> bool {
        let uid = fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(u32::MAX);
        self.pins.iter().all(Pin::live)
            && [&self.outer, &self.root, &self.prefix].iter().all(|p| {
                fs::symlink_metadata(p)
                    .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700)
            })
            && self.outer.starts_with("/tmp")
            && self.root.starts_with(&self.outer)
            && std::env::var("PROTON_NEEDLE_PRIVATE_TEST_BUS").as_deref() == Ok("1")
            && std::env::var("DBUS_SESSION_BUS_ADDRESS").ok().as_ref()
                == self.environment.get("DBUS_SESSION_BUS_ADDRESS")
            && std::env::var_os("DISPLAY").is_none()
            && std::env::var_os("WAYLAND_DISPLAY").is_none()
            && !self.outer.join("INTERRUPTED").exists()
    }
    fn live(&mut self) -> Result<(), String> {
        if !self.paths_live()
            || self
                .child
                .0
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            || start_ticks(self.child.0.id())? != self.ticks
            || bounded_file(format!("/proc/{}/environ", self.child.0.id()), 1048576)?
                != self.proc_environment
            || bounded_file(format!("/proc/{}/cmdline", self.child.0.id()), 65536)?
                != self.proc_command
        {
            return Err("Unregistered, changed or non-isolated fixture lifetime".into());
        }
        Ok(())
    }
    fn runtime(&mut self, runtime: &Runtime) -> Result<(), String> {
        self.live()?;
        if runtime.anchor_pid != self.child.0.id()
            || runtime.start_ticks != self.ticks
            || Path::new(&runtime.prefix) != self.prefix
            || Path::new(&runtime.wine_binary) != self.wine
            || runtime.strategy != "direct_wine"
            || !runtime.proton_path.is_empty()
            || !runtime.launcher_path.is_empty()
            || !runtime.service_owner.is_empty()
            || !Path::new(&runtime.working_directory).starts_with(&self.root)
        {
            return Err("Only the registered native fixture runtime may launch a helper".into());
        }
        Ok(())
    }
}
fn with_registry<T>(
    f: impl FnOnce(&mut RegisteredFixture) -> Result<T, String>,
) -> Result<T, String> {
    let mut registry = REGISTRY
        .lock()
        .map_err(|_| "Fixture registry is poisoned")?;
    f(registry.as_mut().ok_or("No owned fixture is registered")?)
}
pub(crate) fn registered_helper_path() -> PathBuf {
    with_registry(|fixture| {
        fixture.live()?;
        Ok(fixture.helper.clone())
    })
    .unwrap_or_default()
}
pub(crate) fn prepare_request(runtime: &Runtime, mut request: Value) -> Result<Value, String> {
    with_registry(|fixture| {
        fixture.runtime(runtime)?;
        if !request.is_object() {
            return Err("Fixture request must be an object".into());
        }
        if request.get("fixture_session").is_some() || request.get("fixture_targets").is_some() {
            return Err("Fixture authorization is registry-owned, not caller-supplied".into());
        }
        if request["operation"] == "inject" {
            if request["target_windows_pid"] != fixture.windows["windows_pid"]
                || request["expected_image_path"] != fixture.windows["image_path"]
                || request["expected_creation_time"] != fixture.windows["creation_time"]
            {
                return Err("Only the exact registered Windows identity may be touched".into());
            }
            let path = request["dll_path"].as_str().ok_or("Missing fixture DLL")?;
            let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
            let permitted = [
                "proton_needle_test.dll",
                "proton_needle_reject_test.dll",
                "proton_needle_timeout_test.dll",
                "proton_needle_exit_test.dll",
                "proton_needle_測試_🧪.dll",
            ];
            if path.parent() != fixture.helper.parent()
                || !path
                    .file_name()
                    .and_then(|p| p.to_str())
                    .is_some_and(|p| permitted.contains(&p))
                || !fixture
                    .pins
                    .iter()
                    .any(|pin| pin.path == path && pin.live())
            {
                return Err("Only copied, pinned self-built fixture DLLs may be loaded".into());
            }
        }
        request["fixture_session"] = json!(fixture.session);
        request["fixture_targets"] = json!([fixture.windows]);
        Ok(request)
    })
}
pub(crate) fn authorize_command(runtime: &Runtime, command: &mut Command) -> Result<(), String> {
    with_registry(|fixture| {
        fixture.runtime(runtime)?;
        if Path::new(command.get_program()) != fixture.wine
            || command.get_args().next().is_some()
            || !command
                .get_current_dir()
                .is_some_and(|path| path.starts_with(&fixture.root))
        {
            return Err(
                "Fixture helper must use the exact direct native loader without wrapper arguments"
                    .into(),
            );
        }
        for (key, value) in command.get_envs() {
            let key = key.to_str().ok_or("Non-UTF8 fixture environment key")?;
            let value = value
                .and_then(|v| v.to_str())
                .ok_or("Invalid fixture environment value")?;
            if fixture.environment.get(key).map(String::as_str) != Some(value)
                || matches!(key, "DISPLAY" | "WAYLAND_DISPLAY")
            {
                return Err("Helper launch environment differs from the isolated fixture".into());
            }
        }
        command.env("PROTON_NEEDLE_FIXTURE_SESSION", &fixture.session);
        Ok(())
    })
}
fn cleanup_command(fixture: &RegisteredFixture, arg: &str) -> bool {
    let child = Command::new(&fixture.server)
        .arg(arg)
        .env_clear()
        .envs(&fixture.environment)
        .current_dir(&fixture.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(child) = child else { return false };
    let mut child = OwnedChild(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) => return status.success(),
            Err(_) => return false,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
impl Drop for RegisteredFixture {
    fn drop(&mut self) {
        let valid = self.paths_live();
        if valid {
            let _ = fs::write(self.root.join("gate.release"), b"release\n");
            let _ = fs::write(self.root.join("target.stop"), b"stop\n");
            let deadline = Instant::now() + Duration::from_secs(5);
            while matches!(self.child.0.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let clean = valid && cleanup_command(self, "-w");
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        if clean {
            let _ = fs::remove_dir_all(&self.root);
        } else {
            eprintln!(
                "Private fixture teardown unproven. Retained {}",
                self.root.display()
            );
        }
    }
}
struct SessionGuard;
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = REGISTRY.lock() {
            registry.take();
        }
    }
}

#[test]
#[ignore = "Requires explicit self-built fixtures/native Wine and private wrapper. Never runs by default"]
fn controlled_backend_fixture() {
    assert_eq!(
        std::env::var("PROTON_NEEDLE_PRIVATE_TEST_BUS").as_deref(),
        Ok("1")
    );
    let outer = fs::canonicalize(
        std::env::var_os("PROTON_NEEDLE_TEST_ROOT").expect("Use tests/helper_backend.py"),
    )
    .unwrap();
    assert!(outer.starts_with("/tmp"));
    assert_ne!(outer, Path::new("/tmp"));
    assert!(std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none());
    let bus = outer.join("runtime/bus");
    assert!(fs::metadata(&bus).unwrap().file_type().is_socket());
    assert_eq!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap(),
        format!("unix:path={}", bus.display())
    );
    let wine = fs::canonicalize(std::env::var_os("PROTON_NEEDLE_TEST_WINE").unwrap()).unwrap();
    assert!(matches!(
        wine.file_name().and_then(|v| v.to_str()),
        Some("wine" | "wine64")
    ));
    let lower = wine.to_string_lossy().to_lowercase();
    assert!(
        !["steam", "proton", "flatpak", "snap"]
            .iter()
            .any(|word| lower.contains(word))
    );
    let server = fs::canonicalize(wine.parent().unwrap().join("wineserver")).unwrap();
    let source =
        fs::canonicalize(std::env::var_os("PROTON_NEEDLE_TEST_FIXTURES").unwrap()).unwrap();
    let root = outer.join(format!("session-{}", token()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut environment: BTreeMap<String, String> = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("WINEARCH".into(), "win64".into()),
        ("WINEDEBUG".into(), "-all".into()),
        ("WINEDLLOVERRIDES".into(), "mscoree,mshtml=".into()),
        (
            "DBUS_SESSION_BUS_ADDRESS".into(),
            format!("unix:path={}", bus.display()),
        ),
    ]);
    for key in [
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        let directory = root.join(key.to_lowercase());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        environment.insert(key.into(), directory.to_str().unwrap().into());
    }
    let prefix = root.join("prefix");
    fs::DirBuilder::new().mode(0o700).create(&prefix).unwrap();
    let directory = root.join("fixtures");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let names = [
        "proton_needle_fixture_helper_x64.exe",
        "proton_needle_test_target.exe",
        "proton_needle_test.dll",
        "proton_needle_reject_test.dll",
        "proton_needle_timeout_test.dll",
        "proton_needle_exit_test.dll",
    ];
    let mut pins: Vec<Pin> = [&outer, &root, &prefix, &directory, &wine, &server, &bus]
        .iter()
        .map(|p| Pin::new((*p).clone()))
        .collect();
    for name in names {
        fs::copy(source.join(name), directory.join(name)).unwrap();
        pins.push(Pin::new(directory.join(name)));
    }
    let unicode_dll = directory.join("proton_needle_測試_🧪.dll");
    fs::copy(directory.join("proton_needle_test.dll"), &unicode_dll).unwrap();
    pins.push(Pin::new(unicode_dll.clone()));
    let session = token();
    let instance = token();
    environment.insert("WINEPREFIX".into(), prefix.to_str().unwrap().into());
    environment.insert("PROTON_NEEDLE_FIXTURE_SESSION".into(), session.clone());
    environment.insert("PROTON_NEEDLE_TEST_INSTANCE".into(), instance.clone());
    for (key, name) in [
        ("PROTON_NEEDLE_TEST_READY", "target.ready"),
        ("PROTON_NEEDLE_TEST_MARKER", "target.marker"),
        ("PROTON_NEEDLE_TEST_STOP", "target.stop"),
        ("PROTON_NEEDLE_TEST_GATE_RELEASE", "gate.release"),
        ("PROTON_NEEDLE_TEST_GATE_ENTERED", "gate.entered"),
    ] {
        environment.insert(key.into(), root.join(name).to_str().unwrap().into());
    }
    environment.insert(
        "PROTON_NEEDLE_TEST_INTERRUPT".into(),
        outer.join("INTERRUPTED").to_str().unwrap().into(),
    );
    environment.insert(
        "PROTON_NEEDLE_TEST_GATE_EVENT".into(),
        format!("Local\\ProtonNeedleGate_{session}"),
    );
    let executable = directory.join(names[1]);
    let child = Command::new(&wine)
        .arg(&executable)
        .env_clear()
        .envs(&environment)
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut fixture = RegisteredFixture {
        child: OwnedChild(child),
        root: root.clone(),
        outer,
        wine,
        server,
        helper: directory.join(names[0]),
        prefix,
        environment,
        pins,
        ticks: 0,
        proc_environment: Vec::new(),
        proc_command: Vec::new(),
        windows: Value::Null,
        session,
        instance,
    };
    assert!(fixture.paths_live());
    let ready = root.join("target.ready");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        assert!(
            fixture.child.0.try_wait().unwrap().is_none(),
            "Independent fixture exited before readiness"
        );
        if let Ok(bytes) = bounded_file(&ready, 65536)
            && bytes.ends_with(b"\n")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Independent fixture readiness timeout"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let ready_bytes = bounded_file(&ready, 65536).unwrap();
    let text = std::str::from_utf8(&ready_bytes).unwrap();
    let fields: Vec<&str> = text.lines().collect();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[1], fixture.session);
    assert_eq!(fields[4], fixture.instance);
    let pid: u32 = fields[0].parse().unwrap();
    assert_ne!(pid, 0);
    assert_eq!(pid.to_string(), fields[0]);
    assert!(decimal_nonzero(fields[2]));
    assert_eq!(fields[2].parse::<u64>().unwrap().to_string(), fields[2]);
    let mapped = fields[3].replace('\\', "/");
    assert_eq!(&mapped[1..3], ":/");
    let drive = fs::canonicalize(
        fixture
            .prefix
            .join("dosdevices")
            .join(format!("{}:", mapped[..1].to_lowercase())),
    )
    .unwrap();
    assert_eq!(
        fs::canonicalize(drive.join(&mapped[3..])).unwrap(),
        executable
    );
    let linux_pid = fixture.child.0.id();
    fixture.ticks = start_ticks(linux_pid).unwrap();
    fixture.proc_environment = bounded_file(format!("/proc/{linux_pid}/environ"), 1048576).unwrap();
    fixture.proc_command = bounded_file(format!("/proc/{linux_pid}/cmdline"), 65536).unwrap();
    let interrupt_entry = format!(
        "PROTON_NEEDLE_TEST_INTERRUPT={}",
        fixture.outer.join("INTERRUPTED").display()
    );
    assert!(
        fixture
            .proc_environment
            .split(|byte| *byte == 0)
            .any(|entry| entry == interrupt_entry.as_bytes()),
        "Owned target must observe the wrapper's interruption marker"
    );
    for key in [
        "WINEPREFIX",
        "PROTON_NEEDLE_FIXTURE_SESSION",
        "PROTON_NEEDLE_TEST_INSTANCE",
    ] {
        let entry = format!("{key}={}", fixture.environment[key]);
        assert!(
            fixture
                .proc_environment
                .split(|b| *b == 0)
                .any(|item| item == entry.as_bytes())
        );
    }
    fixture.windows = json!({"windows_pid":pid,"image_path":fields[3],"creation_time":fields[2],"fixture_instance":fixture.instance});
    fixture.pins.push(Pin::new(ready));
    fixture.live().unwrap();
    *REGISTRY.lock().unwrap() = Some(fixture);
    let _session = SessionGuard;
    let rows = crate::discovery::discover_registered_fixture(linux_pid);
    let selected = rows
        .into_iter()
        .find(|row| row.windows_pid == pid)
        .expect("Rust discovery must expose independently started Windows fixture");
    assert!(selected.injectable, "{}", selected.detection);
    assert_eq!(selected.architecture, "x64");
    assert!(selected.runtime.version.starts_with("Wine "));
    assert_eq!(selected.image_path, fields[3]);
    assert_eq!(selected.creation_time, fields[2]);
    with_registry(|fixture| {
        fixture.live()?;
        assert_eq!(fixture.child.0.id(), linux_pid);
        Ok(())
    })
    .unwrap();
    let reject = inject_dll(
        &selected,
        directory
            .join("proton_needle_reject_test.dll")
            .to_str()
            .unwrap(),
    );
    assert_eq!(
        reject.error_code, "load_library_failed",
        "{}",
        reject.message
    );
    assert!(!reject.success && reject.inconclusive);
    assert_eq!(
        fs::read_to_string(root.join("target.marker"))
            .unwrap()
            .trim(),
        pid.to_string(),
        "Rejected DLL must prove its code executed"
    );
    fs::remove_file(root.join("target.marker")).unwrap();
    let timed = inject_dll(
        &selected,
        directory
            .join("proton_needle_timeout_test.dll")
            .to_str()
            .unwrap(),
    );
    assert_eq!(timed.error_code, "injection_timeout", "{}", timed.message);
    assert!(timed.inconclusive);
    assert!(root.join("gate.entered").exists());
    with_registry(|fixture| {
        fixture.live()?;
        Ok(())
    })
    .unwrap();
    fs::write(root.join("gate.release"), b"release\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(root.join("target.marker")).is_ok_and(|text| text.trim() == fields[0])
    {
        assert!(
            Instant::now() < deadline,
            "Timed-out loader did not complete after controlled gate release"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        fs::read_to_string(root.join("target.marker"))
            .unwrap()
            .trim(),
        pid.to_string()
    );
    fs::remove_file(root.join("target.marker")).unwrap();
    let dll = directory.join("proton_needle_test.dll");
    assert!(validate_dll(dll.to_str().unwrap()).valid);
    let loaded = inject_dll(&selected, dll.to_str().unwrap());
    assert!(loaded.success, "{}: {}", loaded.error_code, loaded.message);
    assert!(verified_injection(
        &loaded.response,
        pid,
        &selected.image_path,
        &selected.creation_time
    ));
    assert_eq!(
        fs::read_to_string(root.join("target.marker"))
            .unwrap()
            .trim(),
        pid.to_string()
    );
    with_registry(|fixture| {
        fixture.live()?;
        assert_eq!(fixture.child.0.id(), linux_pid);
        Ok(())
    })
    .unwrap();
    let duplicate = inject_dll(&selected, dll.to_str().unwrap());
    assert_eq!(duplicate.error_code, "dll_already_loaded");
    assert!(!duplicate.inconclusive);
    fs::remove_file(root.join("target.marker")).unwrap();
    let unicode = inject_dll(&selected, unicode_dll.to_str().unwrap());
    assert!(
        unicode.success,
        "{}: {}",
        unicode.error_code, unicode.message
    );
    assert!(
        unicode.response["loaded_module_path"]
            .as_str()
            .unwrap()
            .ends_with("proton_needle_測試_🧪.dll")
    );
    assert_eq!(
        fs::read_to_string(root.join("target.marker"))
            .unwrap()
            .trim(),
        pid.to_string()
    );
    let mut stale = selected.clone();
    stale.creation_time = (stale.creation_time.parse::<u64>().unwrap() + 1).to_string();
    assert_eq!(
        inject_dll(&stale, dll.to_str().unwrap()).error_code,
        "target_identity"
    );
    let mut wrong_runtime = selected.runtime.clone();
    wrong_runtime.prefix = root.to_str().unwrap().into();
    assert_eq!(
        run_helper(&wrong_runtime, json!({"operation":"probe"}), 1000).error_code,
        "fixture_safety"
    );
    let exited = inject_dll(
        &selected,
        directory
            .join("proton_needle_exit_test.dll")
            .to_str()
            .unwrap(),
    );
    assert!(
        !exited.success && exited.inconclusive,
        "{}: {}",
        exited.error_code,
        exited.message
    );
    println!(
        "PASS: real Rust filtered discovery, runtime revalidation, fresh identity enumeration, fixture-only helper authorization, code-executed rejection with unknown outcome, verified ASCII/Unicode injection, independent PID marker, unknown target-exit outcome and original owned Child"
    );
}
use std::os::unix::fs::FileTypeExt;
