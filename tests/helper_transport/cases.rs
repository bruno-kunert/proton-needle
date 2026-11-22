use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "proton-needle-helper-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

fn response() -> Value {
    json!({"protocol_version":1,"request_id":"id","operation":"list_processes",
        "status":"success","error_code":"","error_message":"","processes":[]})
}
fn parse(value: &Value) -> OperationResult {
    parse_response(&serde_json::to_vec(value).unwrap(), "id", "list_processes")
}
#[test]
fn protocol_requires_correlated_unique_single_line_envelope() {
    assert!(parse(&response()).success);
    let valid = serde_json::to_vec(&response()).unwrap();
    for suffix in [b"\n".as_slice(), b"\r\n".as_slice()] {
        let mut bytes = valid.clone();
        bytes.extend_from_slice(suffix);
        assert!(parse_response(&bytes, "id", "list_processes").success);
    }
    for bytes in [Vec::new(), b"[]".to_vec(), b"not json".to_vec(),
        [valid.as_slice(), b"\n", valid.as_slice()].concat(),
        [valid.as_slice(), b"\0"].concat(), vec![b'x'; OUTPUT_LIMIT + 1],
        br#"{"protocol_version":1,"request_id":"wrong","request_id":"id","operation":"list_processes","status":"success","error_code":"","error_message":""}"#.to_vec(),
        br#"{"protocol_version":1,"request_id":"id","operation":"list_processes","status":"success","error_code":"","error_message":"","extra":{"x":1,"x":2}}"#.to_vec()] {
        assert!(!parse_response(&bytes, "id", "list_processes").success);
    }
    for (key, bad) in [
        ("protocol_version", json!(1.0)),
        ("protocol_version", json!(2)),
        ("request_id", json!("other")),
        ("operation", json!("inject")),
        ("status", json!("unknown")),
        ("error_message", Value::Null),
        ("inconclusive", json!(1)),
        ("inconclusive", json!(true)),
    ] {
        let mut value = response();
        value[key] = bad;
        assert_eq!(parse(&value).error_code, "helper_protocol", "{key}");
    }
}
#[test]
fn remote_unknown_outcomes_are_preserved_without_faking_success() {
    let mut value = response();
    value["status"] = json!("error");
    value["error_code"] = json!("injection_timeout");
    value["error_message"] = json!("Remote loader may complete");
    value["inconclusive"] = json!(true);
    let result = parse(&value);
    assert!(!result.success && result.inconclusive);
    assert_eq!(result.error_code, "injection_timeout");
    value["inconclusive"] = json!(false);
    assert!(!parse(&value).inconclusive);
    value["operation"] = json!("inject");
    value["error_code"] = json!("invalid_dll");
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(!parse_response(&bytes, "id", "inject").inconclusive);
    value.as_object_mut().unwrap().remove("inconclusive");
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(parse_response(&bytes, "id", "inject").inconclusive);
}
#[test]
fn module_evidence_requires_exact_typed_pid_and_full_width_address() {
    let good = json!({"verified":true,"target_windows_pid":32,
        "target_image_path":"C:\\fixture\\target.exe","target_creation_time":"123",
        "file_identity_verified":true,"method":"load_library_w","remote_thread_exit_code":0,
        "loaded_module_path":"C:\\fixture\\test.dll","module_base":"6442450944"});
    assert!(verified_injection(
        &good,
        32,
        "C:\\fixture\\target.exe",
        "123"
    ));
    for (key, bad) in [
        ("verified", json!("true")),
        ("verified", json!(false)),
        ("target_windows_pid", json!("32")),
        ("target_windows_pid", json!(33)),
        ("target_image_path", json!("C:\\other.exe")),
        ("target_creation_time", json!("124")),
        ("target_creation_time", json!(123)),
        ("file_identity_verified", json!(false)),
        ("file_identity_verified", json!("true")),
        ("method", json!("load_library_a")),
        ("remote_thread_exit_code", json!(4294967296_u64)),
        ("remote_thread_exit_code", json!("0")),
        ("loaded_module_path", json!("")),
        ("loaded_module_path", json!("relative.dll")),
        ("loaded_module_path", json!("C:\\bad\0.dll")),
        ("module_base", json!("0")),
        ("module_base", json!("00032")),
        ("module_base", json!(6442450944_u64)),
        ("module_base", json!("18446744073709551616")),
        ("module_base", json!("+32")),
        ("module_base", json!("32x")),
    ] {
        let mut bad_response = good.clone();
        bad_response[key] = bad;
        assert!(
            !verified_injection(&bad_response, 32, "C:\\fixture\\target.exe", "123"),
            "{key}"
        );
    }
    for key in [
        "target_creation_time",
        "target_image_path",
        "file_identity_verified",
        "method",
        "remote_thread_exit_code",
        "module_base",
        "loaded_module_path",
    ] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            !verified_injection(&missing, 32, "C:\\fixture\\target.exe", "123"),
            "{key}"
        );
    }
}

fn fixture(mode: &str, operation: &str, timeout: u64, args: bool) -> OperationResult {
    // A native protocol simulator, not a Wine/Proton command or a process discovery hook.
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/helper_fixture.py"))
        .arg(mode);
    command.env_clear().current_dir(env!("CARGO_MANIFEST_DIR"));
    execute(command, json!({"operation": operation}), timeout, args)
}
#[test]
fn bounded_native_transport_fixtures_cover_stdin_and_argument_protocols() {
    for args in [false, true] {
        assert!(fixture("success", "list_processes", 3000, args).success);
        assert_eq!(
            fixture("wrong_identity", "list_processes", 3000, args).error_code,
            "helper_protocol"
        );
        assert_eq!(
            fixture("nonzero", "list_processes", 3000, args).error_code,
            "helper_exit"
        );
    }
    for mode in ["large", "stderr_large"] {
        let result = fixture(mode, "inject", 3000, false);
        assert_eq!(result.error_code, "helper_output_limit");
        assert!(result.inconclusive);
    }
    for (mode, code) in [
        ("timeout", "helper_timeout"),
        ("crash", "helper_crash"),
        ("malformed", "helper_protocol"),
        ("truncated", "helper_protocol"),
        ("closed_streams", "helper_protocol"),
        ("wrong_identity", "helper_protocol"),
        ("nonzero", "helper_exit"),
    ] {
        let result = fixture(
            mode,
            "inject",
            if mode == "timeout" { 100 } else { 3000 },
            false,
        );
        assert_eq!(result.error_code, code, "{mode}");
        assert!(result.inconclusive, "{mode}");
    }
    assert!(!fixture("remote_error", "inject", 3000, false).inconclusive);
    for mode in ["remote_timeout", "remote_rejected", "remote_unknown"] {
        let result = fixture(mode, "inject", 3000, false);
        assert!(!result.success && result.inconclusive, "{mode}");
    }
}

#[test]
fn partial_io_and_wrapper_exit_keep_one_deadline() {
    assert!(fixture("inherited_pipe", "list_processes", 3000, false).success);
    for mode in ["chatty", "stdout_chatty", "no_read", "duplex"] {
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/helper_fixture.py"))
            .arg(mode)
            .env_clear();
        let started = Instant::now();
        let result = execute(
            command,
            json!({"operation":"inject","padding":"x".repeat(60000)}),
            if mode == "duplex" { 3000 } else { 150 },
            false,
        );
        if mode == "duplex" {
            assert!(result.success, "{}: {}", result.error_code, result.message);
        } else {
            assert_eq!(result.error_code, "helper_timeout", "{mode}");
            assert!(result.inconclusive, "{mode}");
            assert!(started.elapsed() < Duration::from_secs(2), "{mode}");
        }
    }
}

#[test]
fn each_stream_read_yields_even_when_always_ready() {
    struct Chatty(usize);
    impl Read for Chatty {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            bytes[0] = b'x';
            Ok(1)
        }
    }
    let mut reader = Chatty(0);
    let mut output = Vec::new();
    let mut count = 0;
    assert!(!drain(&mut reader, &mut output, &mut count, 100, true).unwrap());
    assert_eq!(reader.0, 1);
    assert_eq!(output, b"x");
}
#[test]
fn transport_rejects_unbounded_requests_before_starting_process() {
    for timeout in [0, 120001] {
        let result = execute(
            Command::new("/never-executed"),
            json!({"operation":"probe"}),
            timeout,
            false,
        );
        assert_eq!(result.error_code, "invalid_request");
        assert!(!result.inconclusive);
    }
    for (length, argument) in [(65536, false), (31000, true)] {
        let result = execute(
            Command::new("/never-executed"),
            json!({"operation":"probe","extra":"a".repeat(length)}),
            1000,
            argument,
        );
        assert_eq!(result.error_code, "invalid_request");
    }
    let result = execute(
        Command::new("/never-executed"),
        json!({"operation":"inject"}),
        1000,
        false,
    );
    assert_eq!(result.error_code, "helper_start");
    assert!(!result.inconclusive);
}
#[test]
fn raw_runtime_entry_is_disabled_in_unit_tests() {
    let runtime = Runtime {
        supported: true,
        strategy: "direct_wine".into(),
        wine_binary: "/never-executed".into(),
        ..Runtime::default()
    };
    for operation in ["probe", "list_processes", "inject"] {
        assert_eq!(
            run_helper(&runtime, json!({"operation":operation}), 1000).error_code,
            "fixture_safety"
        );
    }
}

#[test]
fn helper_build_rejects_missing_directory_before_configuring() {
    let directory = Temporary::new();
    let cmake = directory.0.join("cmake");
    fs::write(
        &cmake,
        b"#!/bin/sh\nprintf 'unexpected cmake invocation\\n' >&2\nexit 23\n",
    )
    .unwrap();
    fs::set_permissions(&cmake, fs::Permissions::from_mode(0o700)).unwrap();
    for arguments in [
        &["--build-dir"][..],
        &["--build-dir", ""][..],
        &["--build-dir", "--fixtures"][..],
        &["--build-dir", "--help"][..],
    ] {
        let output = Command::new("/bin/bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("helper/build-helper.sh"))
            .args(arguments)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", directory.0.display()))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Missing build directory"),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn pe() -> Vec<u8> {
    let mut bytes = vec![0_u8; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 60, 128);
    bytes[128..132].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 132, 0x8664);
    put16(&mut bytes, 134, 1);
    put16(&mut bytes, 148, 240);
    put16(&mut bytes, 150, 0x2022);
    put16(&mut bytes, 152, 0x20b);
    put32(&mut bytes, 168, 0x1000);
    put32(&mut bytes, 184, 4096);
    put32(&mut bytes, 188, 512);
    put32(&mut bytes, 208, 8192);
    put32(&mut bytes, 212, 512);
    put32(&mut bytes, 260, 16);
    put32(&mut bytes, 400, 512);
    put32(&mut bytes, 404, 4096);
    put32(&mut bytes, 408, 512);
    put32(&mut bytes, 412, 512);
    put32(&mut bytes, 428, 0x60000020);
    bytes
}
#[test]
fn pe_validator_covers_native_backed_sections_and_directory_bounds() {
    let directory = Temporary::new();
    let path = directory.0.join("fixture.dll");
    let validate = |bytes: &[u8]| {
        fs::write(&path, bytes).unwrap();
        validate_dll(path.to_str().unwrap())
    };
    assert!(validate(&pe()).valid);
    assert_eq!(validate(&pe()).architecture, "x64");
    assert!(!validate_dll(directory.0.to_str().unwrap()).valid);
    assert!(!validate_dll(directory.0.join("missing").to_str().unwrap()).valid);
    for bytes in [Vec::new(), b"MZ".to_vec(), pe()[..500].to_vec()] {
        assert!(!validate(&bytes).valid);
    }
    let mut bad = pe();
    put16(&mut bad, 132, 0x14c);
    let result = validate(&bad);
    assert!(!result.valid);
    assert_eq!(result.architecture, "x86");
    for (at, value) in [
        (60, 0xfffffff0),
        (184, 0),
        (188, 0),
        (208, 4096),
        (212, 0),
        (168, 0x1800),
        (400, 0x3000),
        (404, 0x3000),
        (408, 0xfffffe00),
        (412, 0xfffffe00),
        (264, 0x1ff0),
        (376, 0x1000),
    ] {
        let mut bad = pe();
        put32(&mut bad, at, value);
        assert!(!validate(&bad).valid, "offset {at}");
    }
    let mut bad = pe();
    put16(&mut bad, 150, 0x22);
    assert!(!validate(&bad).valid);
    let mut bad = pe();
    put16(&mut bad, 134, 97);
    assert!(!validate(&bad).valid);
    let mut bad = pe();
    put16(&mut bad, 152, 0x10b);
    assert!(!validate(&bad).valid);
    let mut bad = pe();
    put32(&mut bad, 428, 0x40000040);
    assert!(!validate(&bad).valid);
    let mut bad = pe();
    put16(&mut bad, 134, 2);
    let section = bad[392..432].to_vec();
    bad[432..472].copy_from_slice(&section);
    assert!(!validate(&bad).valid);
    let mut good = pe();
    put32(&mut good, 168, 0);
    assert!(validate(&good).valid);
    // Stripped relocations do not make a DLL invalid. Loading can still succeed
    // at its preferred base (PE/COFF IMAGE_FILE_RELOCS_STRIPPED).
    let mut fixed = pe();
    put16(&mut fixed, 150, 0x2023);
    assert!(validate(&fixed).valid);
}

#[path = "backend.rs"]
mod backend;
pub(super) use backend::{authorize_command, prepare_request, registered_helper_path};

#[test]
fn nonregular_dll_paths_are_rejected_without_blocking() {
    let directory = Temporary::new();
    let fifo = directory.0.join("pipe.dll");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    assert!(!validate_dll(fifo.to_str().unwrap()).valid);
    let file = directory.0.join("same.dll");
    fs::write(&file, pe()).unwrap();
    assert!(shared_file(&file, std::process::id()));
    assert!(!shared_file(&file, 0));
    assert!(!shared_file(Path::new("relative.dll"), std::process::id()));
}

#[test]
fn held_dll_identity_detects_path_replacement_and_in_place_change() {
    let directory = Temporary::new();
    let path = directory.0.join("selected.dll");
    fs::write(&path, pe()).unwrap();
    let mut file = open_dll(path.to_str().unwrap()).unwrap();
    let original = file.metadata().unwrap();
    assert!(validate_open_dll(&mut file).valid);
    assert!(unchanged_dll(&file, &original, &path));
    let replacement = directory.0.join("replacement.dll");
    fs::write(&replacement, pe()).unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert!(!unchanged_dll(&file, &original, &path));
    assert!(validate_open_dll(&mut file).valid);
    let new_file = open_dll(path.to_str().unwrap()).unwrap();
    let metadata = new_file.metadata().unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(513)
        .unwrap();
    assert!(!unchanged_dll(&new_file, &metadata, &path));
}
