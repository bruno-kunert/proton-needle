use crate::types::{DllInfo, OperationResult, Process, Runtime};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const STDERR_LIMIT: usize = 65536;

fn failure(code: &str, message: &str, inconclusive: bool) -> OperationResult {
    OperationResult {
        inconclusive,
        ..OperationResult::error(code, message)
    }
}

/// Locate only installed helpers. Never search PATH or accept an environment override.
#[cfg(not(test))]
pub fn helper_path() -> PathBuf {
    let Ok(executable) = std::env::current_exe() else {
        return PathBuf::new();
    };
    let Some(directory) = executable.parent() else {
        return PathBuf::new();
    };
    for path in [
        directory.join("helpers/proton_needle_helper_x64.exe"),
        directory.join("../lib/proton-needle/proton_needle_helper_x64.exe"),
    ] {
        if fs::OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NONBLOCK.bits() as i32)
            .open(&path)
            .is_ok_and(|file| file.metadata().is_ok_and(|metadata| metadata.is_file()))
            && let Ok(path) = path.canonicalize()
        {
            return path;
        }
    }
    PathBuf::new()
}
#[cfg(test)]
pub fn helper_path() -> PathBuf {
    tests::registered_helper_path()
}

fn shared_file(path: &Path, pid: u32) -> bool {
    if pid == 0 || !path.is_absolute() {
        return false;
    }
    let peer =
        PathBuf::from(format!("/proc/{pid}/root")).join(path.strip_prefix("/").unwrap_or(path));
    match (fs::metadata(path), fs::metadata(peer)) {
        (Ok(a), Ok(b)) => a.is_file() && b.is_file() && a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Revalidate the pinned execution route for every operation, without retrying another route.
pub fn run_helper(runtime: &Runtime, request: Value, timeout_ms: u64) -> OperationResult {
    // Test binaries require an in-process registry owning the exact live fixture Child.
    #[cfg(test)]
    let request = match tests::prepare_request(runtime, request) {
        Ok(request) => request,
        Err(error) => return OperationResult::error("fixture_safety", error),
    };
    if !runtime.supported {
        return OperationResult::error(
            if runtime.error_code.is_empty() {
                "runtime_access_unavailable"
            } else {
                &runtime.error_code
            },
            if runtime.error.is_empty() {
                "No verified execution route is available."
            } else {
                &runtime.error
            },
        );
    }
    let mut command = match crate::runtime::command(runtime) {
        Ok(command) => command,
        Err(error) => return OperationResult::error("runtime_unavailable", error),
    };
    #[cfg(test)]
    if let Err(error) = tests::authorize_command(runtime, &mut command) {
        return OperationResult::error("fixture_safety", error);
    }
    let helper = helper_path();
    if helper.as_os_str().is_empty() {
        return OperationResult::error(
            "helper_missing",
            "Build/install the x64 helper in helpers/ beside the application or lib/proton-needle/.",
        );
    }
    if matches!(
        runtime.strategy.as_str(),
        "app_launcher" | "steam_broker" | "direct_wine" | "proton_runtime"
    ) {
        let peer = if matches!(runtime.strategy.as_str(), "app_launcher" | "steam_broker") {
            runtime.service_pid
        } else {
            runtime.anchor_pid
        };
        if !shared_file(&helper, peer)
            || (peer != runtime.anchor_pid && !shared_file(&helper, runtime.anchor_pid))
        {
            return OperationResult::error(
                "helper_inaccessible",
                "The execution context cannot see the exact installed helper file.",
            );
        }
        if request.get("operation").and_then(Value::as_str) == Some("inject") {
            let dll = Path::new(
                request
                    .get("dll_path")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            if !shared_file(dll, peer)
                || (peer != runtime.anchor_pid && !shared_file(dll, runtime.anchor_pid))
            {
                return OperationResult::error(
                    "dll_inaccessible",
                    "The execution context cannot see the exact selected DLL file.",
                );
            }
        }
    }
    command.arg(helper);
    let argument_request = matches!(runtime.strategy.as_str(), "app_launcher" | "steam_broker")
        || (runtime.strategy == "proton_runtime" && !runtime.launcher_path.is_empty());
    execute(command, request, timeout_ms, argument_request)
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Only our launched helper/runtime process, never a selected target or shared wineserver.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

fn drain(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    count: &mut usize,
    limit: usize,
    retain: bool,
) -> io::Result<bool> {
    let mut bytes = [0_u8; 8192];
    // One bounded read per stream gives the writer, other stream and deadline a turn,
    // even if a chatty child keeps this pipe continuously readable.
    match reader.read(&mut bytes) {
        Ok(0) => Ok(true),
        Ok(n) => {
            *count += n;
            if *count > limit {
                return Err(io::Error::other("output limit"));
            }
            if retain {
                output.extend_from_slice(&bytes[..n]);
            }
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn execute(
    mut command: Command,
    mut request: Value,
    timeout_ms: u64,
    argument_request: bool,
) -> OperationResult {
    if !(1..=120000).contains(&timeout_ms) || !request.is_object() {
        return OperationResult::error(
            "invalid_request",
            "The helper request or transport timeout is invalid.",
        );
    }
    let Some(operation) = request
        .get("operation")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return OperationResult::error("invalid_request", "The helper operation must be a string.");
    };
    let mut entropy = [0_u8; 16];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut entropy))
        .is_err()
    {
        return OperationResult::error(
            "helper_identity",
            "Could not obtain a fresh request identity.",
        );
    }
    let request_id: String = entropy
        .iter()
        .flat_map(|byte| {
            let hex = b"0123456789abcdef";
            [
                char::from(hex[usize::from(*byte >> 4)]),
                char::from(hex[usize::from(*byte & 15)]),
            ]
        })
        .collect();
    request["protocol_version"] = json!(1);
    request["request_id"] = json!(request_id);
    let mut input = match serde_json::to_vec(&request) {
        Ok(input) => input,
        Err(_) => {
            return OperationResult::error(
                "invalid_request",
                "The request cannot be encoded as JSON.",
            );
        }
    };
    input.push(b'\n');
    if input.len() > 65536 {
        return OperationResult::error(
            "invalid_request",
            "The helper request exceeds the size limit.",
        );
    }
    if argument_request {
        let text = std::str::from_utf8(&input[..input.len() - 1]).expect("JSON is UTF-8");
        if text.encode_utf16().count() > 30000 {
            return OperationResult::error(
                "invalid_request",
                "The runtime request exceeds the Windows command-line limit.",
            );
        }
        command.args(["--request-json", text]);
    }
    command
        .stdin(if argument_request {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut process = match command.spawn() {
        Ok(child) => OwnedChild(child),
        Err(_) => {
            return OperationResult::error(
                "helper_start",
                "The selected runtime could not start the Windows helper.",
            );
        }
    };
    let uncertain = operation == "inject";
    let mut stdout = process.0.stdout.take().expect("piped stdout");
    let mut stderr = process.0.stderr.take().expect("piped stderr");
    let mut stdin = process.0.stdin.take();
    if nonblocking(&stdout).is_err()
        || nonblocking(&stderr).is_err()
        || stdin
            .as_ref()
            .is_some_and(|input| nonblocking(input).is_err())
    {
        return failure(
            "helper_io",
            "Could not configure bounded helper transport.",
            uncertain,
        );
    }
    // This is only an owned, unreaped Child, never a discovered target. Old kernels
    // or sandbox policies may reject pidfd_open. Bounded poll timeouts then observe exit.
    let pidfd = Pid::from_raw(process.0.id() as i32)
        .and_then(|pid| pidfd_open(pid, PidfdFlags::empty()).ok());
    let deadline = started + Duration::from_millis(timeout_ms);
    let mut status = None;
    let (mut stdout_done, mut stderr_done) = (false, false);
    let mut output = Vec::new();
    let mut discard = Vec::new();
    let (mut stdout_count, mut stderr_count, mut written) = (0, 0, 0);
    loop {
        if Instant::now() >= deadline {
            return failure(
                "helper_timeout",
                if uncertain {
                    "The helper timed out. DLL loading may still complete. Do not retry automatically."
                } else {
                    "The helper operation exceeded its transport deadline."
                },
                uncertain,
            );
        }
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&input[written..]) {
                Ok(0) => {
                    return failure(
                        "helper_write",
                        "The helper request could not be written.",
                        uncertain,
                    );
                }
                Ok(n) => written += n,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    return failure(
                        "helper_write",
                        "The helper request could not be written.",
                        uncertain,
                    );
                }
            }
            if written == input.len() {
                stdin.take();
            }
        }
        // Discard stderr: it can reveal private environment paths.
        let out = if stdout_done {
            Ok(true)
        } else {
            drain(
                &mut stdout,
                &mut output,
                &mut stdout_count,
                OUTPUT_LIMIT,
                true,
            )
        };
        let err = if stderr_done {
            Ok(true)
        } else {
            drain(
                &mut stderr,
                &mut discard,
                &mut stderr_count,
                STDERR_LIMIT,
                false,
            )
        };
        if out.is_err() || err.is_err() {
            let overflow = stdout_count > OUTPUT_LIMIT || stderr_count > STDERR_LIMIT;
            return failure(
                if overflow {
                    "helper_output_limit"
                } else {
                    "helper_io"
                },
                if overflow {
                    "The runtime exceeded the bounded output limit."
                } else {
                    "The helper output could not be read."
                },
                uncertain,
            );
        }
        stdout_done = out.unwrap_or(false);
        stderr_done = err.unwrap_or(false);
        if status.is_none() {
            match process.0.try_wait() {
                Ok(value) => status = value,
                Err(_) => {
                    return failure(
                        "helper_io",
                        "Could not observe helper process completion.",
                        uncertain,
                    );
                }
            }
        }
        if let Some(status) = status
            && stdout_done
            && stderr_done
        {
            if status.code().is_none() {
                return failure(
                    "helper_crash",
                    "The runtime/helper crashed before completing the request.",
                    uncertain,
                );
            }
            let mut result = parse_response(&output, &request_id, &operation);
            if result.success && !status.success() {
                return failure(
                    "helper_exit",
                    "The runtime exited unsuccessfully despite a success response.",
                    uncertain,
                );
            }
            if !result.success && result.response.is_null() && uncertain {
                result.inconclusive = true;
            }
            return result;
        }
        // Poll only live descriptors: a closed stream or reaped child otherwise
        // reports HUP forever. Stack storage avoids allocation on every partial I/O.
        let mut fds = std::array::from_fn::<_, 4, _>(|_| PollFd::new(&stdout, PollFlags::IN));
        let mut count = 0;
        if !stdout_done {
            fds[count] = PollFd::new(&stdout, PollFlags::IN);
            count += 1;
        }
        if !stderr_done {
            fds[count] = PollFd::new(&stderr, PollFlags::IN);
            count += 1;
        }
        if let Some(pipe) = stdin.as_ref() {
            fds[count] = PollFd::new(pipe, PollFlags::OUT);
            count += 1;
        }
        if status.is_none()
            && let Some(fd) = pidfd.as_ref()
        {
            fds[count] = PollFd::new(fd, PollFlags::IN);
            count += 1;
        }
        let mut remaining = deadline.saturating_duration_since(Instant::now());
        if status.is_none() && pidfd.is_none() {
            remaining = remaining.min(Duration::from_millis(20));
        }
        let timeout = Timespec::try_from(remaining).expect("bounded transport timeout");
        match poll(&mut fds[..count], Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(_) => {
                return failure("helper_io", "Could not poll helper transport.", uncertain);
            }
        }
    }
}

// serde_json::Value normally silently accepts duplicate object fields. Reject them recursively,
// so no response can carry two conflicting correlation identities or module-evidence fields.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| UniqueJson(Value::Number(v)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse_response(output: &[u8], request_id: &str, operation: &str) -> OperationResult {
    if output.len() > OUTPUT_LIMIT {
        return OperationResult::error(
            "helper_output_limit",
            "The helper exceeded the response size limit.",
        );
    }
    let line = output.strip_suffix(b"\n").unwrap_or(output);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        return OperationResult::error(
            "helper_protocol",
            "Expected exactly one JSON response line.",
        );
    }
    let response = match serde_json::from_slice::<UniqueJson>(line) {
        Ok(UniqueJson(value)) if value.is_object() => value,
        _ => {
            return OperationResult::error(
                "helper_protocol",
                "The helper returned malformed or duplicate-key JSON.",
            );
        }
    };
    if response.get("protocol_version").and_then(Value::as_u64) != Some(1)
        || response.get("request_id").and_then(Value::as_str) != Some(request_id)
        || response.get("operation").and_then(Value::as_str) != Some(operation)
        || !response.get("status").is_some_and(Value::is_string)
        || !response.get("error_code").is_some_and(Value::is_string)
        || !response.get("error_message").is_some_and(Value::is_string)
        || response
            .get("inconclusive")
            .is_some_and(|flag| !flag.is_boolean())
    {
        return OperationResult::error(
            "helper_protocol",
            "The helper response identity or required fields do not match.",
        );
    }
    let status = response["status"].as_str().unwrap_or("");
    let code = response["error_code"].as_str().unwrap_or("");
    let message = response["error_message"].as_str().unwrap_or("");
    if status == "success"
        && code.is_empty()
        && message.is_empty()
        && response.get("inconclusive").and_then(Value::as_bool) != Some(true)
    {
        return OperationResult {
            success: true,
            response,
            ..OperationResult::default()
        };
    }
    if status != "error" || code.is_empty() {
        return OperationResult::error(
            "helper_protocol",
            "The helper returned inconsistent status/error fields.",
        );
    }
    OperationResult {
        success: false,
        error_code: code.chars().take(128).collect(),
        message: message.chars().take(2048).collect(),
        inconclusive: response
            .get("inconclusive")
            .and_then(Value::as_bool)
            .unwrap_or(operation == "inject"),
        response,
    }
}

pub fn inject_dll(process: &Process, path: &str) -> OperationResult {
    if !process.injectable
        || process.windows_pid == 0
        || process.architecture != "x64"
        || process.image_path.is_empty()
        || !decimal_nonzero(&process.creation_time)
    {
        return OperationResult::error(
            "unsupported_target",
            "Select a live x64 Windows process with a complete helper identity.",
        );
    }
    let absolute = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => return OperationResult::error("invalid_dll", "The selected DLL does not exist."),
    };
    let Some(path) = absolute.to_str() else {
        return OperationResult::error("invalid_dll", "The DLL filename is not UTF-8.");
    };
    // Keep the descriptor whose headers we inspected alive through the operation.
    // Neither this nor Windows sharing locks prevent every native Unix pathname race.
    let mut file = match open_dll(path) {
        Ok(file) => file,
        Err(_) => return OperationResult::error("invalid_dll", "The DLL could not be opened."),
    };
    let original = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return OperationResult::error("invalid_dll", "The DLL metadata is inaccessible.");
        }
    };
    let dll = validate_open_dll(&mut file);
    if !dll.valid {
        return OperationResult::error("invalid_dll", dll.error);
    }
    let enumeration = run_helper(
        &process.runtime,
        json!({"operation": "list_processes"}),
        15000,
    );
    if !enumeration.success {
        return enumeration;
    }
    let rows = match crate::discovery::parse_process_snapshot(
        &enumeration.response["processes"],
        &process.runtime,
        &process.steam_app_id,
    ) {
        Ok(rows) => rows,
        Err(error) => return OperationResult::error("helper_protocol", error),
    };
    if !rows.iter().any(|row| {
        row.windows_pid == process.windows_pid
            && row.image_path == process.image_path
            && row.creation_time == process.creation_time
            && row.architecture == "x64"
    }) {
        return OperationResult::error(
            "target_identity",
            "The target exited or its Windows identity changed. Refresh the process list.",
        );
    }
    if !unchanged_dll(&file, &original, &absolute) {
        return OperationResult::error(
            "dll_identity_changed",
            "The DLL changed after validation. Select it again.",
        );
    }
    let mut result = run_helper(
        &process.runtime,
        json!({"operation": "inject", "target_windows_pid": process.windows_pid,
        "expected_image_path": process.image_path, "expected_creation_time": process.creation_time,
        "dll_path": path, "method": "load_library_w", "timeout_ms": 10000}),
        15000,
    );
    if result.success
        && (!verified_injection(
            &result.response,
            process.windows_pid,
            &process.image_path,
            &process.creation_time,
        ) || !unchanged_dll(&file, &original, &absolute))
    {
        result = failure(
            "helper_protocol",
            "Module-loading evidence or the selected DLL identity could not be verified. Do not retry automatically.",
            true,
        );
    }
    if result.success {
        result.message = format!(
            "Injection verified: {}",
            result.response["loaded_module_path"].as_str().unwrap_or("")
        );
    }
    result
}

fn unchanged_dll(file: &File, original: &fs::Metadata, path: &Path) -> bool {
    let same = |metadata: &fs::Metadata| {
        metadata.is_file()
            && metadata.dev() == original.dev()
            && metadata.ino() == original.ino()
            && metadata.len() == original.len()
            && metadata.mtime() == original.mtime()
            && metadata.mtime_nsec() == original.mtime_nsec()
            && metadata.ctime() == original.ctime()
            && metadata.ctime_nsec() == original.ctime_nsec()
    };
    file.metadata().is_ok_and(|metadata| same(&metadata))
        && fs::metadata(path).is_ok_and(|metadata| same(&metadata))
}
fn decimal_nonzero(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|number| number != 0)
}
fn verified_injection(response: &Value, pid: u32, image: &str, creation: &str) -> bool {
    response.get("verified").and_then(Value::as_bool) == Some(true)
        && response.get("target_windows_pid").and_then(Value::as_u64) == Some(u64::from(pid))
        && response.get("method").and_then(Value::as_str) == Some("load_library_w")
        && response.get("target_image_path").and_then(Value::as_str) == Some(image)
        && response.get("target_creation_time").and_then(Value::as_str) == Some(creation)
        && response
            .get("file_identity_verified")
            .and_then(Value::as_bool)
            == Some(true)
        && response
            .get("remote_thread_exit_code")
            .and_then(Value::as_u64)
            .is_some_and(|code| u32::try_from(code).is_ok())
        && response
            .get("loaded_module_path")
            .and_then(Value::as_str)
            .is_some_and(|path| {
                path.len() <= 4 * 260
                    && !path.contains('\0')
                    && (path.starts_with("\\\\")
                        || (path.as_bytes().get(1..3) == Some(b":\\")
                            && path.as_bytes()[0].is_ascii_alphabetic()))
            })
        && response
            .get("module_base")
            .and_then(Value::as_str)
            .is_some_and(decimal_nonzero)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
#[derive(Clone, Copy, Default)]
struct Section {
    address: u64,
    extent: u64,
    raw_offset: u64,
    raw_size: u64,
}
fn overlaps(a: u64, size_a: u64, b: u64, size_b: u64) -> bool {
    size_a != 0 && size_b != 0 && a < b + size_b && b < a + size_a
}

fn open_dll(path: &str) -> io::Result<File> {
    // Opening first with O_NONBLOCK avoids a metadata/open FIFO replacement race.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NONBLOCK.bits() as i32)
        .open(path)
}

/// Inspect bounded PE data, not the entire DLL. Validation does not establish trust.
pub fn validate_dll(path: &str) -> DllInfo {
    match open_dll(path) {
        Ok(mut file) => validate_open_dll(&mut file),
        Err(_) => DllInfo {
            error: "The DLL could not be opened for reading.".into(),
            ..DllInfo::default()
        },
    }
}

fn validate_open_dll(file: &mut File) -> DllInfo {
    fn check(file: &mut File) -> Result<(), (String, String)> {
        let bad = |message: &str| (String::new(), message.to_owned());
        let metadata = file
            .metadata()
            .map_err(|_| bad("The DLL metadata is inaccessible."))?;
        if !metadata.is_file() {
            return Err(bad("The DLL must be an existing regular file."));
        }
        let length = metadata.len();
        if !(64..=u64::from(u32::MAX)).contains(&length) {
            return Err(bad("The DLL has an unsupported or truncated file size."));
        }
        file.rewind()
            .map_err(|_| bad("Could not seek DLL headers."))?;
        let mut dos = [0_u8; 64];
        file.read_exact(&mut dos)
            .map_err(|_| bad("The DOS header is truncated."))?;
        if &dos[..2] != b"MZ" {
            return Err(bad("The file is not a PE image (missing DOS header)."));
        }
        let nt = u64::from(u32_at(&dos, 60));
        if nt < 64 || nt > i32::MAX as u64 || nt + 24 > length {
            return Err(bad("The PE header offset is outside the file."));
        }
        file.seek(SeekFrom::Start(nt))
            .map_err(|_| bad("Could not seek PE headers."))?;
        let mut coff = [0_u8; 24];
        file.read_exact(&mut coff)
            .map_err(|_| bad("The PE header is truncated."))?;
        if &coff[..4] != b"PE\0\0" {
            return Err(bad("The file has an invalid PE signature."));
        }
        let machine = u16_at(&coff, 4);
        if machine != 0x8664 {
            return Err((
                if machine == 0x14c { "x86" } else { "unknown" }.into(),
                "Only native x86-64 DLLs are supported.".into(),
            ));
        }
        let count = usize::from(u16_at(&coff, 6));
        let optional_size = usize::from(u16_at(&coff, 20));
        let characteristics = u16_at(&coff, 22);
        if !(1..=96).contains(&count)
            || !(112..=4096).contains(&optional_size)
            || characteristics & 0x2002 != 0x2002
        {
            return Err(bad(
                "The PE image is not a loadable DLL or has unsupported headers.",
            ));
        }
        let table_end = nt + 24 + optional_size as u64 + count as u64 * 40;
        if table_end > length {
            return Err(bad("The PE optional header or section table is truncated."));
        }
        let mut optional = [0_u8; 4096];
        file.read_exact(&mut optional[..optional_size])
            .map_err(|_| bad("The PE optional header is truncated."))?;
        if u16_at(&optional, 0) != 0x20b {
            return Err(bad("The DLL must use PE32+ headers."));
        }
        let entry = u64::from(u32_at(&optional, 16));
        let section_alignment = u32_at(&optional, 32);
        let file_alignment = u32_at(&optional, 36);
        let image_size = u64::from(u32_at(&optional, 56));
        let header_size = u64::from(u32_at(&optional, 60));
        let directories = u32_at(&optional, 108) as usize;
        if !section_alignment.is_power_of_two()
            || !file_alignment.is_power_of_two()
            || section_alignment < file_alignment
            || file_alignment > 65536
            || (if section_alignment < 4096 {
                section_alignment != file_alignment
            } else {
                file_alignment < 512
            })
            || image_size == 0
            || image_size % u64::from(section_alignment) != 0
            || header_size < table_end
            || header_size > length
            || header_size > image_size
            || header_size % u64::from(file_alignment) != 0
            || entry >= image_size
            || directories > 16
            || 112 + directories * 8 > optional_size
        {
            return Err(bad(
                "The PE image has invalid alignment, sizes, or data-directory bounds.",
            ));
        }
        if directories > 14 && (u32_at(&optional, 224) != 0 || u32_at(&optional, 228) != 0) {
            return Err(bad(
                "Managed/.NET DLLs are unsupported. Select a native x86-64 DLL.",
            ));
        }
        let mut sections = [Section::default(); 96];
        let mut executable_entry = entry == 0;
        for index in 0..count {
            let mut bytes = [0_u8; 40];
            file.read_exact(&mut bytes)
                .map_err(|_| bad("The PE section table is truncated."))?;
            let section = Section {
                address: u64::from(u32_at(&bytes, 12)),
                extent: u64::from(u32_at(&bytes, 8).max(u32_at(&bytes, 16))),
                raw_offset: u64::from(u32_at(&bytes, 20)),
                raw_size: u64::from(u32_at(&bytes, 16)),
            };
            if !section.address.is_multiple_of(u64::from(section_alignment))
                || section.address < header_size
                || section.address + section.extent > image_size
                || (section.raw_size != 0
                    && (section.raw_offset < header_size
                        || !section.raw_offset.is_multiple_of(u64::from(file_alignment))
                        || !section.raw_size.is_multiple_of(u64::from(file_alignment))
                        || section.raw_offset + section.raw_size > length))
            {
                return Err(bad(
                    "A PE section has invalid alignment or extends beyond the image/file.",
                ));
            }
            for other in &sections[..index] {
                if overlaps(section.address, section.extent, other.address, other.extent)
                    || overlaps(
                        section.raw_offset,
                        section.raw_size,
                        other.raw_offset,
                        other.raw_size,
                    )
                {
                    return Err(bad("PE sections overlap."));
                }
            }
            if entry >= section.address
                && entry < section.address + section.raw_size
                && u32_at(&bytes, 36) & 0x20000000 != 0
            {
                executable_entry = true;
            }
            sections[index] = section;
        }
        if !executable_entry {
            return Err(bad(
                "The DLL entry point does not lie in a backed executable section.",
            ));
        }
        for index in 0..directories {
            let address = u64::from(u32_at(&optional, 112 + index * 8));
            let size = u64::from(u32_at(&optional, 116 + index * 8));
            if address == 0 && size == 0 {
                continue;
            }
            let mapped = address != 0
                && size != 0
                && if index == 4 {
                    address % 8 == 0 && address + size <= length
                } else {
                    address + size <= header_size
                        || sections[..count].iter().any(|section| {
                            address >= section.address
                                && address + size <= section.address + section.raw_size
                        })
                };
            if !mapped {
                return Err(bad("A PE data directory points outside backed image data."));
            }
        }
        Ok(())
    }
    match check(file) {
        Ok(()) => DllInfo {
            valid: true,
            architecture: "x64".into(),
            error: String::new(),
        },
        Err((architecture, error)) => DllInfo {
            valid: false,
            architecture,
            error,
        },
    }
}

#[cfg(test)]
#[path = "../tests/helper_transport/cases.rs"]
mod tests;
