use crate::types::{RouteProbe, Runtime};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub(crate) type Environment = BTreeMap<String, String>;
pub(crate) fn read_bounded(path: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    // Avoid blocking when a metadata path is replaced with a FIFO.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Process metadata must be a regular file".into());
    }
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err("Process metadata exceeds its size limit".into());
    }
    Ok(bytes)
}
pub(crate) fn link(path: impl AsRef<Path>) -> String {
    fs::read_link(path)
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_default()
}
pub(crate) fn canonical(path: impl AsRef<Path>) -> String {
    fs::canonicalize(path)
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_default()
}
pub(crate) fn clean(path: &str) -> String {
    let mut result = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::ParentDir => {
                if !result.pop() && !path.starts_with('/') {
                    result.push("..");
                }
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result.to_string_lossy().into_owned()
}
pub(crate) fn uid() -> u32 {
    fs::metadata("/proc/self")
        .expect("Linux /proc/self is required")
        .uid()
}
pub(crate) fn executable(path: &str) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
}
pub(crate) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}
fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.mode() == b.mode()
        && a.size() == b.size()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
#[derive(Debug)]
pub(crate) struct ProcStat {
    pub pid: u32,
    pub name: String,
    pub ticks: u64,
}
pub(crate) fn parse_stat(data: &[u8]) -> Option<ProcStat> {
    if data.len() > 65536 || data.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let opening = text.find('(')?;
    let closing = text.rfind(')')?;
    if opening < 2 || closing <= opening || text.as_bytes().get(closing + 1) != Some(&b' ') {
        return None;
    }
    let pid: u32 = text[..opening].trim().parse().ok()?;
    let mut fields = text[closing + 2..].split_ascii_whitespace();
    let state = fields.next()?;
    if pid == 0 || state.len() != 1 {
        return None;
    }
    let ticks = fields.nth(18)?.parse().ok()?;
    if ticks == 0 {
        return None;
    }
    Some(ProcStat {
        pid,
        name: text[opening + 1..closing].into(),
        ticks,
    })
}
pub(crate) fn parse_environment(data: &[u8]) -> Option<Environment> {
    if data.len() > 1048576 || (!data.is_empty() && data.last() != Some(&0)) {
        return None;
    }
    let mut result = Environment::new();
    for entry in data.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let split = entry.iter().position(|b| *b == b'=')?;
        if split == 0 {
            return None;
        }
        let key = std::str::from_utf8(&entry[..split]).ok()?.to_owned();
        let value = std::str::from_utf8(&entry[split + 1..]).ok()?.to_owned();
        if result.insert(key, value).is_some() {
            return None;
        }
    }
    Some(result)
}
pub(crate) fn environment(pid: u32) -> Result<Environment, String> {
    parse_environment(&read_bounded(format!("/proc/{pid}/environ"), 1048576)?)
        .ok_or_else(|| "The process environment is malformed or inaccessible".into())
}
pub(crate) fn value<'a>(environment: &'a Environment, key: &str) -> &'a str {
    environment.get(key).map(String::as_str).unwrap_or("")
}
pub(crate) fn declared_prefix(environment: &Environment) -> String {
    let wine = value(environment, "WINEPREFIX");
    let compat = value(environment, "STEAM_COMPAT_DATA_PATH");
    let home = value(environment, "HOME");
    let prefix = if !wine.is_empty() {
        wine.into()
    } else if !compat.is_empty() {
        format!("{compat}/pfx")
    } else if !home.is_empty() {
        format!("{home}/.wine")
    } else {
        String::new()
    };
    if prefix.starts_with('/') {
        clean(&prefix)
    } else {
        String::new()
    }
}
pub(crate) fn selected_prefix(environment: &Environment) -> String {
    let path = declared_prefix(environment);
    if Path::new(&path).is_dir() {
        canonical(path)
    } else {
        String::new()
    }
}
pub(crate) fn launch_context(environment: &Environment) -> String {
    let temporary = value(environment, "TMPDIR");
    let temporary = clean(if temporary.is_empty() {
        "/tmp"
    } else {
        temporary
    });
    let xdg = value(environment, "XDG_RUNTIME_DIR");
    let xdg = if xdg.starts_with('/') {
        clean(xdg)
    } else {
        String::new()
    };
    format!("{}:{}{}:{}", temporary.len(), temporary, xdg.len(), xdg)
}
pub(crate) fn namespace_key(pid: u32) -> String {
    format!(
        "{:?}",
        ["mnt", "user", "pid"].map(|n| link(format!("/proc/{pid}/ns/{n}")))
    )
}
pub(crate) fn permitted_environment(source: &Environment) -> Environment {
    const ALLOWED: &[&str] = &[
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TMPDIR",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "DBUS_SESSION_BUS_ADDRESS",
        "LD_LIBRARY_PATH",
        "WINEPREFIX",
        "WINEARCH",
        "WINEDLLOVERRIDES",
        "WINEESYNC",
        "WINEFSYNC",
        "STEAM_COMPAT_DATA_PATH",
        "STEAM_COMPAT_CLIENT_INSTALL_PATH",
        "STEAM_COMPAT_INSTALL_PATH",
        "STEAM_COMPAT_SHADER_PATH",
        "STEAM_COMPAT_APP_ID",
        "STEAM_COMPAT_LIBRARY_PATHS",
        "STEAM_COMPAT_MOUNTS",
        "STEAM_COMPAT_TOOL_PATHS",
        "PRESSURE_VESSEL_RUNTIME_BASE",
        "PRESSURE_VESSEL_RUNTIME",
        "SteamAppId",
        "SteamGameId",
        "SRT_LAUNCHER_SERVICE_ALONGSIDE_STEAM",
        "PROTON_USE_WINED3D",
        "PROTON_NO_ESYNC",
        "PROTON_NO_FSYNC",
    ];
    source
        .iter()
        .filter(|(key, _)| ALLOWED.contains(&key.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
const MAX_MAPS_BYTES: usize = 4 * 1048576;
const MAX_MAPS_LINE: usize = 65536;

fn mapped_wine(executable_path: &str, mut maps: impl Read) -> String {
    if !executable_path.starts_with('/') || executable_path.ends_with(" (deleted)") {
        return String::new();
    }
    let mut buffer = [0u8; MAX_MAPS_LINE];
    let mut pending = 0;
    let mut total = 0;
    let mut ntdll = false;
    let mut loader = String::new();
    loop {
        let available = (MAX_MAPS_BYTES + 1 - total).min(buffer.len() - pending);
        if available == 0 {
            return String::new();
        }
        let count = match maps.read(&mut buffer[pending..pending + available]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return String::new(),
        };
        total += count;
        if total > MAX_MAPS_BYTES {
            return String::new();
        }
        let end = pending + count;
        let mut start = 0;
        for index in pending..end {
            if buffer[index] != b'\n' {
                continue;
            }
            let line = &buffer[start..index];
            start = index + 1;
            let mut fields = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|v| !v.is_empty());
            let _address = fields.next();
            if fields.next() != Some(b"r-xp".as_slice()) {
                continue;
            }
            // Pathnames are not whitespace-delimited: spaces, tabs and backslashes
            // are literal in procfs maps. Only newline is escaped, ambiguously.
            let Some(path_start) = line.iter().position(|byte| *byte == b'/') else {
                continue;
            };
            let path = &line[path_start..];
            let name = path.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
            if name != b"ntdll.so" && name != b"wine" && name != b"wine64" {
                continue;
            }
            if path.windows(4).any(|bytes| bytes == b"\\012") {
                return String::new();
            }
            if name == b"ntdll.so" {
                // Wine's source-tree and custom installs can put ntdll.so beside
                // an arbitrarily named loader, outside any directory named wine.
                ntdll = true;
                continue;
            }
            let Ok(path) = std::str::from_utf8(path) else {
                return String::new();
            };
            let canonical = canonical(path);
            let selected = if canonical.is_empty() {
                path
            } else {
                &canonical
            };
            if !loader.is_empty() && loader != selected {
                return String::new();
            }
            if loader.is_empty() {
                loader = selected.into();
            }
        }
        pending = end - start;
        buffer.copy_within(start..end, 0);
    }
    // A partial final record cannot establish executable identity.
    if !ntdll || pending != 0 {
        return String::new();
    }
    let basename = Path::new(executable_path)
        .file_name()
        .and_then(|v| v.to_str());
    if matches!(basename, Some("wine-preloader" | "wine64-preloader")) {
        return loader;
    }
    // Most processes are not Wine. Avoid realpath's component-by-component
    // probes and all pathname allocation until a Wine mapping was observed.
    let executable = canonical(executable_path);
    let executable = if executable.is_empty() {
        executable_path
    } else {
        &executable
    };
    if !loader.is_empty() && loader != executable {
        return String::new();
    }
    executable.into()
}
pub(crate) fn wine(pid: u32) -> String {
    let executable = link(format!("/proc/{pid}/exe"));
    if !executable.starts_with('/') || executable.ends_with(" (deleted)") {
        return String::new();
    }
    File::open(format!("/proc/{pid}/maps"))
        .map(|maps| mapped_wine(&executable, maps))
        .unwrap_or_default()
}
pub(crate) fn proton_for_wine(binary: &str) -> String {
    let Some(mut directory) = Path::new(binary).parent() else {
        return String::new();
    };
    for _ in 0..8 {
        let script = directory.join("proton");
        if executable(script.to_str().unwrap_or("")) && Path::new(binary).starts_with(directory) {
            return canonical(script);
        }
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent;
    }
    String::new()
}
fn component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}
pub(crate) fn steam_runtime_for(environment: &Environment) -> String {
    let version = value(environment, "PRESSURE_VESSEL_RUNTIME");
    if !component(version) {
        return String::new();
    }
    let validate = |declared: &str| -> Option<String> {
        if !declared.starts_with('/') {
            return None;
        }
        let root = canonical(declared);
        if root.is_empty() || !Path::new(&root).is_dir() {
            return None;
        }
        let selected = canonical(format!("{root}/{version}/files"));
        if selected.is_empty()
            || !Path::new(&selected).is_dir()
            || !executable(&format!("{root}/run"))
        {
            return None;
        }
        let script = read_bounded(format!("{root}/run"), 16384).ok()?;
        let mut configured = None;
        for line in std::str::from_utf8(&script).ok()?.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("dir=") {
                if configured.is_some() {
                    return None;
                }
                let value = if value.len() >= 2
                    && ((value.starts_with('\'') && value.ends_with('\''))
                        || (value.starts_with('"') && value.ends_with('"')))
                {
                    &value[1..value.len() - 1]
                } else {
                    value
                };
                if !component(value) {
                    return None;
                }
                configured = Some(value);
            }
        }
        if canonical(format!("{root}/{}/files", configured?)) != selected {
            return None;
        }
        Some(canonical(format!("{root}/run")))
    };
    let base = value(environment, "PRESSURE_VESSEL_RUNTIME_BASE");
    if !base.is_empty() {
        return validate(base).unwrap_or_default();
    }
    let mut selected = String::new();
    for tool in value(environment, "STEAM_COMPAT_TOOL_PATHS").split(':') {
        if let Some(candidate) = validate(tool) {
            if !selected.is_empty()
                && !same_file(
                    Path::new(&selected).parent().unwrap(),
                    Path::new(&candidate).parent().unwrap(),
                )
            {
                return String::new();
            }
            selected = candidate;
        }
    }
    selected
}
pub(crate) fn anchor_alive(pid: u32, ticks: u64) -> Result<(), String> {
    let base = format!("/proc/{pid}");
    if pid == 0 || ticks == 0 || !fs::metadata(&base).is_ok_and(|m| m.uid() == uid()) {
        return Err("Runtime anchor exited or is foreign-owned".into());
    }
    let state = parse_stat(&read_bounded(format!("{base}/stat"), 65536)?)
        .ok_or("Invalid runtime process identity")?;
    if state.pid != pid || state.ticks != ticks {
        return Err("Runtime anchor exited or its PID was reused. Refresh the process list".into());
    }
    Ok(())
}
pub(crate) fn validate_anchor(
    pid: u32,
    ticks: u64,
    container: bool,
    peer: u32,
) -> Result<(), String> {
    anchor_alive(pid, ticks)?;
    if peer != 0
        && (!fs::metadata(format!("/proc/{peer}")).is_ok_and(|m| m.uid() == uid())
            || !same_file(format!("/proc/{peer}/ns/pid"), "/proc/self/ns/pid"))
    {
        return Err(
            "Helper launch peer is unavailable, foreign-owned or in another PID namespace".into(),
        );
    }
    if container
        && !same_file(
            format!("/proc/{pid}/root/tmp"),
            if peer == 0 {
                "/tmp".into()
            } else {
                format!("/proc/{peer}/root/tmp")
            },
        )
    {
        return Err(
            "The runtime does not share the verified helper launch context's temporary directory"
                .into(),
        );
    }
    for name in ["mnt", "user", "pid"] {
        let own = link(format!("/proc/self/ns/{name}"));
        let target = link(format!("/proc/{pid}/ns/{name}"));
        if own.is_empty() || target.is_empty() || (own != target && !(container && name != "pid")) {
            return Err(format!(
                "The runtime's {name} namespace differs from the verified launch context"
            ));
        }
    }
    Ok(())
}
fn pointer_metadata(path: &str) -> Result<Option<Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn read_pointer(path: &str, expected: &Metadata) -> Result<Vec<u8>, String> {
    // Reject symlinks and avoid blocking on a substituted FIFO.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !unchanged(expected, &file.metadata().map_err(|e| e.to_string())?) {
        return Err("Wineserver pointer changed before open".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(13)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() != 11
        || !bytes.starts_with(b"wine-")
        || !bytes[5..].iter().all(u8::is_ascii_alphanumeric)
        || !unchanged(expected, &file.metadata().map_err(|e| e.to_string())?)
    {
        return Err("Invalid or changed wineserver pointer".into());
    }
    Ok(bytes)
}
pub(crate) fn shared_wineserver(
    prefix: &str,
    environment: &Environment,
    target: &str,
    peer: &str,
    peer_tmpdir: &str,
) -> Result<(), String> {
    let refusal = || {
        "The exact unique owned wineserver socket is not shared. No alternate Wine session will be started".to_string()
    };
    let metadata = fs::metadata(prefix).map_err(|_| refusal())?;
    if !metadata.is_dir()
        || metadata.uid() != uid()
        || !same_file(prefix, format!("{target}{prefix}"))
        || !same_file(prefix, format!("{peer}{prefix}"))
    {
        return Err(refusal());
    }
    let directory = format!("server-{:x}-{:x}", metadata.dev(), metadata.ino());
    let mut sockets = vec![
        format!("/tmp/.wine-{}/{directory}/socket", uid()),
        format!("/run/user/{}/wine/{directory}/socket", uid()),
    ];
    let xdg = value(environment, "XDG_RUNTIME_DIR");
    if xdg.starts_with('/') {
        sockets.push(format!("{}/wine/{directory}/socket", clean(xdg)));
    }
    let pointer = format!("{prefix}/wineserver");
    let before = pointer_metadata(&format!("{target}{pointer}"))?;
    let mut snapshots: Vec<(String, Metadata, bool)> = Vec::new();
    for root in [target, peer, ""] {
        let path = format!("{root}{pointer}");
        let m = pointer_metadata(&path)?;
        match (&before, m) {
            (None, None) => {}
            (Some(a), Some(b)) if unchanged(a, &b) => snapshots.push((path, b, true)),
            _ => return Err(refusal()),
        }
    }
    let mut pointer_socket = String::new();
    let mut peer_socket = String::new();
    if let Some(before) = before.as_ref() {
        if !before.is_file() || before.uid() != uid() || before.mode() & 0o7777 != 0o400 {
            return Err(refusal());
        }
        let name = read_pointer(&format!("{target}{pointer}"), before)?;
        if name != read_pointer(&format!("{peer}{pointer}"), before)? {
            return Err(refusal());
        }
        let name = std::str::from_utf8(&name).map_err(|_| refusal())?;
        let tmp = environment
            .get("TMPDIR")
            .map(String::as_str)
            .unwrap_or("/tmp");
        let peer_tmp = if peer_tmpdir.is_empty() {
            tmp
        } else {
            peer_tmpdir
        };
        if !tmp.starts_with('/')
            || !peer_tmp.starts_with('/')
            || !same_file(
                format!("{target}{}", clean(tmp)),
                format!("{peer}{}", clean(peer_tmp)),
            )
        {
            return Err(refusal());
        }
        let random = format!("{}/{name}", clean(tmp));
        let peer_random = format!("{}/{name}", clean(peer_tmp));
        for (a, b) in [
            (random.clone(), peer_random.clone()),
            (
                format!("{random}/{directory}"),
                format!("{peer_random}/{directory}"),
            ),
        ] {
            let a = format!("{target}{a}");
            let b = format!("{peer}{b}");
            let metadata = fs::metadata(&a).map_err(|_| refusal())?;
            let other = fs::metadata(&b).map_err(|_| refusal())?;
            if !metadata.is_dir()
                || metadata.uid() != uid()
                || metadata.mode() & 0o77 != 0
                || !unchanged(&metadata, &other)
            {
                return Err(refusal());
            }
            snapshots.push((a, metadata, false));
            snapshots.push((b, other, false));
        }
        pointer_socket = format!("{random}/{directory}/socket");
        peer_socket = format!("{peer_random}/{directory}/socket");
        sockets.push(pointer_socket.clone());
    }
    let mut found = None;
    let mut pointer_found = false;
    for socket in sockets {
        let Ok(a) = fs::metadata(format!("{target}{socket}")) else {
            continue;
        };
        if !a.file_type().is_socket() {
            continue;
        }
        let b = fs::metadata(format!(
            "{peer}{}",
            if socket == pointer_socket {
                &peer_socket
            } else {
                &socket
            }
        ))
        .map_err(|_| refusal())?;
        if a.uid() != uid()
            || a.mode() & 0o77 != 0
            || !b.file_type().is_socket()
            || !unchanged(&a, &b)
        {
            return Err(refusal());
        }
        let identity = (a.dev(), a.ino());
        if found.is_some_and(|old| old != identity) {
            return Err(refusal());
        }
        found = Some(identity);
        pointer_found |= socket == pointer_socket;
    }
    for (path, before, pointer) in snapshots {
        let after = if pointer {
            fs::symlink_metadata(path)
        } else {
            fs::metadata(path)
        }
        .map_err(|_| refusal())?;
        if !unchanged(&before, &after) {
            return Err(refusal());
        }
    }
    if before.is_none() {
        for root in [target, peer, ""] {
            if pointer_metadata(&format!("{root}{pointer}"))?.is_some() {
                return Err(refusal());
            }
        }
    }
    if found.is_none() || (before.is_some() && !pointer_found) {
        return Err(refusal());
    }
    Ok(())
}
pub(crate) fn validate_direct(runtime: &Runtime) -> Result<(), String> {
    validate_anchor(runtime.anchor_pid, runtime.start_ticks, false, 0)?;
    let root = format!("/proc/{}/root", runtime.anchor_pid);
    let environment = environment(runtime.anchor_pid)?;
    let prefix = if !value(&environment, "WINEPREFIX").is_empty() {
        value(&environment, "WINEPREFIX").to_string()
    } else {
        format!("{}/.wine", value(&environment, "HOME"))
    };
    if !prefix.starts_with('/')
        || runtime.prefix.is_empty()
        || !same_file(format!("{root}{prefix}"), &runtime.prefix)
    {
        return Err("Direct Wine prefix object changed or is inaccessible".into());
    }
    if !executable(&runtime.wine_binary)
        || wine(runtime.anchor_pid) != runtime.wine_binary
        || !same_file(
            format!("{root}{}", runtime.wine_binary),
            &runtime.wine_binary,
        )
    {
        return Err("The exact active Wine executable is not shared".into());
    }
    if !same_file(format!("{root}/tmp"), "/tmp") {
        return Err("Direct Wine temporary directory is not shared".into());
    }
    shared_wineserver(
        &runtime.prefix,
        &environment,
        &root,
        "",
        value(&environment, "TMPDIR"),
    )?;
    anchor_alive(runtime.anchor_pid, runtime.start_ticks)
}
pub(crate) fn validate_proton(runtime: &Runtime) -> Result<(), String> {
    validate_anchor(
        runtime.anchor_pid,
        runtime.start_ticks,
        !runtime.launcher_path.is_empty(),
        0,
    )?;
    let environment = environment(runtime.anchor_pid)?;
    let root = format!("/proc/{}/root", runtime.anchor_pid);
    if wine(runtime.anchor_pid) != runtime.wine_binary
        || proton_for_wine(&runtime.wine_binary) != runtime.proton_path
        || !executable(&runtime.proton_path)
    {
        return Err("The exact active Proton loader or wrapper changed".into());
    }
    if runtime.prefix.is_empty()
        || selected_prefix(&environment) != runtime.prefix
        || canonical(format!(
            "{}/pfx",
            value(&environment, "STEAM_COMPAT_DATA_PATH")
        )) != runtime.prefix
        || !same_file(format!("{root}{}", runtime.prefix), &runtime.prefix)
        || !same_file(
            format!("{root}{}", runtime.wine_binary),
            &runtime.wine_binary,
        )
    {
        return Err("The exact Proton prefix and loader objects are not shared".into());
    }
    let declared = !value(&environment, "PRESSURE_VESSEL_RUNTIME_BASE").is_empty()
        || !value(&environment, "PRESSURE_VESSEL_RUNTIME").is_empty();
    if (declared || !runtime.launcher_path.is_empty())
        && (runtime.launcher_path.is_empty()
            || steam_runtime_for(&environment) != runtime.launcher_path)
    {
        return Err("Declared Steam Runtime no longer identifies its exact launcher".into());
    }
    shared_wineserver(
        &runtime.prefix,
        &environment,
        &root,
        "",
        value(&environment, "TMPDIR"),
    )?;
    anchor_alive(runtime.anchor_pid, runtime.start_ticks)
}
pub fn revalidate(runtime: &Runtime) -> Result<(), String> {
    if runtime.namespace_key != namespace_key(runtime.anchor_pid)
        || runtime.launch_context_key != launch_context(&environment(runtime.anchor_pid)?)
    {
        return Err("Runtime namespace or launch context changed. Refresh the process list".into());
    }
    match runtime.strategy.as_str() {
        "direct_wine" => validate_direct(runtime),
        "proton_runtime" => validate_proton(runtime),
        "app_launcher" | "steam_broker" => crate::steam::revalidate(runtime),
        _ => Err("No authenticated launch route is selected".into()),
    }
}
pub(crate) const DESKTOP_KEYS: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "LD_LIBRARY_PATH",
];
pub(crate) const UNSET_KEYS: &[&str] =
    &["PROTON_LOG", "WINELOADER", "WINESERVER", "WINELOADERNOEXEC"];
fn desktop_environment() -> Environment {
    std::env::vars()
        .filter(|(k, _)| {
            [
                "HOME",
                "USER",
                "LOGNAME",
                "PATH",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "DBUS_SESSION_BUS_ADDRESS",
                "XDG_RUNTIME_DIR",
            ]
            .contains(&k.as_str())
        })
        .collect()
}
pub fn command(runtime: &Runtime) -> Result<Command, String> {
    revalidate(runtime)?;
    let mut environment = permitted_environment(&environment(runtime.anchor_pid)?);
    environment.insert("WINEPREFIX".into(), runtime.prefix.clone());
    environment.insert("WINEDEBUG".into(), "-all".into());
    let mut command = match runtime.strategy.as_str() {
        "direct_wine" => Command::new(&runtime.wine_binary),
        "proton_runtime" if runtime.launcher_path.is_empty() => {
            let mut c = Command::new(&runtime.proton_path);
            c.arg("runinprefix");
            c
        }
        "proton_runtime" => {
            environment.remove("LD_LIBRARY_PATH");
            for key in [
                "DBUS_SESSION_BUS_ADDRESS",
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XDG_RUNTIME_DIR",
            ] {
                environment.remove(key);
                if let Ok(v) = std::env::var(key) {
                    environment.insert(key.into(), v);
                }
            }
            let mut c = Command::new(&runtime.launcher_path);
            c.args(["--batch", "--", &runtime.proton_path, "runinprefix"]);
            c
        }
        "app_launcher" => {
            let mut c = Command::new(crate::steam::app_client(runtime)?);
            c.args(crate::steam::app_arguments(runtime));
            environment = desktop_environment();
            c
        }
        "steam_broker" => {
            let mut c = Command::new(&runtime.service_client);
            c.arg(format!("--bus-name={}", runtime.service_owner))
                .arg(format!("--directory={}", runtime.working_directory));
            for (key, value) in &environment {
                if !DESKTOP_KEYS.contains(&key.as_str()) {
                    c.arg(format!("--env={key}={value}"));
                }
            }
            for key in UNSET_KEYS {
                c.arg(format!("--unset-env={key}"));
            }
            c.args([
                "--",
                &runtime.launcher_path,
                "--batch",
                "--",
                &runtime.proton_path,
                "runinprefix",
            ]);
            environment = desktop_environment();
            c
        }
        _ => return Err("No authenticated launch route".into()),
    };
    command.env_clear().envs(environment).current_dir(
        if Path::new(&runtime.working_directory).is_dir() {
            &runtime.working_directory
        } else {
            &runtime.prefix
        },
    );
    Ok(command)
}
pub(crate) fn probe(strategy: &str, result: Result<(), String>) -> RouteProbe {
    match result {
        Ok(()) => RouteProbe {
            strategy: strategy.into(),
            available: true,
            code: "not_probed".into(),
            message: "Route checks passed. Application Windows visibility remains unverified"
                .into(),
        },
        Err(message) => RouteProbe {
            strategy: strategy.into(),
            available: false,
            code: "runtime_access_unavailable".into(),
            message,
        },
    }
}

pub(crate) fn image_architecture(path: &str) -> String {
    fn parse(path: &str) -> Option<&'static str> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() {
            return None;
        }
        let length = metadata.len();
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos).ok()?;
        if &dos[..2] != b"MZ" {
            return None;
        }
        let offset = u32::from_le_bytes(dos[60..64].try_into().ok()?) as u64;
        if offset < 64 || offset.checked_add(26)? > length {
            return None;
        }
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut header = [0u8; 26];
        file.read_exact(&mut header).ok()?;
        if &header[..4] != b"PE\0\0" {
            return None;
        }
        let u16_at = |n| u16::from_le_bytes([header[n], header[n + 1]]);
        let (machine, sections, optional_size, flags, magic) =
            (u16_at(4), u16_at(6), u16_at(20), u16_at(22), u16_at(24));
        if sections == 0
            || sections > 96
            || optional_size > 4096
            || flags & 0x2002 != 2
            || offset + 24 + u64::from(optional_size) + u64::from(sections) * 40 > length
        {
            return None;
        }
        let architecture = match (machine, magic) {
            (0x8664, 0x20b) if optional_size >= 112 => "x64",
            (0x14c, 0x10b) if optional_size >= 96 => "x86",
            _ => return None,
        };
        file.seek(SeekFrom::Start(offset + 24)).ok()?;
        let mut optional = [0u8; 64];
        file.read_exact(&mut optional).ok()?;
        let image_size = u32::from_le_bytes(optional[56..60].try_into().ok()?) as u64;
        let header_size = u32::from_le_bytes(optional[60..64].try_into().ok()?) as u64;
        if image_size == 0
            || header_size > image_size
            || header_size < offset + 24 + u64::from(optional_size) + u64::from(sections) * 40
            || header_size > length
        {
            return None;
        }
        file.seek(SeekFrom::Start(offset + 24 + u64::from(optional_size)))
            .ok()?;
        for _ in 0..sections {
            let mut item = [0u8; 40];
            file.read_exact(&mut item).ok()?;
            let u32_at = |n| u32::from_le_bytes(item[n..n + 4].try_into().unwrap()) as u64;
            let (virtual_size, address, raw_size, raw_offset) =
                (u32_at(8), u32_at(12), u32_at(16), u32_at(20));
            if address + virtual_size.max(raw_size) > image_size
                || (raw_size != 0 && (raw_offset < header_size || raw_offset + raw_size > length))
            {
                return None;
            }
        }
        Some(architecture)
    }
    parse(path).unwrap_or("").into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "needle-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn metadata_and_image_reads_reject_nonregular_paths_without_blocking() {
        let fixture = Fixture::new();
        let fifo = fixture.0.join("metadata");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        for path in [&fifo, &fixture.0] {
            assert!(read_bounded(path, 4096).is_err());
            assert!(image_architecture(path.to_str().unwrap()).is_empty());
        }
        let regular = fixture.0.join("regular");
        fs::write(&regular, b"metadata").unwrap();
        assert_eq!(read_bounded(&regular, 8).unwrap(), b"metadata");
        assert!(read_bounded(&regular, 7).is_err());
    }
    #[test]
    fn strict_proc_metadata() {
        let suffix = format!("R{} 12345 0\n", " 0".repeat(18));
        let stat = parse_stat(format!("42 (odd ) (name)) {suffix}").as_bytes()).unwrap();
        assert_eq!(
            (stat.pid, stat.name.as_str(), stat.ticks),
            (42, "odd ) (name)", 12345)
        );
        for bytes in [b"42 (x) R 0".as_slice(), b"0 (x) R 0", b"42 (x)\0 R 0"] {
            assert!(parse_stat(bytes).is_none());
        }
        for ticks in ["0", "-1", "18446744073709551616", "not-a-time"] {
            let malformed = format!("42 (race) R{} {ticks}\n", " 0".repeat(18));
            assert!(parse_stat(malformed.as_bytes()).is_none());
        }
        assert!(parse_stat(&vec![b' '; 65537]).is_none());
        assert_eq!(parse_environment(b"A=a=b\0EMPTY=\0").unwrap()["A"], "a=b");
        for bytes in [b"A=1\0A=2\0".as_slice(), b"A=x", b"bad\0", b"=x\0"] {
            assert!(parse_environment(bytes).is_none());
        }
    }
    #[test]
    fn loader_requires_unambiguous_wine_mapping() {
        assert!(mapped_wine("/opt/wine64", b"".as_slice()).is_empty());
        let maps =
            b"0-1 r-xp 0 00:01 1 /opt/wine/x86_64-unix/ntdll.so\n0-1 r-xp 0 00:01 2 /opt/wine64\n";
        assert_eq!(
            mapped_wine("/opt/wine64-preloader", maps.as_slice()),
            "/opt/wine64"
        );
        assert!(mapped_wine("/other/wine64", maps.as_slice()).is_empty());
        assert!(mapped_wine("/opt/wine64 (deleted)", maps.as_slice()).is_empty());
    }
    #[test]
    fn renamed_custom_loaders_and_literal_maps_paths() {
        for executable in [
            "/custom/renamed-runner",
            "/custom/wine space\\040\\011\\134",
        ] {
            let maps = format!(
                "0-1 r-xp 0 00:01 1 /custom/build/dlls/ntdll/ntdll.so\n0-1 r-xp 0 00:01 2 {executable}\n"
            );
            assert_eq!(mapped_wine(executable, maps.as_bytes()), executable);
        }
        for path in [
            "/custom/ntdll.so (deleted)",
            "/custom/ntdll.dll",
            "/custom/ambiguous\\012/ntdll.so",
        ] {
            let maps = format!("0-1 r-xp 0 00:01 1 {path}\n");
            assert!(mapped_wine("/custom/renamed", maps.as_bytes()).is_empty());
        }
        assert!(
            mapped_wine(
                "/custom/renamed",
                b"0-1 r--p 0 00:01 1 /custom/ntdll.so\n".as_slice()
            )
            .is_empty()
        );
    }
    #[test]
    fn streaming_maps_enforces_full_snapshot_and_memory_bounds() {
        struct Chunks<'a> {
            bytes: &'a [u8],
            size: usize,
            consumed: usize,
            fail: bool,
        }
        impl Read for Chunks<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.is_empty() && self.fail {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                let count = output.len().min(self.size).min(self.bytes.len());
                output[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes = &self.bytes[count..];
                self.consumed += count;
                Ok(count)
            }
        }
        let valid = b"0-1 r-xp 0 00:01 1 /custom/ntdll.so\n";
        for size in [1, 7, 31, MAX_MAPS_LINE] {
            let chunks = Chunks {
                bytes: valid,
                size,
                consumed: 0,
                fail: false,
            };
            assert_eq!(mapped_wine("/custom/renamed", chunks), "/custom/renamed");
        }
        let mut large = valid.to_vec();
        let ordinary = b"0-1 r--p 0 00:01 2 /ordinary/library.so\n";
        while large.len() + ordinary.len() <= MAX_MAPS_BYTES {
            large.extend_from_slice(ordinary);
        }
        large.resize(MAX_MAPS_BYTES, b'\n');
        assert_eq!(
            mapped_wine("/custom/renamed", large.as_slice()),
            "/custom/renamed"
        );
        large.push(b'\n');
        let mut chunks = Chunks {
            bytes: &large,
            size: 997,
            consumed: 0,
            fail: false,
        };
        assert!(mapped_wine("/custom/renamed", &mut chunks).is_empty());
        assert_eq!(chunks.consumed, MAX_MAPS_BYTES + 1);
        large.truncate(MAX_MAPS_LINE + 1);
        large.fill(b'x');
        let mut chunks = Chunks {
            bytes: &large,
            size: 997,
            consumed: 0,
            fail: false,
        };
        assert!(mapped_wine("/custom/renamed", &mut chunks).is_empty());
        assert_eq!(chunks.consumed, MAX_MAPS_LINE);
        assert!(mapped_wine("/custom/renamed", &valid[..valid.len() - 1]).is_empty());
        let chunks = Chunks {
            bytes: valid,
            size: 7,
            consumed: 0,
            fail: true,
        };
        assert!(mapped_wine("/custom/renamed", chunks).is_empty());
        let mut conflicting = valid.to_vec();
        conflicting.extend_from_slice(b"0-1 r-xp 0 00:01 2 /other/wine\n");
        assert!(mapped_wine("/custom/renamed", conflicting.as_slice()).is_empty());
    }
    #[test]
    fn process_lifetime_rejects_reused_missing_and_exited_pid() {
        use std::process::{Command, Stdio};
        let pid = std::process::id();
        let state = parse_stat(&read_bounded(format!("/proc/{pid}/stat"), 65536).unwrap()).unwrap();
        assert!(anchor_alive(pid, state.ticks).is_ok());
        assert!(anchor_alive(pid, state.ticks + 1).is_err());
        assert!(anchor_alive(0, state.ticks).is_err());
        assert!(anchor_alive(pid, 0).is_err());
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let exited = child.id();
        child.wait().unwrap();
        assert!(anchor_alive(exited, 1).is_err());
        assert!(wine(exited).is_empty());
    }
    #[test]
    fn environment_secrets_and_context() {
        let env = Environment::from([
            ("PASSWORD".into(), "secret".into()),
            ("LD_PRELOAD".into(), "evil".into()),
            ("PROTON_LOG".into(), "1".into()),
            ("HOME".into(), "/home/a".into()),
        ]);
        assert_eq!(permitted_environment(&env).len(), 1);
        assert_eq!(
            launch_context(&Environment::new()),
            launch_context(&Environment::from([
                ("TMPDIR".into(), "/tmp/../tmp//".into()),
                ("XDG_RUNTIME_DIR".into(), "relative".into())
            ]))
        );
    }
    #[test]
    fn random_wineserver_pointer_rejects_symlinks_modes_and_ambiguity() {
        let fixture = Fixture::new();
        let root = fixture.0.to_str().unwrap();
        let prefix = format!("{root}/prefix");
        fs::create_dir(&prefix).unwrap();
        let metadata = fs::metadata(&prefix).unwrap();
        let directory = format!("server-{:x}-{:x}", metadata.dev(), metadata.ino());
        let random = format!("{root}/wine-Ab12Cd");
        let server = format!("{random}/{directory}");
        fs::create_dir_all(&server).unwrap();
        fs::set_permissions(&random, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&server, fs::Permissions::from_mode(0o700)).unwrap();
        let _socket = UnixListener::bind(format!("{server}/socket")).unwrap();
        fs::set_permissions(
            format!("{server}/socket"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let pointer = format!("{prefix}/wineserver");
        fs::write(&pointer, b"wine-Ab12Cd").unwrap();
        fs::set_permissions(&pointer, fs::Permissions::from_mode(0o400)).unwrap();
        let mut env = Environment::from([("TMPDIR".into(), root.into())]);
        assert!(shared_wineserver(&prefix, &env, "", "", root).is_ok());
        fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(shared_wineserver(&prefix, &env, "", "", root).is_err());
        fs::set_permissions(&pointer, fs::Permissions::from_mode(0o400)).unwrap();
        let xdg = format!("{root}/xdg");
        let other = format!("{xdg}/wine/{directory}");
        fs::create_dir_all(&other).unwrap();
        let _other = UnixListener::bind(format!("{other}/socket")).unwrap();
        fs::set_permissions(format!("{other}/socket"), fs::Permissions::from_mode(0o600)).unwrap();
        env.insert("XDG_RUNTIME_DIR".into(), xdg);
        assert!(shared_wineserver(&prefix, &env, "", "", root).is_err());
        env.remove("XDG_RUNTIME_DIR");
        fs::rename(&pointer, format!("{prefix}/real")).unwrap();
        std::os::unix::fs::symlink("real", &pointer).unwrap();
        assert!(shared_wineserver(&prefix, &env, "", "", root).is_err());
    }
    #[test]
    fn exact_runtime_launcher_never_falls_back_from_bad_metadata() {
        let fixture = Fixture::new();
        let root = fixture.0.to_str().unwrap();
        fs::create_dir_all(format!("{root}/sniper.1/files")).unwrap();
        fs::write(format!("{root}/run"), "#!/bin/sh\ndir='sniper.1'\n").unwrap();
        fs::set_permissions(format!("{root}/run"), fs::Permissions::from_mode(0o700)).unwrap();
        let mut env = Environment::from([
            ("PRESSURE_VESSEL_RUNTIME".into(), "sniper.1".into()),
            ("STEAM_COMPAT_TOOL_PATHS".into(), root.into()),
        ]);
        assert_eq!(steam_runtime_for(&env), format!("{root}/run"));
        env.insert(
            "PRESSURE_VESSEL_RUNTIME_BASE".into(),
            format!("{root}/missing"),
        );
        assert!(steam_runtime_for(&env).is_empty());
        env.remove("PRESSURE_VESSEL_RUNTIME_BASE");
        fs::write(format!("{root}/run"), "dir=sniper.1\ndir=sniper.1\n").unwrap();
        assert!(steam_runtime_for(&env).is_empty());
    }
}
