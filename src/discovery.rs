use crate::runtime::{self as rt, Environment};
use crate::steam;
use crate::types::{OperationResult, Process, RouteProbe, Runtime};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

fn infrastructure(name: &str) -> bool {
    [
        "services.exe",
        "winedevice.exe",
        "plugplay.exe",
        "rpcss.exe",
        "explorer.exe",
        "wineboot.exe",
        "start.exe",
        "conhost.exe",
        "svchost.exe",
        "steam.exe",
        "steamwebhelper.exe",
        "tabtip.exe",
        "xalia.exe",
        "proton_needle_helper_x64.exe",
    ]
    .iter()
    .any(|item| name.eq_ignore_ascii_case(item))
}
pub(crate) fn complete_identity(process: &Process) -> bool {
    process.windows_pid != 0
        && !process.name.is_empty()
        && !process.name.contains('\0')
        && !process.image_path.is_empty()
        && !process.image_path.contains('\0')
        && process.creation_time.len() <= 20
        && !process.creation_time.starts_with('0')
        && process.creation_time.bytes().all(|c| c.is_ascii_digit())
        && process
            .creation_time
            .parse::<u64>()
            .is_ok_and(|time| time != 0)
        && matches!(process.architecture.as_str(), "x64" | "x86")
}
pub(crate) fn parse_process_snapshot(
    value: &Value,
    runtime: &Runtime,
    steam_id: &str,
) -> Result<Vec<Process>, String> {
    let malformed =
        || "The helper returned malformed or beyond-limit process identities".to_string();
    let entries = value.as_array().ok_or_else(malformed)?;
    if entries.len() > 16384 {
        return Err(malformed());
    }
    let mut ids = HashSet::with_capacity(entries.len());
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or_else(malformed)?;
        let pid = object
            .get("windows_pid")
            .and_then(Value::as_u64)
            .filter(|pid| *pid != 0 && *pid <= u32::MAX as u64)
            .ok_or_else(malformed)? as u32;
        if !ids.insert(pid) {
            return Err(malformed());
        }
        let string = |key| {
            object
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(malformed)
        };
        let (name, image_path, creation_time, architecture) = (
            string("name")?,
            string("image_path")?,
            string("creation_time")?,
            string("architecture")?,
        );
        if name.len() > 32768
            || image_path.len() > 32768
            || creation_time.len() > 64
            || architecture.len() > 32
            || [name, image_path, creation_time, architecture]
                .iter()
                .any(|value| value.contains('\0'))
        {
            return Err(malformed());
        }
        if infrastructure(name) {
            continue;
        }
        let mut process = Process {
            windows_pid: pid,
            name: name.into(),
            image_path: image_path.into(),
            creation_time: creation_time.into(),
            architecture: architecture.into(),
            steam_app_id: steam_id.into(),
            runtime: runtime.clone(),
            detection: "Windows identity verified by helper in the exact active Wine session"
                .into(),
            ..Process::default()
        };
        process.injectable = architecture == "x64" && complete_identity(&process);
        result.push(process);
    }
    Ok(result)
}
fn group_key(runtime: &Runtime, route: &str) -> String {
    let session = runtime.session_identity();
    if runtime.prefix.is_empty() {
        format!(
            "{:?}",
            (session, route, runtime.anchor_pid, runtime.start_ticks)
        )
    } else {
        format!("{:?}", (session, route))
    }
}
fn image_file(image: &str, prefix: &str, root: &str, cwd: &str) -> String {
    let bytes = image.as_bytes();
    let path = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        if prefix.is_empty() {
            return String::new();
        }
        let device = format!(
            "{prefix}/dosdevices/{}:",
            (bytes[0] as char).to_ascii_lowercase()
        );
        let drive = rt::link(format!("{root}{device}"));
        let drive = if drive.is_empty() {
            format!("{root}{device}")
        } else if drive.starts_with('/') {
            format!("{root}{}", rt::clean(&drive))
        } else {
            format!(
                "{root}{}",
                rt::clean(&format!("{prefix}/dosdevices/{drive}"))
            )
        };
        let relative = image[3..].replace('\\', "/");
        let mut normalized = PathBuf::new();
        for component in Path::new(&relative).components() {
            match component {
                Component::ParentDir => {
                    if !normalized.pop() {
                        return String::new();
                    }
                }
                Component::Normal(v) => normalized.push(v),
                Component::CurDir => {}
                _ => return String::new(),
            }
        }
        Path::new(&drive)
            .join(normalized)
            .to_string_lossy()
            .into_owned()
    } else if image.starts_with('/') {
        format!("{root}{}", rt::clean(image))
    } else if !cwd.is_empty() && !image.contains(['\\', ':']) {
        format!("{root}{}", rt::clean(&format!("{cwd}/{image}")))
    } else {
        return String::new();
    };
    if rt::image_architecture(&path).is_empty() {
        String::new()
    } else {
        path
    }
}
fn host_process(runtime: &Runtime, state: &rt::ProcStat, cmdline: &[u8]) -> Process {
    let first = cmdline.split(|v| *v == 0).next().unwrap_or_default();
    let image = std::str::from_utf8(first)
        .ok()
        .filter(|v| v.to_ascii_lowercase().ends_with(".exe") && !v.contains(['\n', '\r']))
        .unwrap_or("");
    let name = if image.is_empty() {
        state.name.clone()
    } else {
        image.rsplit(['\\', '/']).next().unwrap_or(image).into()
    };
    let mut runtime = runtime.clone();
    if runtime.wine_binary.is_empty() {
        runtime.supported = false;
        runtime.strategy = "none".into();
        runtime.error_code = "wine_not_identified".into();
    }
    let host_image = image_file(
        image,
        &runtime.prefix,
        &format!("/proc/{}/root", state.pid),
        &runtime.working_directory,
    );
    Process {
        linux_pid: state.pid,
        host_start_ticks: state.ticks,
        name,
        image_path: image.into(),
        architecture: rt::image_architecture(&host_image),
        steam_app_id: steam::app_id(&runtime.environment),
        detection: if runtime.wine_binary.is_empty() {
            "Windows-like host process observed. Wine runtime and Windows identity unavailable"
                .into()
        } else {
            "Wine host process observed. Windows identity unavailable".into()
        },
        runtime,
        ..Process::default()
    }
}
fn diagnostic(runtime: &Runtime) -> Process {
    Process {
        name: if runtime.proton_path.is_empty() {
            "Wine runtime".into()
        } else {
            "Proton runtime".into()
        },
        runtime: runtime.clone(),
        steam_app_id: steam::app_id(&runtime.environment),
        detection: runtime.error.clone(),
        ..Process::default()
    }
}
fn metadata_probes(runtime: &Runtime) -> Vec<RouteProbe> {
    let direct = if !rt::executable(&runtime.wine_binary) {
        Err("The exact active Wine loader is unavailable".into())
    } else if !Path::new(&runtime.prefix).is_dir() {
        Err("The selected Wine prefix is unavailable".into())
    } else {
        Ok(())
    };
    let proton = if !rt::executable(&runtime.proton_path) {
        Err("The exact active Proton wrapper is unavailable".into())
    } else if runtime.prefix.is_empty()
        || rt::canonical(format!(
            "{}/pfx",
            rt::value(&runtime.environment, "STEAM_COMPAT_DATA_PATH")
        )) != runtime.prefix
    {
        Err("Proton compatibility data does not identify the active prefix".into())
    } else if (!rt::value(&runtime.environment, "PRESSURE_VESSEL_RUNTIME_BASE").is_empty()
        || !rt::value(&runtime.environment, "PRESSURE_VESSEL_RUNTIME").is_empty())
        && (runtime.launcher_path.is_empty()
            || rt::steam_runtime_for(&runtime.environment) != runtime.launcher_path)
    {
        Err("Declared Steam Runtime metadata does not identify its exact installed launcher".into())
    } else {
        Ok(())
    };
    let app = if !rt::executable(&runtime.proton_path) {
        Err("Per-app entry requires the active Proton wrapper".into())
    } else if steam::app_selector(&runtime.environment).is_empty() {
        Err("No authoritative per-app launcher selector is present".into())
    } else {
        steam::app_client(runtime).map(|_| ())
    };
    vec![
        rt::probe("direct_wine", direct),
        rt::probe("proton_runtime", proton),
        rt::probe("steam_broker", steam::broker_prerequisites(runtime)),
        rt::probe("app_launcher", app),
    ]
}
fn candidate_route(runtime: &mut Runtime, strategy: &str) -> Option<Runtime> {
    let index = runtime
        .route_probes
        .iter()
        .position(|probe| probe.strategy == strategy && probe.available)?;
    let mut candidate = runtime.clone();
    candidate.strategy = strategy.into();
    let result = match strategy {
        "direct_wine" => rt::validate_direct(&candidate),
        "proton_runtime" => rt::validate_proton(&candidate),
        _ => steam::select(&mut candidate),
    };
    let probe = rt::probe(strategy, result);
    candidate.supported = probe.available;
    runtime.route_probes[index] = probe;
    if !candidate.supported {
        return None;
    }
    candidate.error.clear();
    candidate.error_code.clear();
    Some(candidate)
}

fn append_wine_version(runtime: &mut Runtime, response: &Value) {
    if response["wine_detected"].as_bool() == Some(true)
        && let Some(wine) = response["wine_version"].as_str()
        && !wine.is_empty()
        && wine.len() <= 4096
        && !wine.contains('\0')
    {
        if !runtime.version.is_empty() {
            runtime.version.push_str(" / ");
        }
        runtime.version.push_str("Wine ");
        runtime.version.push_str(wine);
    }
}
fn runtime_metadata(
    pid: u32,
    state: &rt::ProcStat,
    wine: String,
    source: Option<&Environment>,
) -> Runtime {
    let empty = Environment::new();
    let environment = source.unwrap_or(&empty);
    let mut prefix = rt::selected_prefix(environment);
    if prefix.is_empty() {
        prefix = rt::declared_prefix(environment);
    }
    let proton_path = rt::proton_for_wine(&wine);
    let packaging = if Path::new(&format!("/proc/{pid}/root/.flatpak-info")).exists()
        || !rt::value(environment, "FLATPAK_ID").is_empty()
    {
        "flatpak"
    } else if steam::is_steam_snap(pid, environment) {
        "steam_snap"
    } else if wine.is_empty() || source.is_none() {
        "unknown"
    } else if !proton_path.is_empty() {
        "native_proton"
    } else if environment.iter().any(|(key, v)| {
        !v.is_empty()
            && (matches!(
                key.as_str(),
                "SteamAppId" | "SteamGameId" | "STEAM_RUNTIME" | "PROTONPATH"
            ) || key.starts_with("STEAM_COMPAT_")
                || key.starts_with("PRESSURE_VESSEL_")
                || (key.starts_with("PROTON_") && !key.starts_with("PROTON_NEEDLE_")))
    }) {
        "unknown"
    } else {
        "standard_wine"
    };
    let mut permitted = rt::permitted_environment(environment);
    if !prefix.is_empty() {
        permitted.insert("WINEPREFIX".into(), prefix.clone());
    }
    let mut runtime = Runtime {
        packaging: packaging.into(),
        prefix,
        proton_path,
        wine_binary: wine,
        working_directory: rt::link(format!("/proc/{pid}/cwd")),
        environment: permitted,
        anchor_pid: pid,
        start_ticks: state.ticks,
        namespace_key: rt::namespace_key(pid),
        launch_context_key: rt::launch_context(environment),
        strategy: "none".into(),
        error_code: "not_probed".into(),
        error: "Host metadata only. No helper or runtime service was probed".into(),
        ..Runtime::default()
    };
    if !runtime.proton_path.is_empty() {
        runtime.launcher_path = rt::steam_runtime_for(environment);
        if let Some(root) = Path::new(&runtime.proton_path).parent() {
            runtime.version = rt::read_bounded(root.join("version"), 4096)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default()
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(256)
                .collect();
            if runtime.version.is_empty() {
                runtime.version = root
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
            }
        }
    }
    runtime.route_probes = metadata_probes(&runtime);
    if source.is_none() || runtime.wine_binary.is_empty() {
        runtime.error_code = if runtime.wine_binary.is_empty() {
            "wine_not_identified".into()
        } else {
            "process_metadata_unavailable".into()
        };
        runtime.error = "The active Wine loader and launch environment must be readable".into();
        for probe in &mut runtime.route_probes {
            probe.available = false;
            probe.code = runtime.error_code.clone();
            probe.message = runtime.error.clone();
        }
    }
    runtime
}
fn collect(active: bool, cancelled: &AtomicBool, progress: impl Fn(&str)) -> Vec<Process> {
    progress("Inspecting host Wine and Proton metadata");
    let Ok(entries) = fs::read_dir("/proc") else {
        progress("Host process metadata is unavailable");
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .filter_map(Result::ok)
        .filter_map(|v| v.file_name().to_str()?.parse().ok())
        .filter(|pid| *pid != 0)
        .collect();
    pids.sort_unstable();
    collect_pids(
        &pids,
        active,
        cancelled,
        crate::helper::run_helper,
        progress,
    )
}
// The explicit PID set is also used by fixture tests; production always scans /proc.
fn collect_pids(
    pids: &[u32],
    active: bool,
    cancelled: &AtomicBool,
    run: impl Fn(&Runtime, Value, u64) -> OperationResult,
    progress: impl Fn(&str),
) -> Vec<Process> {
    let mut output = Vec::new();
    let mut enumerated = HashSet::new();
    let mut diagnostics = HashSet::new();
    let mut hosts = HashSet::new();
    let mut failed_routes: HashMap<String, OperationResult> = HashMap::new();
    let mut reported_routes = HashSet::new();
    let owner = rt::uid();
    for &pid in pids {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let base = format!("/proc/{pid}");
        if !fs::metadata(&base).is_ok_and(|m| m.uid() == owner) {
            continue;
        }
        let Some(state) = rt::read_bounded(format!("{base}/stat"), 65536)
            .ok()
            .and_then(|v| rt::parse_stat(&v))
            .filter(|state| state.pid == pid)
        else {
            continue;
        };
        let wine = rt::wine(pid);
        let cmdline = rt::read_bounded(format!("{base}/cmdline"), 65536).unwrap_or_default();
        let first = std::str::from_utf8(cmdline.split(|v| *v == 0).next().unwrap_or_default())
            .unwrap_or("");
        if wine.is_empty()
            && !state.name.to_ascii_lowercase().ends_with(".exe")
            && !first.to_ascii_lowercase().ends_with(".exe")
        {
            continue;
        }
        let environment = rt::environment(pid).ok();
        let mut runtime = runtime_metadata(pid, &state, wine, environment.as_ref());
        // /proc files are separate snapshots. Never attach metadata from a
        // replacement PID to the lifetime observed at the start of this scan.
        if rt::anchor_alive(pid, state.ticks).is_err() {
            continue;
        }
        let group = group_key(&runtime, "");
        if enumerated.contains(&group) {
            continue;
        }
        if active && environment.is_some() && !runtime.wine_binary.is_empty() {
            let mut attempted = false;
            for strategy in [
                "direct_wine",
                "app_launcher",
                "proton_runtime",
                "steam_broker",
            ] {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let report_route = runtime
                    .route_probes
                    .iter()
                    .any(|probe| probe.strategy == strategy && probe.available)
                    && reported_routes.insert(group_key(&runtime, strategy));
                if report_route {
                    progress(&format!(
                        "Checking {strategy} route for Wine session anchored at Linux PID {pid}"
                    ));
                }
                let Some(mut candidate) = candidate_route(&mut runtime, strategy) else {
                    if report_route {
                        progress(&format!(
                            "{strategy} route unavailable for this Wine session"
                        ));
                    }
                    continue;
                };
                attempted = true;
                candidate.route_probes = runtime.route_probes.clone();
                if !Path::new(&candidate.working_directory).is_dir() {
                    candidate.working_directory = candidate.prefix.clone();
                }
                let route_key = group_key(
                    &candidate,
                    &format!("{:?}", (&candidate.strategy, &candidate.service_owner)),
                );
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let result = if let Some(result) = failed_routes.get(&route_key) {
                    result.clone()
                } else {
                    if report_route {
                        progress(&format!(
                            "Helper checking Windows identities through {strategy}"
                        ));
                    }
                    run(&candidate, json!({"operation":"list_processes"}), 15000)
                };
                let snapshot = if result.success {
                    parse_process_snapshot(
                        &result.response["processes"],
                        &candidate,
                        &steam::app_id(&candidate.environment),
                    )
                } else {
                    Err(result.message.clone())
                };
                let visible = snapshot
                    .as_ref()
                    .is_ok_and(|rows| rows.iter().any(complete_identity));
                if visible {
                    if report_route {
                        progress(&format!(
                            "Helper verified application Windows identities through {strategy}"
                        ));
                    }
                    candidate.supported = true;
                    candidate.error.clear();
                    candidate.error_code.clear();
                    append_wine_version(&mut candidate, &result.response);
                    for probe in &mut candidate.route_probes {
                        if probe.strategy == candidate.strategy {
                            probe.code.clear();
                            probe.message = "Running Wine session and application Windows identity verified by helper".into();
                        }
                    }
                    for mut process in snapshot.unwrap() {
                        process.runtime = candidate.clone();
                        output.push(process);
                    }
                    enumerated.insert(group.clone());
                    runtime = candidate;
                    break;
                }
                candidate.supported = false;
                candidate.error_code = if !result.success {
                    result.error_code.clone()
                } else if snapshot.is_err() {
                    "helper_protocol".into()
                } else {
                    "windows_target_not_visible".into()
                };
                candidate.error = if result.success && snapshot.is_ok() {
                    "The helper reached this Wine session but returned no complete application Windows identity".into()
                } else {
                    snapshot.err().unwrap_or_default()
                };
                if report_route {
                    progress(&format!(
                        "{strategy} did not verify a complete application Windows identity"
                    ));
                }
                if !result.success && result.error_code != "runtime_identity" {
                    failed_routes.insert(route_key, result);
                }
                for probe in &mut candidate.route_probes {
                    if probe.strategy == candidate.strategy {
                        probe.code = candidate.error_code.clone();
                        probe.message = candidate.error.clone();
                    }
                }
                runtime = candidate;
            }
            if !attempted && !cancelled.load(Ordering::Relaxed) {
                runtime.error_code = "runtime_access_unavailable".into();
                runtime.error = "No candidate route authenticated the running Wine session".into();
            }
        }
        if enumerated.contains(&group) {
            continue;
        }
        let process = host_process(&runtime, &state, &cmdline);
        if !process.name.is_empty() && !infrastructure(&process.name) {
            output.push(process);
            hosts.insert(group);
        } else if diagnostics.insert(group) {
            output.push(diagnostic(&runtime));
        }
    }
    output.retain(|process| {
        if process.windows_pid != 0 {
            return true;
        }
        let group = group_key(&process.runtime, "");
        !enumerated.contains(&group) && (process.linux_pid != 0 || !hosts.contains(&group))
    });
    if cancelled.load(Ordering::Relaxed) {
        progress("Discovery cancelled");
    } else if active {
        let verified = output
            .iter()
            .filter(|process| complete_identity(process))
            .count();
        progress(&format!(
            "Discovery complete: {verified} verified Windows identities, {} unverified observations",
            output.len() - verified
        ));
    } else {
        progress(&format!(
            "Host inspection complete: {} observations. Windows identities not verified",
            output.len()
        ));
    }
    output
}
/// Inspect host metadata only: never connect to runtime services or launch a helper.
pub fn inspect_processes() -> Vec<Process> {
    inspect_processes_cancelled(&AtomicBool::new(false), |_| {})
}
pub fn inspect_processes_cancelled(
    cancelled: &AtomicBool,
    progress: impl Fn(&str),
) -> Vec<Process> {
    collect(false, cancelled, progress)
}
/// Enumerate authenticated existing Wine sessions, retaining blocked host observations.
pub fn discover_processes_cancelled(
    cancelled: &AtomicBool,
    progress: impl Fn(&str),
) -> Vec<Process> {
    collect(true, cancelled, progress)
}

/// Test harness entry: never enumerate or prepare an ambient /proc candidate.
#[cfg(test)]
pub(crate) fn discover_registered_fixture(anchor_pid: u32) -> Vec<Process> {
    collect_pids(
        &[anchor_pid],
        true,
        &AtomicBool::new(false),
        crate::helper::run_helper,
        |_| {},
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_rejects_duplicate_fractional_and_incomplete_identity() {
        let runtime = Runtime::default();
        let target = json!({"windows_pid":42,"name":"Game.exe","image_path":"C:\\Games\\Game.exe","creation_time":"123456789","architecture":"x64"});
        let parsed = parse_process_snapshot(&json!([target.clone()]), &runtime, "42").unwrap();
        assert_eq!(parsed[0].linux_pid, 0);
        assert!(parsed[0].injectable);
        assert!(
            parse_process_snapshot(&json!([target.clone(), target.clone()]), &runtime, "").is_err()
        );
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(42.0),
            json!(4294967296u64),
            json!("42"),
        ] {
            let mut t = target.clone();
            t["windows_pid"] = bad;
            assert!(parse_process_snapshot(&json!([t]), &runtime, "").is_err());
        }
        let mut incomplete = target.clone();
        incomplete["creation_time"] = json!("");
        let parsed = parse_process_snapshot(&json!([incomplete]), &runtime, "").unwrap();
        assert!(!parsed[0].injectable);
        assert!(!complete_identity(&parsed[0]));
        for bad in ["0", "0123", "+123", "not-a-time", "18446744073709551616"] {
            let mut malformed = target.clone();
            malformed["creation_time"] = json!(bad);
            assert!(
                !parse_process_snapshot(&json!([malformed]), &runtime, "").unwrap()[0].injectable
            );
        }
        let mut infra = target;
        infra["name"] = json!("SERVICES.EXE");
        assert!(
            parse_process_snapshot(&json!([infra]), &runtime, "")
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn grouping_scopes_namespaces_context_and_unknown_prefixes() {
        let first = Runtime {
            prefix: "/pfx".into(),
            wine_binary: "/wine".into(),
            namespace_key: "mnt1".into(),
            launch_context_key: "tmp1".into(),
            anchor_pid: 1,
            start_ticks: 2,
            ..Runtime::default()
        };
        let mut second = first.clone();
        second.anchor_pid = 3;
        second.start_ticks = 4;
        assert_eq!(group_key(&first, ""), group_key(&second, ""));
        second.launch_context_key = "tmp2".into();
        assert_ne!(group_key(&first, ""), group_key(&second, ""));
        second = first.clone();
        second.namespace_key = "mnt2".into();
        assert_ne!(group_key(&first, ""), group_key(&second, ""));
        let mut first = first;
        first.prefix.clear();
        second = first.clone();
        second.anchor_pid += 1;
        assert_ne!(group_key(&first, ""), group_key(&second, ""));
    }
    #[test]
    fn blocked_host_observations_keep_linux_lifetime() {
        let state = rt::ProcStat {
            pid: 42,
            name: "Game.exe".into(),
            ticks: 123,
        };
        let runtime = Runtime {
            anchor_pid: 42,
            start_ticks: 123,
            ..Runtime::default()
        };
        let row = host_process(&runtime, &state, b"C:\\Games\\Game.exe\0");
        assert_eq!(row.linux_pid, 42);
        assert_eq!(row.host_start_ticks, 123);
        assert_eq!(row.windows_pid, 0);
        assert!(!row.injectable);
        assert!(!row.runtime.supported);
        assert_eq!(row.name, "Game.exe");
        assert_eq!(
            row.identity(),
            host_process(&runtime, &state, b"").identity()
        );
    }
    #[test]
    fn incomplete_metadata_never_labels_standalone_wine() {
        let state = rt::ProcStat {
            pid: std::process::id(),
            name: "Game.exe".into(),
            ticks: 1,
        };
        assert_eq!(
            runtime_metadata(state.pid, &state, "/missing/wine".into(), None).packaging,
            "unknown"
        );
        let environment =
            Environment::from([("STEAM_COMPAT_DATA_PATH".into(), "/missing/data".into())]);
        assert_eq!(
            runtime_metadata(
                state.pid,
                &state,
                "/missing/wine".into(),
                Some(&environment)
            )
            .packaging,
            "unknown"
        );
    }
    #[test]
    fn host_image_resolution_rejects_drive_escape_and_uses_process_root() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "needle-image-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let _fixture = Fixture(root.clone());
        fs::create_dir_all(root.join("prefix/dosdevices")).unwrap();
        fs::create_dir(root.join("drive")).unwrap();
        symlink("/drive", root.join("prefix/dosdevices/c:")).unwrap();
        let mut pe = vec![0u8; 512];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        pe[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[70..72].copy_from_slice(&1u16.to_le_bytes());
        pe[84..86].copy_from_slice(&112u16.to_le_bytes());
        pe[86..88].copy_from_slice(&2u16.to_le_bytes());
        pe[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[144..148].copy_from_slice(&4096u32.to_le_bytes());
        pe[148..152].copy_from_slice(&512u32.to_le_bytes());
        fs::write(root.join("drive/Game.exe"), &pe).unwrap();
        let expected = root.join("drive/Game.exe").to_string_lossy().into_owned();
        assert_eq!(
            image_file("C:\\Game.exe", "/prefix", root.to_str().unwrap(), ""),
            expected
        );
        assert_eq!(
            image_file("Game.exe", "", root.to_str().unwrap(), "/drive"),
            expected
        );
        assert!(
            image_file(
                "C:\\..\\drive\\Game.exe",
                "/prefix",
                root.to_str().unwrap(),
                ""
            )
            .is_empty()
        );
        assert!(
            image_file(
                "C:\\..\\..\\drive\\Game.exe",
                "/prefix",
                root.to_str().unwrap(),
                ""
            )
            .is_empty()
        );
        pe[86..88].copy_from_slice(&0x2002u16.to_le_bytes());
        fs::write(root.join("drive/Game.exe"), pe).unwrap();
        assert!(image_file("C:\\Game.exe", "/prefix", root.to_str().unwrap(), "").is_empty());
    }
    #[test]
    fn fixture_scan_with_no_runtime_cannot_launch() {
        let rows = collect_pids(
            &[std::process::id()],
            true,
            &AtomicBool::new(false),
            |_, _, _| panic!("No fixture Wine target exists. Helper must not launch"),
            |_| {},
        );
        assert!(rows.is_empty());
    }
    #[test]
    fn cancelled_discovery_cannot_start_helpers() {
        let cancelled = AtomicBool::new(true);
        for active in [false, true] {
            let rows = collect_pids(
                &[std::process::id(), u32::MAX],
                active,
                &cancelled,
                |_, _, _| panic!("Cancelled discovery must not launch a helper"),
                |_| {},
            );
            assert!(rows.is_empty());
        }
    }
    #[test]
    fn empty_fixture_progress_distinguishes_host_inspection_and_discovery() {
        use std::cell::RefCell;
        for (active, expected) in [
            (
                false,
                "Host inspection complete: 0 observations. Windows identities not verified",
            ),
            (
                true,
                "Discovery complete: 0 verified Windows identities, 0 unverified observations",
            ),
        ] {
            let progress = RefCell::new(Vec::new());
            let rows = collect_pids(
                &[],
                active,
                &AtomicBool::new(false),
                |_, _, _| panic!("An empty fixture must not launch a helper"),
                |text| progress.borrow_mut().push(text.to_owned()),
            );
            assert!(rows.is_empty());
            assert_eq!(&*progress.borrow(), &[expected]);
        }
        let progress = RefCell::new(Vec::new());
        let rows = collect_pids(
            &[std::process::id()],
            true,
            &AtomicBool::new(true),
            |_, _, _| panic!("Cancelled discovery must not launch a helper"),
            |text| progress.borrow_mut().push(text.to_owned()),
        );
        assert!(rows.is_empty());
        assert_eq!(&*progress.borrow(), &["Discovery cancelled"]);
    }
    #[test]
    fn enumeration_version_is_optional_bounded_and_does_not_erase_proton() {
        let mut runtime = Runtime {
            version: "Proton custom".into(),
            ..Runtime::default()
        };
        for invalid in [
            json!({}),
            json!({"wine_detected":false,"wine_version":"11.0"}),
            json!({"wine_detected":true,"wine_version":42}),
            json!({"wine_detected":true,"wine_version":""}),
            json!({"wine_detected":true,"wine_version":"bad\0version"}),
            json!({"wine_detected":true,"wine_version":"v".repeat(4097)}),
        ] {
            append_wine_version(&mut runtime, &invalid);
            assert_eq!(runtime.version, "Proton custom");
        }
        append_wine_version(
            &mut runtime,
            &json!({"wine_detected":true,"wine_version":"11.0"}),
        );
        assert_eq!(runtime.version, "Proton custom / Wine 11.0");
    }
}
