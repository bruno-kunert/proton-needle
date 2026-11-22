use crate::runtime::{self as rt, Environment};
use crate::types::Runtime;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use zbus::blocking::{Connection, Proxy};

const ALONGSIDE: &str = "com.steampowered.PressureVessel.LaunchAlongsideSteam";
const HINT: &str = "SRT_LAUNCHER_SERVICE_ALONGSIDE_STEAM";
const BUS_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn app_id(environment: &Environment) -> String {
    let value = environment
        .get("STEAM_COMPAT_APP_ID")
        .or_else(|| environment.get("SteamAppId"))
        .or_else(|| environment.get("SteamGameId"))
        .map(String::as_str)
        .unwrap_or("");
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|c| c.is_ascii_digit()) {
        return String::new();
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|v| *v != 0)
        .map(|v| v.to_string())
        .unwrap_or_default()
}
pub(crate) fn app_selector(environment: &Environment) -> String {
    // Match the launcher's documented authority order, without normalizing a
    // selector into a different bus name (App001 is not App1).
    let selected = environment
        .get("STEAM_COMPAT_APP_ID")
        .or_else(|| environment.get("SteamAppId"))
        .map(String::as_str)
        .unwrap_or("");
    if selected != "0" {
        return if app_bus(selected).is_ok() {
            selected.into()
        } else {
            String::new()
        };
    }
    if environment.contains_key("SteamAppId") {
        return String::new();
    }
    let game = rt::value(environment, "SteamGameId");
    if game
        .parse::<u64>()
        .is_ok_and(|v| v != 0 && v.to_string() == game)
    {
        "0".into()
    } else {
        String::new()
    }
}
fn app_bus(selector: &str) -> Result<String, String> {
    if !selector.is_empty()
        && selector.len() <= 10
        && selector.bytes().all(|c| c.is_ascii_digit())
        && selector
            .parse::<u32>()
            .is_ok_and(|v| v.to_string() == selector)
    {
        Ok(format!("com.steampowered.App{selector}"))
    } else {
        Err("No authoritative per-app launcher selector is present".into())
    }
}
pub(crate) fn broker_name_valid(name: &str) -> bool {
    if name == ALONGSIDE {
        return true;
    }
    let Some(suffix) = name
        .strip_prefix(ALONGSIDE)
        .and_then(|s| s.strip_prefix(".Instance"))
    else {
        return false;
    };
    name.len() <= 255
        && !suffix.starts_with('0')
        && !suffix.is_empty()
        && suffix.bytes().all(|c| c.is_ascii_digit())
        && suffix.parse::<u64>().is_ok_and(|v| v != 0)
}
fn profile(pid: u32) -> String {
    rt::read_bounded(format!("/proc/{pid}/attr/current"), 4096)
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_default()
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .into()
}
pub(crate) fn is_steam_snap(pid: u32, environment: &Environment) -> bool {
    let p = profile(pid);
    p == "snap.steam.steam"
        || (rt::value(environment, "SNAP_NAME") == "steam"
            && p.starts_with("snap.steam_")
            && p.ends_with(".steam"))
}
fn session_bus() -> Result<Connection, String> {
    // Never autolaunch a session bus.
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .map_err(|_| "The user's existing session bus address is unavailable")?;
    connect(&address)
}
fn connect(address: &str) -> Result<Connection, String> {
    connect_with_timeout(address, BUS_TIMEOUT)
}
fn connect_with_timeout(address: &str, timeout: Duration) -> Result<Connection, String> {
    use std::borrow::Cow;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::net::UnixStream;
    use zbus::address::{Address, Transport, transport::UnixSocket};
    let address = Address::try_from(address).map_err(|error| error.to_string())?;
    let Transport::Unix(transport) = address.transport() else {
        return Err(
            "Only an existing Unix session bus is accepted. Autolaunch is forbidden".into(),
        );
    };
    let path = match transport.path() {
        UnixSocket::File(path) => Cow::Borrowed(path.as_path()),
        UnixSocket::Abstract(name) => {
            let mut bytes = Vec::with_capacity(name.len() + 1);
            bytes.push(0);
            bytes.extend_from_slice(name.as_encoded_bytes());
            Cow::Owned(std::path::PathBuf::from(std::ffi::OsString::from_vec(
                bytes,
            )))
        }
        _ => return Err("A connectable existing Unix session bus address is required".into()),
    };
    // zbus's method timeout excludes connection/authentication, and its address
    // builder delegates connect to a blocking thread. Preconnect nonblocking so
    // timing out drops the socket even when a listener's backlog is full.
    async_io::block_on(async {
        let build = async {
            let stream = async_io::Async::<UnixStream>::connect(path.as_ref())
                .await
                .and_then(async_io::Async::into_inner)
                .map_err(|error| error.to_string())?;
            let connection = zbus::connection::Builder::async_io_unix_stream(stream)
                .method_timeout(BUS_TIMEOUT)
                .build()
                .await
                .map_err(|error| error.to_string())?;
            if address.guid().is_some_and(|expected| {
                expected.as_str() != connection.server_guid().inner().as_str()
            }) {
                return Err("The existing session bus GUID does not match its address".into());
            }
            Ok(Connection::from(connection))
        };
        let mut connection = std::pin::pin!(build);
        let mut deadline = std::pin::pin!(async_io::Timer::after(timeout));
        std::future::poll_fn(|context| {
            if deadline.as_mut().poll(context).is_ready() {
                return std::task::Poll::Ready(Err(
                    "The existing session bus connection/authentication timed out".into(),
                ));
            }
            connection.as_mut().poll(context)
        })
        .await
    })
}
fn bus_proxy(connection: &Connection) -> Result<Proxy<'_>, String> {
    Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(|e| e.to_string())
}
#[derive(Clone, Debug)]
struct Identity {
    bus: String,
    owner: String,
    pid: u32,
    ticks: u64,
    executable: String,
    client: String,
}
fn owner(proxy: &Proxy<'_>, name: &str) -> Result<String, String> {
    let owner: String = proxy
        .call("GetNameOwner", &(name,))
        .map_err(|e| format!("Existing launcher service is unavailable: {e}"))?;
    if !owner.starts_with(':') {
        return Err("The advertised owner is not a unique bus name".into());
    }
    Ok(owner)
}
fn identity(proxy: &Proxy<'_>, bus: &str) -> Result<Identity, String> {
    let owner = owner(proxy, bus)?;
    let user: u32 = proxy
        .call("GetConnectionUnixUser", &(&owner,))
        .map_err(|e| e.to_string())?;
    let pid: u32 = proxy
        .call("GetConnectionUnixProcessID", &(&owner,))
        .map_err(|e| e.to_string())?;
    // Authenticate bus credentials before reading any service process metadata.
    if user != rt::uid() || pid == 0 || pid > i32::MAX as u32 {
        return Err("The service's user/process credentials cannot be verified".into());
    }
    let state = rt::parse_stat(&rt::read_bounded(format!("/proc/{pid}/stat"), 65536)?)
        .ok_or("Invalid service process start identity")?;
    if state.pid != pid {
        return Err("Service process identity changed".into());
    }
    rt::anchor_alive(pid, state.ticks)?;
    Ok(Identity {
        bus: bus.into(),
        owner,
        pid,
        ticks: state.ticks,
        executable: rt::link(format!("/proc/{pid}/exe")),
        client: String::new(),
    })
}
fn still_owned(proxy: &Proxy<'_>, identity: &Identity, runtime: &Runtime) -> Result<(), String> {
    if owner(proxy, &identity.bus)? != identity.owner {
        return Err("Service owner changed during inspection".into());
    }
    rt::anchor_alive(identity.pid, identity.ticks)?;
    rt::anchor_alive(runtime.anchor_pid, runtime.start_ticks)
}
pub(crate) fn app_client(runtime: &Runtime) -> Result<String, String> {
    if runtime.launcher_path.is_empty() {
        return Err("The selected official runtime is unavailable".into());
    }
    let root = Path::new(&runtime.launcher_path)
        .parent()
        .ok_or("Invalid runtime launcher")?;
    let client = rt::canonical(root.join("pressure-vessel/bin/steam-runtime-launch-client"));
    if !rt::executable(&client) {
        return Err("The selected runtime's official launch client is unavailable".into());
    }
    Ok(client)
}
pub(crate) fn app_arguments(runtime: &Runtime) -> Vec<String> {
    let mut args = vec![
        format!("--bus-name={}", runtime.service_owner),
        format!("--directory={}", runtime.working_directory),
    ];
    for key in rt::UNSET_KEYS {
        args.push(format!("--unset-env={key}"));
    }
    args.extend([
        "--".into(),
        runtime.proton_path.clone(),
        "runinprefix".into(),
    ]);
    args
}
fn inspect_app(runtime: &Runtime, proxy: &Proxy<'_>) -> Result<Identity, String> {
    let selector = app_selector(&runtime.environment);
    let bus = app_bus(&selector)?;
    let mut identity = identity(proxy, &bus)?;
    identity.client = app_client(runtime)?;
    let installed = rt::canonical(
        Path::new(&runtime.launcher_path)
            .parent()
            .ok_or("Invalid runtime launcher")?
            .join("pressure-vessel/bin/steam-runtime-launcher-service"),
    );
    let service_base = format!("/proc/{}", identity.pid);
    let anchor_base = format!("/proc/{}", runtime.anchor_pid);
    if installed.is_empty() || !rt::same_file(format!("{service_base}/exe"), &installed) {
        return Err(
            "The advertised service is not the installed service for this Steam Runtime".into(),
        );
    }
    identity.executable = installed;
    rt::anchor_alive(runtime.anchor_pid, runtime.start_ticks)?;
    if runtime.proton_path.is_empty()
        || runtime.wine_binary.is_empty()
        || rt::wine(runtime.anchor_pid) != runtime.wine_binary
        || rt::proton_for_wine(&runtime.wine_binary) != runtime.proton_path
    {
        return Err("The selected game's exact Wine/Proton identity changed".into());
    }
    for path in [&runtime.proton_path, &runtime.wine_binary] {
        if !rt::same_file(format!("{service_base}/root{path}"), path)
            || !rt::same_file(format!("{anchor_base}/root{path}"), path)
        {
            return Err(
                "The service cannot launch the selected game's exact Proton objects".into(),
            );
        }
    }
    for name in ["mnt", "user", "pid"] {
        let namespace = rt::link(format!("{service_base}/ns/{name}"));
        if namespace.is_empty() || namespace != rt::link(format!("{anchor_base}/ns/{name}")) {
            return Err("The per-app service is not in the selected game's namespaces".into());
        }
    }
    let service_environment = rt::environment(identity.pid)?;
    let anchor_environment = rt::environment(runtime.anchor_pid)?;
    if app_selector(&service_environment) != selector
        || app_selector(&anchor_environment) != selector
        || (selector == "0"
            && (rt::value(&service_environment, "SteamGameId")
                != rt::value(&anchor_environment, "SteamGameId")
                || rt::value(&anchor_environment, "SteamGameId")
                    != rt::value(&runtime.environment, "SteamGameId")))
    {
        return Err(
            "The service and selected game do not share the authoritative AppID/GameID".into(),
        );
    }
    for (base, environment) in [
        (&service_base, &service_environment),
        (&anchor_base, &anchor_environment),
    ] {
        let prefix = rt::value(environment, "WINEPREFIX");
        let compat = rt::value(environment, "STEAM_COMPAT_DATA_PATH");
        if runtime.prefix.is_empty()
            || !prefix.starts_with('/')
            || !compat.starts_with('/')
            || !rt::same_file(format!("{base}/root{prefix}"), &runtime.prefix)
            || !rt::same_file(format!("{base}/root{compat}/pfx"), &runtime.prefix)
        {
            return Err("The service does not share the selected game's exact Wine prefix and compatibility data".into());
        }
    }
    if !rt::same_file(
        format!("{service_base}/root/tmp"),
        format!("{anchor_base}/root/tmp"),
    ) {
        return Err("Service and target temporary directory objects differ".into());
    }
    rt::shared_wineserver(
        &runtime.prefix,
        &anchor_environment,
        &format!("{anchor_base}/root"),
        &format!("{service_base}/root"),
        service_environment
            .get("TMPDIR")
            .map(String::as_str)
            .unwrap_or("/tmp"),
    )?;
    still_owned(proxy, &identity, runtime)?;
    Ok(identity)
}
#[derive(Clone)]
struct Installed {
    root: String,
    service: String,
    client: String,
}
fn installed_brokers(runtime: &Runtime) -> Result<Vec<Installed>, String> {
    let declared = rt::value(&runtime.environment, "STEAM_COMPAT_CLIENT_INSTALL_PATH");
    if !declared.starts_with('/') {
        return Err("The target-associated Steam client installation is unavailable".into());
    }
    let root = rt::canonical(declared);
    if !fs::metadata(&root).is_ok_and(|m| m.is_dir() && m.uid() == rt::uid()) {
        return Err(
            "The target-associated Steam installation is unavailable or foreign-owned".into(),
        );
    }
    let mut result: Vec<Installed> = Vec::new();
    for suffix in [
        "steamrt64/pv-runtime/steam-runtime-steamrt/pressure-vessel",
        "ubuntu12_64/steam-runtime-tools-64",
    ] {
        let directory = rt::canonical(format!("{root}/{suffix}"));
        if directory.is_empty() {
            continue;
        }
        let client = rt::canonical(format!("{directory}/bin/steam-runtime-launch-client"));
        if !rt::executable(&client) || !Path::new(&client).starts_with(&directory) {
            continue;
        }
        for suffix in [
            "bin/steam-runtime-launcher-service",
            "libexec/steam-runtime-tools-0/x86_64-linux-gnu-srt-launcher-service",
            "libexec/steam-runtime-tools-0/i386-linux-gnu-srt-launcher-service",
        ] {
            let service = rt::canonical(format!("{directory}/{suffix}"));
            if !rt::executable(&service) || !Path::new(&service).starts_with(&directory) {
                continue;
            }
            if !result
                .iter()
                .any(|v| rt::same_file(&v.service, &service) && v.client == client)
            {
                result.push(Installed {
                    root: root.clone(),
                    service,
                    client: client.clone(),
                });
            }
        }
    }
    if result.is_empty() {
        return Err(
            "The selected Steam client bundle's installed launcher service/client is unavailable"
                .into(),
        );
    }
    Ok(result)
}
pub(crate) fn broker_prerequisites(runtime: &Runtime) -> Result<(), String> {
    if !rt::executable(&runtime.proton_path) {
        return Err("The exact active Proton wrapper is unavailable".into());
    }
    if !rt::executable(&runtime.launcher_path) {
        return Err("The exact selected Steam Runtime launcher is unavailable".into());
    }
    installed_brokers(runtime).map(|_| ())
}
fn inspect_broker_owner(
    runtime: &Runtime,
    proxy: &Proxy<'_>,
    bus: &str,
    installed: &[Installed],
) -> Result<Identity, String> {
    let mut identity = identity(proxy, bus)?;
    let base = format!("/proc/{}", identity.pid);
    let target = format!("/proc/{}", runtime.anchor_pid);
    let target_environment = rt::environment(runtime.anchor_pid)?;
    let peer_environment = rt::environment(identity.pid)?;
    let declared = rt::value(&target_environment, "STEAM_COMPAT_CLIENT_INSTALL_PATH");
    if !declared.starts_with('/')
        || declared != rt::value(&runtime.environment, "STEAM_COMPAT_CLIENT_INSTALL_PATH")
    {
        return Err("The target's Steam client installation association changed".into());
    }
    let snap = is_steam_snap(runtime.anchor_pid, &target_environment);
    if (runtime.packaging == "steam_snap" && !snap)
        || (snap
            && (profile(runtime.anchor_pid) != profile(identity.pid)
                || !is_steam_snap(identity.pid, &peer_environment)))
    {
        return Err("The service does not belong to the selected Steam Snap instance".into());
    }
    if snap && target_environment.contains_key("SNAP") {
        let package = rt::value(&target_environment, "SNAP");
        if !package.starts_with('/')
            || package != rt::value(&peer_environment, "SNAP")
            || !rt::same_file(
                format!("{target}/root{package}"),
                format!("{base}/root{package}"),
            )
        {
            return Err("The service does not share the selected Steam Snap revision".into());
        }
    }
    let mut selected: Option<&Installed> = None;
    for candidate in installed {
        if !rt::same_file(format!("{base}/exe"), &candidate.service)
            || !rt::same_file(&candidate.root, format!("{target}/root{declared}"))
            || !rt::same_file(&candidate.root, format!("{base}/root{declared}"))
            || !rt::same_file(
                &candidate.service,
                format!("{base}/root{}", candidate.service),
            )
            || !rt::same_file(
                &candidate.client,
                format!("{base}/root{}", candidate.client),
            )
        {
            continue;
        }
        if selected
            .is_some_and(|old| old.service != candidate.service || old.client != candidate.client)
        {
            return Err("The installed client service identity is ambiguous".into());
        }
        selected = Some(candidate);
    }
    let selected = selected.ok_or(
        "The advertised process is not this Steam installation's installed client-runtime service",
    )?;
    identity.executable = selected.service.clone();
    identity.client = selected.client.clone();
    still_owned(proxy, &identity, runtime)?;
    Ok(identity)
}
fn inspect_broker(runtime: &Runtime, proxy: &Proxy<'_>) -> Result<Identity, String> {
    broker_prerequisites(runtime)?;
    if rt::wine(runtime.anchor_pid) != runtime.wine_binary
        || rt::proton_for_wine(&runtime.wine_binary) != runtime.proton_path
    {
        return Err("The selected game's exact Wine/Proton identity changed".into());
    }
    let environment = rt::environment(runtime.anchor_pid)?;
    let hint = rt::value(&environment, HINT);
    let explicit = !hint.is_empty() && hint != "1";
    if explicit && !broker_name_valid(hint) {
        return Err("The target's alongside-Steam service name hint is invalid".into());
    }
    if !runtime.service_bus.is_empty() && explicit && runtime.service_bus != hint {
        return Err(
            "The target's authoritative alongside-Steam service association changed".into(),
        );
    }
    let selected_name = if !runtime.service_bus.is_empty() {
        &runtime.service_bus
    } else if explicit {
        hint
    } else {
        ""
    };
    let installed = installed_brokers(runtime)?;
    // ListNames and GetNameOwner inspect only advertised services, never activation.
    let mut names: Vec<String> = proxy.call("ListNames", &()).map_err(|e| e.to_string())?;
    names.sort();
    let mut selected: Option<Identity> = None;
    let mut failure = "No existing authenticated alongside-Steam service is advertised".to_string();
    for name in names.iter().filter(|n| {
        broker_name_valid(n) && (selected_name.is_empty() || n.as_str() == selected_name)
    }) {
        match inspect_broker_owner(runtime, proxy, name, &installed) {
            Ok(identity) => {
                if selected
                    .as_ref()
                    .is_some_and(|old| old.owner != identity.owner)
                {
                    return Err(
                        "Multiple authenticated alongside-Steam owners match this target. No unambiguous route exists".into(),
                    );
                }
                if selected.is_none() {
                    selected = Some(identity);
                }
            }
            Err(error) => {
                if !selected_name.is_empty() {
                    return Err(error);
                }
                failure = error;
            }
        }
    }
    let identity = selected.ok_or(failure)?;
    let target = format!("/proc/{}/root", runtime.anchor_pid);
    let peer = format!("/proc/{}/root", identity.pid);
    for path in [
        &runtime.prefix,
        &runtime.wine_binary,
        &runtime.proton_path,
        &runtime.launcher_path,
    ] {
        if path.is_empty()
            || !rt::same_file(path, format!("{target}{path}"))
            || !rt::same_file(path, format!("{peer}{path}"))
        {
            return Err(
                "The broker cannot see the exact selected prefix and Proton/runtime objects".into(),
            );
        }
    }
    let peer_environment = rt::environment(identity.pid)?;
    rt::shared_wineserver(
        &runtime.prefix,
        &environment,
        &target,
        &peer,
        peer_environment
            .get("TMPDIR")
            .map(String::as_str)
            .unwrap_or("/tmp"),
    )?;
    rt::validate_anchor(runtime.anchor_pid, runtime.start_ticks, true, identity.pid)?;
    still_owned(proxy, &identity, runtime)?;
    Ok(identity)
}
fn inspect(runtime: &Runtime) -> Result<Identity, String> {
    let connection = session_bus()?;
    let proxy = bus_proxy(&connection)?;
    match runtime.strategy.as_str() {
        "app_launcher" => inspect_app(runtime, &proxy),
        "steam_broker" => inspect_broker(runtime, &proxy),
        _ => Err("Not a service-backed runtime route".into()),
    }
}
pub(crate) fn select(runtime: &mut Runtime) -> Result<(), String> {
    let identity = inspect(runtime)?;
    if runtime.strategy == "app_launcher" {
        runtime.app_id = app_selector(&runtime.environment);
    }
    runtime.service_bus = identity.bus;
    runtime.service_owner = identity.owner;
    runtime.service_pid = identity.pid;
    runtime.service_start_ticks = identity.ticks;
    runtime.service_executable = identity.executable;
    runtime.service_client = identity.client;
    Ok(())
}
pub(crate) fn revalidate(runtime: &Runtime) -> Result<(), String> {
    if !runtime.service_owner.starts_with(':')
        || runtime.service_pid == 0
        || runtime.service_start_ticks == 0
    {
        return Err("No authenticated existing launcher service is pinned".into());
    }
    let identity = inspect(runtime)?;
    if identity.bus != runtime.service_bus
        || identity.owner != runtime.service_owner
        || identity.pid != runtime.service_pid
        || identity.ticks != runtime.service_start_ticks
        || identity.executable != runtime.service_executable
        || identity.client != runtime.service_client
    {
        return Err("The verified service was replaced. Refresh the process list".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    #[test]
    fn broker_instance_names_are_strict() {
        assert!(broker_name_valid(ALONGSIDE));
        for suffix in ["1", "7114", "18446744073709551615"] {
            assert!(broker_name_valid(&format!("{ALONGSIDE}.Instance{suffix}")));
        }
        for suffix in [
            "",
            "0",
            "01",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.foo",
            "1\n",
            "18446744073709551616",
            "１２",
            "1/other",
        ] {
            assert!(!broker_name_valid(&format!("{ALONGSIDE}.Instance{suffix}")));
        }
    }
    #[test]
    fn app_and_shortcut_id_authority() {
        assert_eq!(
            app_id(&Environment::from([("SteamAppId".into(), "000123".into())])),
            "123"
        );
        assert!(
            app_id(&Environment::from([(
                "SteamGameId".into(),
                "1099511627776".into()
            )]))
            .is_empty()
        );
        let mut shortcut = Environment::from([
            ("STEAM_COMPAT_APP_ID".into(), "0".into()),
            ("SteamGameId".into(), "18446744069414584320".into()),
        ]);
        assert_eq!(app_selector(&shortcut), "0");
        shortcut.insert("SteamAppId".into(), "0".into());
        assert!(app_selector(&shortcut).is_empty());
        for invalid in ["", "01", "-1", "+1", "4294967296", "١٢٣"] {
            assert!(app_bus(invalid).is_err());
        }
        assert_eq!(
            app_selector(&Environment::from([
                ("STEAM_COMPAT_APP_ID".into(), "123".into()),
                ("SteamAppId".into(), "456".into()),
            ])),
            "123"
        );
        for invalid in ["", "000123", "+123", "not-an-id", "4294967296"] {
            assert!(
                app_selector(&Environment::from([
                    ("STEAM_COMPAT_APP_ID".into(), invalid.into()),
                    ("SteamAppId".into(), "123".into()),
                ]))
                .is_empty()
            );
        }
        assert!(
            app_selector(&Environment::from([("SteamGameId".into(), "123".into())])).is_empty()
        );
    }
    #[test]
    fn app_launch_argv_never_forwards_environment_or_nests_container() {
        let runtime = Runtime {
            service_owner: ":1.999".into(),
            working_directory: "/game space/'quoted';$HOME\nnext".into(),
            proton_path: "/Proton space/proton".into(),
            ..Runtime::default()
        };
        let args = app_arguments(&runtime);
        assert_eq!(
            &args[args.len() - 3..],
            ["--", "/Proton space/proton", "runinprefix"]
        );
        assert!(
            !args
                .iter()
                .any(|v| v.starts_with("--env=") || v == "--batch")
        );
    }
    #[test]
    fn private_bus_stalled_authentication_times_out_and_closes_socket() {
        use std::io::Read;
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::net::UnixListener;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Instant;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
            "needle-bus-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let started = Instant::now();
        let result = connect_with_timeout(
            &format!("unix:path={}", path.display()),
            Duration::from_millis(30),
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut authentication = Vec::new();
        // EOF, rather than a read timeout, proves the abandoned build closed
        // its transport even though the peer never answered authentication.
        socket.read_to_end(&mut authentication).unwrap();
        for address in [
            "",
            "autolaunch:",
            "tcp:host=localhost,port=123",
            "unix:path=/tmp/x;autolaunch:",
        ] {
            assert!(connect(address).is_err());
        }
    }
    #[test]
    fn private_bus_credentials_and_owner_replacement() {
        struct Daemon(Child);
        impl Drop for Daemon {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let process = match Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("SKIP: dbus-daemon unavailable");
                return;
            }
            Err(e) => panic!("Cannot start fixture private bus: {e}"),
        };
        let mut daemon = Daemon(process);
        let mut address = String::new();
        std::io::BufReader::new(daemon.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let monitor = connect(address.trim()).unwrap();
        let parsed = zbus::Address::try_from(address.trim()).unwrap();
        let zero = "00000000000000000000000000000000";
        let incorrect = if parsed.guid().is_some_and(|guid| guid.as_str() == zero) {
            "11111111111111111111111111111111"
        } else {
            zero
        };
        let wrong_guid = parsed
            .set_guid(zbus::Guid::try_from(incorrect).unwrap())
            .unwrap()
            .to_string();
        assert!(connect(&wrong_guid).unwrap_err().contains("GUID"));
        let bus = bus_proxy(&monitor).unwrap();
        let advertised = connect(address.trim()).unwrap();
        advertised.request_name(ALONGSIDE).unwrap();
        let identity = identity(&bus, ALONGSIDE).unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.owner.starts_with(':'));
        advertised.release_name(ALONGSIDE).unwrap();
        assert!(owner(&bus, ALONGSIDE).is_err());
        let replacement = connect(address.trim()).unwrap();
        replacement.request_name(ALONGSIDE).unwrap();
        assert_ne!(owner(&bus, ALONGSIDE).unwrap(), identity.owner);
        // Correct name and same-user credentials do not authenticate a random executable.
        let invalid = Runtime {
            strategy: "app_launcher".into(),
            environment: Environment::from([("SteamAppId".into(), "123".into())]),
            ..Runtime::default()
        };
        replacement.request_name("com.steampowered.App123").unwrap();
        assert!(inspect_app(&invalid, &bus).is_err());
    }
}
