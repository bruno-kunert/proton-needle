use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct RouteProbe {
    pub strategy: String,
    pub available: bool,
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Default)]
pub struct Runtime {
    pub packaging: String,
    pub prefix: String,
    pub proton_path: String,
    pub wine_binary: String,
    pub launcher_path: String,
    pub version: String,
    pub working_directory: String,
    pub environment: BTreeMap<String, String>,
    pub anchor_pid: u32,
    pub start_ticks: u64,
    pub namespace_key: String,
    pub launch_context_key: String,
    pub app_id: String,
    pub strategy: String,
    pub supported: bool,
    pub error_code: String,
    pub error: String,
    pub service_bus: String,
    pub service_owner: String,
    pub service_pid: u32,
    pub service_start_ticks: u64,
    pub service_executable: String,
    pub route_probes: Vec<RouteProbe>,
    pub service_client: String,
}
impl Runtime {
    pub fn session_identity(&self) -> String {
        let executable = if self.proton_path.is_empty() {
            &self.wine_binary
        } else {
            &self.proton_path
        };
        format!(
            "{:?}",
            (
                &self.prefix,
                executable,
                &self.namespace_key,
                &self.launch_context_key
            )
        )
    }
}
#[derive(Clone, Debug, Default)]
pub struct Process {
    pub linux_pid: u32,
    pub host_start_ticks: u64,
    pub windows_pid: u32,
    pub name: String,
    pub image_path: String,
    pub creation_time: String,
    pub architecture: String,
    pub steam_app_id: String,
    pub detection: String,
    pub runtime: Runtime,
    pub injectable: bool,
}
impl Process {
    pub fn identity(&self) -> String {
        if self.windows_pid == 0 {
            format!("host:{}:{}", self.linux_pid, self.host_start_ticks)
        } else {
            format!(
                "{}:{}:{}",
                self.runtime.session_identity(),
                self.windows_pid,
                self.creation_time
            )
        }
    }
    pub fn lifetime_key(&self) -> String {
        format!(
            "{:?}",
            (&self.runtime.prefix, self.windows_pid, &self.creation_time)
        )
    }
}
#[derive(Clone, Debug, Default)]
pub struct OperationResult {
    pub success: bool,
    pub error_code: String,
    pub message: String,
    pub response: serde_json::Value,
    pub inconclusive: bool,
}
impl OperationResult {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            error_code: code.into(),
            message: message.into(),
            ..Self::default()
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct DllInfo {
    pub valid: bool,
    pub architecture: String,
    pub error: String,
}
