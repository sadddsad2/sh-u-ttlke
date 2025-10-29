use shuttle_axum::axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shuttle_runtime::SecretStore;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path as StdPath;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

// Vmess 配置结构体
#[derive(Serialize, Deserialize)]
struct VmessConfig {
    v: String,
    ps: String,
    add: String,
    port: String,
    id: String,
    aid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scy: Option<String>,
    net: String,
    #[serde(rename = "type")]
    type_field: String,
    host: String,
    path: String,
    tls: String,
    sni: String,
    alpn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
}

// 共享状态
#[derive(Clone)]
struct AppState {
    file_path: String,
    uuid: String,
    encoded_url: Arc<RwLock<String>>,
    client: Client,
}

async fn hello_world() -> &'static str {
    "hello world"
}

async fn read_info() -> impl IntoResponse {
    let uuid = env::var("UUID").unwrap_or_default();
    format!(
        r#"
==============================

    /info 系统信息
    /start 检查进程
    /{} 订阅

==============================
"#,
        uuid
    )
}

async fn read_sub(State(state): State<AppState>) -> impl IntoResponse {
    let sub_path = format!("{}/sub.txt", state.file_path);
    match fs::read_to_string(&sub_path) {
        Ok(content) => content,
        Err(_) => "Failed to read sub.txt".to_string(),
    }
}

async fn uuid_handler(
    Path(uuid_param): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if uuid_param == state.uuid {
        let encoded_url = state.encoded_url.read().await;
        encoded_url.clone()
    } else {
        "Not Found".to_string()
    }
}

async fn start_processes() -> Json<Value> {
    let mut statuses = vec![];

    // 检查 web 进程
    let web_status = check_process("web");
    statuses.push(json!({
        "process": "web",
        "status": if web_status { "Running" } else { "Not running" }
    }));

    // 检查 cfloat 进程
    let cff_status = check_process("cfloat");
    statuses.push(json!({
        "process": "cfloat",
        "status": if cff_status { "Running" } else { "Not running" }
    }));

    // 检查 nexus 进程
    let nezha_status = check_process("nexus");
    statuses.push(json!({
        "process": "nexus",
        "status": if nezha_status { "Running" } else { "Not running" }
    }));

    Json(json!({
        "message": "Process status check completed",
        "processes": statuses
    }))
}

fn check_process(process_name: &str) -> bool {
    Command::new("ps")
        .args(["aux"])
        .output()
        .ok()
        .and_then(|output| {
            let output_str = String::from_utf8_lossy(&output.stdout);
            Some(output_str.contains(process_name) && !output_str.contains("grep"))
        })
        .unwrap_or(false)
}

async fn create_config_files() {
    println!("Creating config files...");
    let file_path = env::var("FILE_PATH").unwrap_or_else(|_| "./tmp".to_string());
    let uuid = env::var("UUID").unwrap_or_default();

    if !StdPath::new(&file_path).exists() {
        fs::create_dir_all(&file_path).expect("Failed to create directory");
    }

    // 清理旧文件
    let old_files = ["argo.log", "sub.txt", "list.txt", "config.yml"];
    for file in old_files.iter() {
        let file_path_full = format!("{}/{}", file_path, file);
        let _ = fs::remove_file(file_path_full);
    }

    // 创建 Nezha 配置
    let nezha_server = env::var("NSERVER").unwrap_or_default();
    let nezha_key = env::var("NKEY").unwrap_or_default();

    if !nezha_server.is_empty() && !nezha_key.is_empty() {
        let nezha_has_port = nezha_server.contains(':');
        
        if nezha_has_port {
            let tls_value = env::var("NTLS")
                .unwrap_or_else(|_| "--tls".to_string())
                .contains("--tls");

            let sub_name = env::var("SUB_NAME").unwrap_or_else(|_| "GitHub".to_string());
            let tok = env::var("TOK").unwrap_or_default();
            let seed = format!("{}{}{}{}{}", sub_name, uuid, nezha_server, nezha_key, tok);
            let mut hasher = Sha256::new();
            hasher.update(seed.as_bytes());
            let hash = format!("{:x}", hasher.finalize());
            let agent_uuid = env::var("AGENT_UUID").unwrap_or_else(|_| {
                format!(
                    "{}-{}-{}-{}-{}",
                    &hash[0..8],
                    &hash[8..12],
                    &hash[12..16],
                    &hash[16..20],
                    &hash[20..32]
                )
            });

            let config_yaml = format!(
                r#"client_secret: {}
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 3
server: {}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: {}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {}"#,
                nezha_key, nezha_server, tls_value, agent_uuid
            );

            fs::write(format!("{}/config.yml", file_path), config_yaml)
                .expect("Failed to write config.yml");
            println!("Nezha config created");
        }
    }
}

async fn download_files() {
    println!("Downloading files...");
    let file_path = env::var("FILE_PATH").unwrap_or_else(|_| "./tmp".to_string());
    let arch = Command::new("uname")
        .arg("-m")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default();

    println!("Architecture: {}", arch);

    let nezha_server = env::var("NSERVER").unwrap_or_default();
    let nezha_key = env::var("NKEY").unwrap_or_default();
    let nezha_has_port = nezha_server.contains(':');

    let file_info = match arch.as_str() {
        "arm" | "arm64" | "aarch64" => {
            let mut files = vec![
                (
                    "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan-arm",
                    "webdav",
                ),
                (
                    "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-arm64",
                    "cfloat",
                ),
            ];
            if !nezha_server.is_empty() && !nezha_key.is_empty() {
                let nezha_url = if nezha_has_port {
                    "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_arm64"
                } else {
                    "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_arm64"
                };
                files.push((nezha_url, "nexus"));
            }
            files
        }
        "amd64" | "x86_64" | "x86" => {
            let mut files = vec![
                (
                    "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan",
                    "webdav",
                ),
                (
                    "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-amd64",
                    "cfloat",
                ),
            ];
            if !nezha_server.is_empty() && !nezha_key.is_empty() {
                let nezha_url = if nezha_has_port {
                    "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_amd64"
                } else {
                    "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_amd64"
                };
                files.push((nezha_url, "nexus"));
            }
            files
        }
        _ => vec![],
    };

    for (url, filename) in file_info {
        let filepath = format!("{}/{}", file_path, filename);
        if !StdPath::new(&filepath).exists() {
            println!("Downloading {} from {}", filename, url);
            Command::new("curl")
                .args(["-L", "-sS", "-o", &filepath, url])
                .status()
                .expect("Failed to download file");

            Command::new("chmod")
                .args(["777", &filepath])
                .status()
                .expect("Failed to set permissions");
            println!("Downloaded and set permissions for {}", filename);
        } else {
            println!("{} already exists", filename);
        }
    }
}

async fn run_services() {
    println!("Starting services...");
    let file_path = env::var("FILE_PATH").unwrap_or_else(|_| "./tmp".to_string());
    let uuid = env::var("UUID").unwrap_or_default();
    let vmms = env::var("VPATH").unwrap_or_else(|_| "vls-123456".to_string());
    let vmmport = env::var("VL_PORT").unwrap_or_else(|_| "8002".to_string());
    let vmpath = env::var("MPATH").unwrap_or_else(|_| "vms-3456789".to_string());
    let vmport = env::var("VM_PORT").unwrap_or_else(|_| "8001".to_string());
    let tok = env::var("TOK").unwrap_or_default();

    // 启动 Nezha
    let nezha_server = env::var("NSERVER").unwrap_or_default();
    let nezha_key = env::var("NKEY").unwrap_or_default();
    let nezha_port = env::var("NPORT").unwrap_or_else(|_| "443".to_string());
    let nezha_has_port = nezha_server.contains(':');

    if !nezha_server.is_empty() && !nezha_key.is_empty() {
        if StdPath::new(&format!("{}/nexus", file_path)).exists() {
            if nezha_has_port {
                // 使用配置文件
                Command::new(format!("{}/nexus", file_path))
                    .args(["-c", &format!("{}/config.yml", file_path)])
                    .spawn()
                    .expect("Failed to start nexus with config");
                println!("Nezha agent started (with config)");
            } else {
                // 使用命令行参数
                let neztls = env::var("NTLS").unwrap_or_else(|_| "--tls".to_string());
                Command::new(format!("{}/nexus", file_path))
                    .args([
                        "-s",
                        &format!("{}:{}", nezha_server, nezha_port),
                        "-p",
                        &nezha_key,
                        &neztls,
                    ])
                    .spawn()
                    .expect("Failed to start nexus");
                println!("Nezha agent started (command line)");
            }
        }
    }

    sleep(Duration::from_secs(2)).await;

    // 启动 webdav
    if StdPath::new(&format!("{}/webdav", file_path)).exists() {
        Command::new(format!("{}/webdav", file_path))
            .env("MPATH", &vmpath)
            .env("VM_PORT", &vmport)
            .env("VPATH", &vmms)
            .env("VL_PORT", &vmmport)
            .env("UUID", &uuid)
            .spawn()
            .expect("Failed to start webdav");
        println!("Webdav started");
    }

    sleep(Duration::from_secs(2)).await;

    // 启动 cfloat
    if StdPath::new(&format!("{}/cfloat", file_path)).exists() {
        let xieyi = env::var("XIEYI").unwrap_or_else(|_| "vms".to_string());
        let vport = if xieyi == "vms" { &vmport } else { &vmmport };

        if !tok.is_empty() {
            Command::new(format!("{}/cfloat", file_path))
                .args([
                    "tunnel",
                    "--edge-ip-version",
                    "auto",
                    "--protocol",
                    "auto",
                    "run",
                    "--no-autoupdate",
                    "--token",
                    &tok,
                ])
                .spawn()
                .expect("Failed to start cfloat with token");
            println!("Cloudflare tunnel started (with token)");
        } else {
            Command::new(format!("{}/cfloat", file_path))
                .args([
                    "tunnel",
                    "--edge-ip-version",
                    "auto",
                    "--protocol",
                    "auto",
                    "--url",
                    &format!("http://localhost:{}", vport),
                    "--no-autoupdate",
                ])
                .stdout(
                    File::create(format!("{}/argo.log", file_path))
                        .expect("Failed to create argo.log"),
                )
                .stderr(
                    File::create(format!("{}/argo.log", file_path))
                        .expect("Failed to create argo.log"),
                )
                .spawn()
                .expect("Failed to start cfloat");
            println!("Cloudflare tunnel started (without token)");
        }
    }
}

async fn generate_links(state: &AppState) {
    println!("Waiting for services to start...");
    sleep(Duration::from_secs(6)).await;

    let file_path = &state.file_path;
    let tok = env::var("TOK").unwrap_or_default();
    let host_name = if !tok.is_empty() {
        env::var("DOM").unwrap_or_default()
    } else {
        // 从 argo.log 提取域名
        let argo_log = fs::read_to_string(format!("{}/argo.log", file_path)).unwrap_or_default();
        let re = Regex::new(r"https://([^/\s]+\.trycloudflare\.com)").unwrap();
        re.captures(&argo_log)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    };

    if host_name.is_empty() {
        println!("Warning: Could not determine host_name");
        return;
    }

    println!("Host name: {}", host_name);

    // 获取国家代码和 ISP
    let country_code = get_country_code(&state.client).await;
    println!("Country Code: {}", country_code);

    let sub_name = env::var("SUB_NAME").unwrap_or_else(|_| "GitHub".to_string());
    let youxuan = env::var("CF_IP").unwrap_or_else(|_| "ip.sb".to_string());
    let xieyi = env::var("XIEYI").unwrap_or_else(|_| "vms".to_string());
    let vmms = env::var("VPATH").unwrap_or_else(|_| "vls-123456".to_string());
    let vmpath = env::var("MPATH").unwrap_or_else(|_| "vms-3456789".to_string());

    let mut list_file =
        File::create(format!("{}/list.txt", file_path)).expect("Failed to create list.txt");

    if xieyi == "vms" {
        // Vmess 配置
        let vmess_config = VmessConfig {
            v: "2".to_string(),
            ps: format!("{}-{}", country_code, sub_name),
            add: youxuan.clone(),
            port: "443".to_string(),
            id: state.uuid.clone(),
            aid: "0".to_string(),
            scy: None,
            net: "ws".to_string(),
            type_field: "none".to_string(),
            host: host_name.clone(),
            path: format!("/{}?ed=2048", vmpath),
            tls: "tls".to_string(),
            sni: host_name.clone(),
            alpn: "".to_string(),
            fp: None,
        };

        let vmess_json = serde_json::to_string(&vmess_config).unwrap();
        let vmess_link = format!("vmess://{}", BASE64_STANDARD.encode(vmess_json));

        writeln!(list_file, "{}", vmess_link).unwrap();
    } else {
        // Vless 配置
        let vless_link = format!(
            "vless://{}@{}:443?path=%2F{}%3Fed%3D2048&security=tls&encryption=none&host={}&type=ws&sni={}#{}-{}",
            state.uuid, youxuan, vmms, host_name, host_name, country_code, sub_name
        );
        writeln!(list_file, "{}", vless_link).unwrap();
    }

    let list_content =
        fs::read_to_string(format!("{}/list.txt", file_path)).expect("Failed to read list.txt");
    let sub_content = BASE64_STANDARD.encode(list_content.as_bytes());

    fs::write(format!("{}/sub.txt", file_path), &sub_content).expect("Failed to write sub.txt");

    // 更新共享状态
    *state.encoded_url.write().await = sub_content.clone();

    println!("\nSubscription link generated:");
    println!("{}", sub_content);

    // 发送订阅
    let sub_url = env::var("SUB_URL").unwrap_or_default();
    if !sub_url.is_empty() {
        let _ = send_subscription(&state.client, &sub_url, &sub_name, &list_content).await;
    }

    // 清理临时文件
    let _ = fs::remove_file(format!("{}/list.txt", file_path));
}

async fn get_country_code(client: &Client) -> String {
    let urls = vec![
        "http://ipinfo.io/country",
        "https://ifconfig.co/country",
        "https://ipapi.co/country",
    ];

    for url in urls {
        if let Ok(response) = client.get(url).send().await {
            if let Ok(text) = response.text().await {
                let code = text.trim().to_string();
                if code.len() >= 1
                    && code.len() <= 2
                    && code.chars().all(|c| c.is_ascii_uppercase())
                {
                    return code;
                }
            }
        }
    }

    "UN".to_string()
}

async fn send_subscription(
    client: &Client,
    sub_url: &str,
    sub_name: &str,
    up_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let post_data = json!({
        "URL_NAME": sub_name,
        "URL": up_url
    });

    match client.post(sub_url).json(&post_data).send().await {
        Ok(_) => {
            println!("Subscription uploaded successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("Subscription upload failed: {}", e);
            Err(Box::new(e))
        }
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    // 设置环境变量
    for (key, value) in secrets.into_iter() {
        env::set_var(key, value);
    }

    println!("==============================");
    println!();
    println!("     /info 系统信息");
    println!("     /start 检查进程");
    println!(
        "     /{} 订阅",
        env::var("UUID").unwrap_or_default()
    );
    println!();
    println!("==============================");

    let file_path = env::var("FILE_PATH").unwrap_or_else(|_| "./tmp".to_string());
    let uuid = env::var("UUID").unwrap_or_default();

    let state = AppState {
        file_path: file_path.clone(),
        uuid: uuid.clone(),
        encoded_url: Arc::new(RwLock::new(String::new())),
        client: Client::new(),
    };

    // 初始化 - 同步执行，不使用 spawn
    create_config_files().await;
    download_files().await;
    run_services().await;
    
    // 生成链接
    generate_links(&state).await;

    println!("\n==============================");
    println!("App is running!");
    println!("Checking process status:");
    println!("  - webdav: {}", if check_process("webdav") { "Running" } else { "Not running" });
    println!("  - cfloat: {}", if check_process("cfloat") { "Running" } else { "Not running" });
    println!("  - nexus: {}", if check_process("nexus") { "Running" } else { "Not running" });
    println!("==============================\n");

    // 构建路由
    let router = Router::new()
        .route("/", get(hello_world))
        .route("/info", get(read_info))
        .route("/start", get(start_processes))
        .route(&format!("/{}", uuid), get(uuid_handler))
        .route(
            &format!(
                "/{}",
                env::var("SUB_PATH").unwrap_or_else(|_| "sub".to_string())
            ),
            get(read_sub),
        )
        .with_state(state);

    Ok(router.into())
}
