//! JNI surface for `com.acowork.androidhost` (ADR-AND-004).
//!
//! Keeps Android SDK / Gradle out of `acowork-android`; the APK loads this
//! `cdylib` and talks only through the methods below.

#![allow(non_snake_case)]

mod node_host;

use std::path::PathBuf;

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use once_cell::sync::OnceCell;

use acowork_android::host::{
    HostConfig, HostProfile, LocalHost, ProbeCommand, catalog, run_probe,
};
use acowork_android::node::capability_tags;

static RUNTIME: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

fn rt() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("acowork-android-ffi")
            .build()
            .expect("tokio runtime")
    })
}

fn init_log() {
    static ONCE: OnceCell<()> = OnceCell::new();
    let _ = ONCE.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn jstring(env: &mut JNIEnv<'_>, s: impl AsRef<str>) -> jstring {
    env.new_string(s.as_ref())
        .expect("new_string")
        .into_raw()
}

fn java_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, String> {
    env.get_string(&value)
        .map(|s| s.into())
        .map_err(|e| e.to_string())
}

fn err_json(msg: impl AsRef<str>) -> String {
    serde_json::json!({ "ok": false, "error": msg.as_ref() }).to_string()
}

/// `Native.version(): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    jstring(
        &mut env,
        format!("acowork-android-ffi {}", env!("CARGO_PKG_VERSION")),
    )
}

/// `Native.probeSummary(home: String, packageName: String): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_probeSummary(
    mut env: JNIEnv,
    _class: JClass,
    home: JString,
    package_name: JString,
) -> jstring {
    init_log();
    let result = (|| -> Result<String, String> {
        let home = PathBuf::from(java_string(&mut env, home)?);
        let package = java_string(&mut env, package_name)?;
        let _ = std::fs::create_dir_all(&home);
        let host = LocalHost::new().map_err(|e| e.to_string())?;
        let probe = rt().block_on(run_probe(&host, &ProbeCommand::read_only_set(), &package));
        let profile = HostProfile::assemble(&probe, &package);
        let tags = capability_tags(&profile);
        Ok(serde_json::json!({
            "ok": true,
            "profile": profile.name.as_str(),
            "privilege": format!("{:?}", profile.privilege),
            "caps": tags,
            "home": home.display().to_string(),
        })
        .to_string())
    })()
    .unwrap_or_else(err_json);
    jstring(&mut env, result)
}

/// `Native.settingsCatalog(): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_settingsCatalog(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let body = serde_json::to_string(&catalog()).unwrap_or_else(|e| err_json(e.to_string()));
    jstring(&mut env, body)
}

/// `Native.loadHostConfig(home: String): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_loadHostConfig(
    mut env: JNIEnv,
    _class: JClass,
    home: JString,
) -> jstring {
    let result = (|| -> Result<String, String> {
        let home = PathBuf::from(java_string(&mut env, home)?);
        let loaded = HostConfig::load(&home).map_err(|e| e.to_string())?;
        serde_json::to_string(&loaded.config).map_err(|e| e.to_string())
    })()
    .unwrap_or_else(err_json);
    jstring(&mut env, result)
}

/// `Native.saveHostConfig(home: String, json: String): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_saveHostConfig(
    mut env: JNIEnv,
    _class: JClass,
    home: JString,
    json: JString,
) -> jstring {
    let result = (|| -> Result<String, String> {
        let home = PathBuf::from(java_string(&mut env, home)?);
        let raw = java_string(&mut env, json)?;
        let config: HostConfig = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        config.validate().map_err(|e| e.to_string())?;
        config.save(&home).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    })()
    .unwrap_or_else(err_json);
    jstring(&mut env, result)
}

/// `Native.startNode(home, gatewayHttp, enrollmentToken, nodeName, advertiseHost, advertisePort, enginePath): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_startNode(
    mut env: JNIEnv,
    _class: JClass,
    home: JString,
    gateway_http: JString,
    enrollment_token: JString,
    node_name: JString,
    advertise_host: JString,
    advertise_port: JString,
    engine_path: JString,
) -> jstring {
    init_log();
    let result = (|| -> Result<String, String> {
        let home = PathBuf::from(java_string(&mut env, home)?);
        let gateway_http = java_string(&mut env, gateway_http)?;
        let enrollment_token = java_string(&mut env, enrollment_token)?;
        let node_name = java_string(&mut env, node_name)?;
        let advertise_host = java_string(&mut env, advertise_host)?;
        let advertise_port_raw = java_string(&mut env, advertise_port)?;
        let engine_path = java_string(&mut env, engine_path)?;
        let advertise_port: u16 = if advertise_port_raw.is_empty() {
            0
        } else {
            advertise_port_raw
                .parse()
                .map_err(|e| format!("advertise_port: {e}"))?
        };
        node_host::start(
            rt(),
            node_host::StartArgs {
                home,
                gateway_http,
                enrollment_token: if enrollment_token.is_empty() {
                    None
                } else {
                    Some(enrollment_token)
                },
                node_name: if node_name.is_empty() {
                    None
                } else {
                    Some(node_name)
                },
                advertise_host: if advertise_host.is_empty() {
                    "127.0.0.1".into()
                } else {
                    advertise_host
                },
                advertise_port,
                package_name: "com.acowork.androidhost".into(),
                engine_path: if engine_path.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(engine_path))
                },
            },
        )
    })()
    .unwrap_or_else(err_json);
    jstring(&mut env, result)
}

/// `Native.stopNode(): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_stopNode(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = node_host::stop().unwrap_or_else(err_json);
    jstring(&mut env, result)
}

/// `Native.nodeStatus(): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acowork_androidhost_Native_nodeStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    jstring(&mut env, node_host::status_json())
}
