// SPDX-License-Identifier: MIT
//! Explicit finite Linux user services reuse the ordinary consent, clock and activation gates.
use super::{files, model, services};
use crate::runtime_manifest::Manifest;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Args)]
pub struct Options {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    clock_monitor: PathBuf,
    /// Retain an already approved clock binary while independently updating a workload.
    #[arg(long)]
    clock_executable: Option<PathBuf>,
    #[arg(long)]
    activation_request: Option<PathBuf>,
    #[arg(long)]
    minimum_signer_generation: Option<u64>,
}
#[derive(Subcommand)]
pub enum Command {
    Preview(Options),
    /// Enable only the exact reviewed unit and its separately pinned clock monitor.
    Enable {
        #[command(flatten)]
        options: Options,
        #[arg(long)]
        preview_digest: String,
        /// Explicitly permit this user's services to survive logout and start at boot.
        #[arg(long)]
        enable_linger: bool,
    },
    Disable {
        #[arg(long)]
        directory: PathBuf,
    },
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Fixed systemd entry point; invokes the normal runtime checks before serving.
    Run {
        #[arg(long)]
        directory: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Installation {
    root: PathBuf,
    service: bool,
    profile: String,
    executable: PathBuf,
    executable_digest: String,
    clock_monitor: PathBuf,
    activation_request: Option<Vec<u8>>,
    minimum_signer_generation: Option<u64>,
    unit: String,
    clock_unit: String,
    unit_bytes: String,
    clock_unit_bytes: String,
}
fn quoted(path: &Path) -> Result<String> {
    files::safe_path(path)?;
    ensure!(path.is_absolute(), "Managed paths must be absolute");
    Ok(format!(
        "\"{}\"",
        path.to_str().context("UTF8 path required")?
    ))
}
fn unit_name(root: &Path, clock: bool) -> String {
    format!(
        "HyperNet{}{}.service",
        if clock { "Clock" } else { "Runtime" },
        &files::hex_digest(root.as_os_str().as_encoded_bytes())[..24]
    )
}
fn profile(root: &Path, service: bool) -> Result<(Manifest, String, PathBuf)> {
    if service {
        let (p, s) = services::load(root)?;
        ensure!(
            s.consented && !s.withdrawn,
            "Explicit unwithdrawn local consent required"
        );
        Ok((p.manifest.clone(), p.digest()?, p.clock_directory))
    } else {
        let (p, s) = model::load(root)?;
        ensure!(
            s.accepted_consent.is_some() && s.withdrawal_generation == 0,
            "Explicit unwithdrawn local consent required"
        );
        Ok((
            p.manifest.canonical()?,
            p.configuration_digest()?,
            p.clock_directory,
        ))
    }
}
fn candidate(options: Options, service: bool) -> Result<Installation> {
    let root = files::root(&options.directory)?;
    let (manifest, profile, clock_export) = profile(&root, service)?;
    ensure!(
        manifest.session_mode == 1 && manifest.clock.kernel_boot == "CurrentHost",
        "Managed boot requires explicit finite Managed consent; use a reviewed stopped successor first"
    );
    let clock_monitor = files::root(&options.clock_monitor)?;
    let clock_config: Value = files::json(&clock_monitor.join("ClockConfig.json"))?;
    ensure!(
        clock_config["exportDirectory"].as_str() == clock_export.to_str(),
        "Monitor does not export the approved clock directory"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_digest = files::executable(&executable)?;
    ensure!(
        executable_digest == hex::encode(manifest.software_digest),
        "Managed executable differs from explicit consent"
    );
    ensure!(
        files::now()?.checked_mul(1000).context("Time overflow")? < manifest.validity.1,
        "Managed consent expired"
    );
    let activation_request = if service {
        ensure!(
            options.minimum_signer_generation.is_none(),
            "Service does not accept an authority signer floor"
        );
        let input = options
            .activation_request
            .as_ref()
            .context("Managed service needs its exact signed activation request")?;
        let bytes = files::read(input, crate::trust_wire::MAXIMUM)?;
        let request = crate::authority_runtime_activation::Request::parse(&bytes)?;
        ensure!(
            request.operation().recipient == manifest.roles[0].service_key,
            "Activation has another service recipient"
        );
        Some(bytes)
    } else {
        ensure!(
            options.activation_request.is_none(),
            "Authority does not take a service activation request"
        );
        ensure!(options.minimum_signer_generation.is_some_and(|v| v>0 && model::signer_generation(&root).is_ok_and(|old|v>=old)),
            "Managed authority requires its independently retained signer generation");
        None
    };
    let unit = unit_name(&root, false);
    let clock_unit = unit_name(&clock_monitor, true);
    let exe = quoted(&executable)?;
    let runtime = if service {
        "runtime services managed run"
    } else {
        "runtime managed run"
    };
    let unit_bytes = format!(
        "[Unit]\nDescription=HyperNet consented runtime\nRequires={clock_unit}\nAfter={clock_unit}\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart={exe} {runtime} --directory {}\nKillMode=mixed\nTimeoutStopSec=90\nUMask=0077\nDelegate=yes\nRestart=no\nEnvironment=TMPDIR={}\n\n[Install]\nWantedBy=default.target\n",
        quoted(&root)?,
        quoted(&root.join("Temporary"))?
    );
    let clock_executable = options
        .clock_executable
        .unwrap_or_else(|| executable.clone());
    files::executable(&clock_executable)?;
    let clock_exe = quoted(&clock_executable)?;
    let clock_unit_bytes = format!(
        "[Unit]\nDescription=HyperNet signed clock monitor\nStopWhenUnneeded=yes\n\n[Service]\nType=simple\nExecStart={clock_exe} authority-clock monitor --directory {}\nUMask=0077\nRestart=on-failure\nRestartSec=5\n",
        quoted(&clock_monitor)?
    );
    Ok(Installation {
        root,
        service,
        profile,
        executable,
        executable_digest,
        clock_monitor,
        activation_request,
        minimum_signer_generation: options.minimum_signer_generation,
        unit,
        clock_unit,
        unit_bytes,
        clock_unit_bytes,
    })
}
fn preview(i: &Installation) -> Result<Value> {
    Ok(
        json!({"status":"ManagedPreview","previewDigest":files::hex_digest(&serde_json::to_vec(i)?),
        "profileDigest":i.profile,"unit":i.unit,"clockUnit":i.clock_unit,"unitContents":i.unit_bytes,
        "clockUnitContents":i.clock_unit_bytes,"logout":"Continues only with explicit user lingering",
        "boot":"Pinned monitor authenticates the actual kernel boot; finite consent and normal authority checks still apply",
        "failure":"Failed boot remains stopped; correct the reported dependency and explicitly restart the unit"}),
    )
}
fn systemctl(arguments: &[String]) -> Result<Vec<u8>> {
    let mut args = vec!["--user".into()];
    args.extend_from_slice(arguments);
    files::capture(Path::new("/usr/bin/systemctl"), &args, 120, 16384, 16384).map(|v| v.0)
}
fn user_name() -> Result<String> {
    let bytes = files::capture(
        Path::new("/usr/bin/id"),
        &files::strings(&["-un"]),
        5,
        256,
        1024,
    )?
    .0;
    let user = String::from_utf8(bytes)?.trim().to_string();
    ensure!(
        !user.is_empty()
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "Unsupported local account name"
    );
    Ok(user)
}
fn linger(enable: bool) -> Result<()> {
    let user = user_name()?;
    if enable {
        files::capture(
            Path::new("/usr/bin/loginctl"),
            &files::strings(&["enable-linger", &user]),
            120,
            4096,
            8192,
        )?;
    }
    let out = files::capture(
        Path::new("/usr/bin/loginctl"),
        &files::strings(&["show-user", &user, "--property=Linger", "--value"]),
        10,
        128,
        4096,
    )?
    .0;
    ensure!(
        out == b"yes\n",
        "Boot and logout persistence require user lingering; review --enable-linger or have the host administrator enable it"
    );
    Ok(())
}
fn load(root: &Path, service: bool) -> Result<Installation> {
    let i: Installation = files::json(&root.join("Managed.json"))?;
    ensure!(
        i.root == root
            && i.service == service
            && i.unit == unit_name(root, false)
            && i.clock_unit == unit_name(&i.clock_monitor, true),
        "Managed installation identity differs"
    );
    Ok(i)
}
fn check(i: &Installation) -> Result<Manifest> {
    let (manifest, digest, _) = profile(&i.root, i.service)?;
    ensure!(
        digest == i.profile
            && manifest.session_mode == 1
            && manifest.clock.kernel_boot == "CurrentHost"
            && files::executable(&std::env::current_exe()?.canonicalize()?)? == i.executable_digest
            && i.executable_digest == hex::encode(manifest.software_digest),
        "Managed unit is stale; review and enable its exact successor"
    );
    Ok(manifest)
}
fn run_installed(root: &Path, service: bool) -> Result<Value> {
    let i = load(root, service)?;
    let manifest = check(&i)?;
    let (_, _, clock) = profile(root, service)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        check(&i)?;
        ensure!(
            files::now()?.checked_mul(1000).context("Time overflow")? < manifest.validity.1,
            "Managed consent expired"
        );
        let source = crate::authority_clock_handoff::Source::Signed {
            path: clock.join(&manifest.clock.witness_file_name),
            public_key: hex::encode(manifest.clock.monitor_key),
            kernel_boot: manifest.clock.kernel_boot.clone(),
        };
        if source.health().and_then(|health| health.observe()).is_ok() {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "Pinned monitor did not establish current boot clock health; runtime remains stopped"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    if service {
        {
            let _lock = files::lock(root)?;
            let (p, mut s) = services::load(root)?;
            services::control::stop(&p, &mut s)?;
        }
        let request = root.join("ManagedActivation.cbor");
        let bytes = i
            .activation_request
            .context("Managed activation request absent")?;
        crate::authority_files::atomic_at(
            &crate::authority_files::private_directory(root)?,
            std::ffi::OsStr::new("ManagedActivation.cbor"),
            &bytes,
            true,
        )?;
        services::control::start(root, &request)
    } else {
        super::serve_managed(
            root,
            i.minimum_signer_generation
                .context("Managed signer floor absent")?,
        )?;
        Ok(json!({"status":"Stopped"}))
    }
}
pub(super) fn run(command: Command, service: bool) -> Result<Value> {
    match command {
        Command::Preview(options) => preview(&candidate(options, service)?),
        Command::Enable {
            options,
            preview_digest,
            enable_linger,
        } => {
            let i = candidate(options, service)?;
            ensure!(
                preview(&i)?["previewDigest"] == preview_digest,
                "Managed preview changed"
            );
            let _lock = files::lock(&i.root)?;
            let _manager = files::manager_lock(&i.root.join("Manager"))?;
            let (manifest, _, _) = profile(&i.root, service)?;
            crate::runtime_audit::record(&i.root, &manifest, "ManagedEnable", "Prepared")?;
            linger(enable_linger)?;
            if !i.root.join("Temporary").try_exists()? {
                files::directory(&i.root.join("Temporary"))?;
            }
            files::private_dir(&i.root.join("Temporary"))?;
            let units = [
                (i.root.join(&i.unit), &i.unit_bytes),
                (i.clock_monitor.join(&i.clock_unit), &i.clock_unit_bytes),
            ];
            for (path, bytes) in &units {
                let parent = crate::authority_files::private_directory(path.parent().unwrap())?;
                if path.try_exists()? {
                    let old = files::read(path, 16384)?;
                    if old != bytes.as_bytes() {
                        ensure!(
                            path == &units[0].0,
                            "Shared clock unit differs; stop its dependent runtimes before an executable cutover"
                        );
                    }
                }
                crate::authority_files::atomic_at(
                    &parent,
                    path.file_name().unwrap(),
                    bytes.as_bytes(),
                    true,
                )?;
            }
            files::save(&i.root.join("Managed.json"), &i)?;
            systemctl(&[
                "link".into(),
                units[1].0.to_str().unwrap().into(),
                units[0].0.to_str().unwrap().into(),
            ])?;
            systemctl(&files::strings(&["daemon-reload"]))?;
            systemctl(&files::strings(&["enable", &i.unit]))?;
            drop(_manager);
            drop(_lock);
            systemctl(&files::strings(&["start", &i.unit]))?;
            if let Err(error) =
                crate::runtime_audit::record(&i.root, &manifest, "ManagedEnable", "Committed")
            {
                let cleanup = systemctl(&files::strings(&["disable", "--now", &i.unit]));
                crate::runtime_audit::restrictive(&i.root, &manifest, "ManagedEnable", "Failed");
                let outcome = match cleanup {
                    Ok(_) => "The owned runtime unit was disabled and stopped".to_owned(),
                    Err(cleanup) => format!(
                        "The owned runtime unit could not be confirmed disabled and stopped: {cleanup:#}"
                    ),
                };
                return Err(error.context(format!(
                    "Managed activation audit completion failed. {outcome}; retained consent and other user units are unchanged"
                )));
            }
            Ok(
                json!({"status":"ManagedEnabled","unit":i.unit,"readiness":"Inspect runtime status; unit activation alone grants no network permission"}),
            )
        }
        Command::Disable { directory } => {
            let root = files::root(&directory)?;
            let i = load(&root, service)?;
            let manifest = Manifest::parse(&files::public_read(
                &root.join("Authorization/Manifest.cbor"),
                crate::runtime_manifest::MAXIMUM,
            )?)?;
            crate::runtime_audit::restrictive(&root, &manifest, "ManagedDisable", "Prepared");
            systemctl(&files::strings(&["disable", "--now", &i.unit]))?;
            crate::runtime_audit::restrictive(&root, &manifest, "ManagedDisable", "Committed");
            Ok(
                json!({"status":"ManagedDisabled","unit":i.unit,"consent":"Retained; withdrawal is separate","lingering":"Unchanged because other user services may require it"}),
            )
        }
        Command::Status { directory } => {
            let root = files::root(&directory)?;
            let i = load(&root, service)?;
            let output = systemctl(&files::strings(&[
                "show",
                &i.unit,
                "--property=ActiveState,SubState,Result,UnitFileState",
            ]))?;
            Ok(
                json!({"unit":i.unit,"profileCurrent":check(&i).is_ok(),"manager":String::from_utf8(output)?}),
            )
        }
        Command::Run { directory } => run_installed(&files::root(&directory)?, service),
    }
}
