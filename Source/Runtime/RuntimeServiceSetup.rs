// SPDX-License-Identifier: MIT
// Inert service import precedes the operator's exact local consent and any workload launch.
use super::*;
use crate::{authority_files, runtime_service_authorization, trust_bootstrap};
use ed25519_dalek::SigningKey;
use std::{fs, os::unix::fs::PermissionsExt};
use zeroize::{Zeroize, Zeroizing};
#[derive(Args)]
pub struct Setup {
    #[arg(long)]
    directory: PathBuf,
    /// Directory containing the fixed configuration artifacts for one service role.
    #[arg(long)]
    configuration: PathBuf,
    #[arg(long)]
    operator_key: PathBuf,
    #[arg(long)]
    host_consent: PathBuf,
    #[arg(long)]
    authority_directory: PathBuf,
    #[arg(long)]
    clock_directory: PathBuf,
    /// Exact local content or media service controls exposed to a bridge as HOSTKEY=INSTALLED_DIRECTORY.
    #[arg(long)]
    media_service: Vec<String>,
    /// Exact installed application socket exposed by a route endpoint.
    #[arg(long)]
    route_service: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Identity {
    public_key: String,
    secret_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}
fn key(bytes: &[u8]) -> Result<SigningKey> {
    if bytes.len() == 32 {
        return Ok(SigningKey::from_bytes(bytes.try_into()?));
    }
    let identity: Identity = serde_json::from_slice(bytes)?;
    let seed = Zeroizing::new(trust_bootstrap::hex32(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
        "operator key pair differs"
    );
    Ok(key)
}
fn host_consent(manifest: &Manifest, bytes: &[u8]) -> Result<()> {
    let (payload, signatures) = wire::envelope(bytes, 1)?;
    ensure!(
        payload == manifest.unsigned_consent(0)?
            && signatures.len() == 1
            && signatures[0].0 == manifest.operator,
        "host consent differs from the exact operator manifest"
    );
    Ok(())
}
pub fn run(args: Setup) -> Result<Value> {
    files::safe_path(&args.directory)?;
    ensure!(
        args.directory.is_absolute() && !args.directory.try_exists()?,
        "service setup requires a new absolute directory"
    );
    let parent = args.directory.parent().context("service parent absent")?;
    files::ancestors(parent)?;
    let configuration = files::root(&args.configuration)?;
    let manifest = Manifest::parse(&authority_files::read(
        &configuration.join("Manifest.cbor"),
        wire::MAXIMUM,
        true,
    )?)?;
    ensure!(manifest.roles.len() == 1, "service setup requires one role");
    let expected: &[&str] = match manifest.roles[0].role {
        5 => &[
            "Bootstrap.cbor",
            "Certificate.pem",
            "CertificateAuthority.pem",
            "Manifest.cbor",
            "RouteProfile.cbor",
            "Service.key",
            "ServiceConfig.json",
            "Transport.key",
        ],
        7 => &[
            "Bootstrap.cbor",
            "BridgeProfile.cbor",
            "Certificate.pem",
            "CertificateAuthority.pem",
            "Manifest.cbor",
            "Service.key",
            "ServiceConfig.json",
            "Transport.key",
        ],
        8 => &[
            "AuthorizedKeys",
            "Bootstrap.cbor",
            "Manifest.cbor",
            "Service.key",
            "ServiceConfig.json",
            "SshHostKey",
            "SshProfile.cbor",
            "SshdConfig",
        ],
        4 => &[
            "Bootstrap.cbor",
            "Manifest.cbor",
            "Service.key",
            "ServiceConfig.json",
            "TransferProfile.cbor",
        ],
        1 => &[
            "Bootstrap.cbor",
            "Manifest.cbor",
            "PageProfile.cbor",
            "Service.key",
            "ServiceConfig.json",
        ],
        2 => &[
            "Bootstrap.cbor",
            "Manifest.cbor",
            "MediaProfile.cbor",
            "Service.key",
            "ServiceConfig.json",
        ],
        3 => &[
            "Bootstrap.cbor",
            "MailProfile.cbor",
            "Manifest.cbor",
            "Service.key",
            "ServiceConfig.json",
        ],
        _ => anyhow::bail!("service template is not available for this role"),
    };
    let names = fs::read_dir(&configuration)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid service filename"))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        names
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "configuration must contain exactly the fixed service template files"
    );
    let mut data = BTreeMap::new();
    for name in expected {
        data.insert(
            name.to_string(),
            Zeroizing::new(authority_files::read(
                &configuration.join(name),
                wire::MAXIMUM,
                true,
            )?),
        );
    }
    ensure!(
        Manifest::parse(&data["Manifest.cbor"])? == manifest,
        "manifest changed while importing configuration"
    );
    let bootstrap = trust_bootstrap::inspect(&data["Bootstrap.cbor"], true)?;
    ensure!(
        bootstrap.file_digest() == manifest.bootstrap_digest
            && bootstrap.descriptor().scope().network == manifest.network
            && bootstrap.descriptor().scope().incarnation == manifest.incarnation,
        "manifest differs from accepted bootstrap"
    );
    let operator_bytes = Zeroizing::new(authority_files::read(&args.operator_key, 8192, true)?);
    let operator = key(&operator_bytes)?;
    ensure!(
        operator.verifying_key().to_bytes() == manifest.operator,
        "operator identity differs from host consent"
    );
    let host = authority_files::read(&args.host_consent, wire::MAXIMUM, true)?;
    host_consent(&manifest, &host)?;
    let (authority, _) = super::super::model::load(&files::root(&args.authority_directory)?)?;
    ensure!(
        authority.network == hex::encode(manifest.network)
            && authority.incarnation == hex::encode(manifest.incarnation),
        "private authority control belongs to another network"
    );
    files::safe_path(&args.clock_directory)?;
    ensure!(
        args.clock_directory.is_absolute()
            && args.clock_directory.canonicalize()? == args.clock_directory,
        "clock path must be absolute without symbolic links"
    );
    files::ancestors(&args.clock_directory)?;
    let mut media_controls = BTreeMap::new();
    ensure!(
        manifest.roles[0].role == 7 || args.media_service.is_empty(),
        "media mounts require role7"
    );
    for selected in &args.media_service {
        let (key, path) = selected
            .split_once('=')
            .context("media service must be HOSTKEY=INSTALLED_DIRECTORY")?;
        let public = trust_bootstrap::hex32(key)?;
        let directory = files::root(Path::new(path))?;
        let (media, _) = load(&directory)?;
        media.check_artifacts()?;
        store_route(&manifest, &media.manifest, public)?;
        ensure!(
            key == hex::encode(public)
                && media_controls
                    .insert(
                        key.to_string(),
                        MediaMount {
                            directory,
                            profile_digest: media.binding_digest()?
                        }
                    )
                    .is_none(),
            "bridge media control identity repeats"
        );
    }
    if manifest.roles[0].role == 7 {
        let config: Value = serde_json::from_slice(&data["ServiceConfig.json"])?;
        let keys = media_controls
            .keys()
            .map(|k| Value::String(k.clone()))
            .collect::<Vec<_>>();
        ensure!(
            config["mediaHosts"] == Value::Array(keys),
            "bridge configuration media hosts differ from exact selected control mounts"
        );
        data.insert(
            "MediaBindings.json".into(),
            Zeroizing::new(serde_json::to_vec(&media_controls)?),
        );
    }
    ensure!(
        manifest.roles[0].role == 5 || args.route_service.is_none(),
        "application socket mounts require role5"
    );
    let route_target = if let Some(directory) = &args.route_service {
        let directory = files::root(directory)?;
        let (target, _) = load(&directory)?;
        target.check_artifacts()?;
        super::route_target(&manifest, &target.manifest)?;
        Some(MediaMount {
            directory,
            profile_digest: target.binding_digest()?,
        })
    } else {
        None
    };
    if manifest.roles[0].role == 5 {
        crate::route_config::validate_import(
            &manifest,
            &data,
            route_target.as_ref().map(|v| v.directory.as_path()),
        )?;
        let route_profile = crate::authority_domains::routes::RegisteredProfile::parse(
            &data["RouteProfile.cbor"],
            manifest.network,
            manifest.incarnation,
        )?;
        data.insert(
            "Egress.json".into(),
            Zeroizing::new(super::egress::configuration(&manifest, &route_profile)?),
        );
        data.insert(
            "RouteBinding.json".into(),
            Zeroizing::new(serde_json::to_vec(&route_target)?),
        );
    }
    let seccomp = serde_json::to_vec(&super::super::setup::seccomp()?)?;
    data.insert("Seccomp.json".into(), Zeroizing::new(seccomp));
    let profile = Profile {
        version: 1,
        root: args.directory.clone(),
        manifest,
        artifacts: data
            .iter()
            .map(|(n, v)| (n.clone(), wire::digest(v)))
            .collect(),
        authority_control: args.authority_directory.join("Launch/State/Control"),
        clock_directory: args.clock_directory,
        selinux: files::selinux_enabled()?,
        media_controls,
        route_target,
    };
    profile.validate()?;
    ensure!(
        files::executable(&std::env::current_exe()?.canonicalize()?)?
            == hex::encode(profile.manifest.software_digest),
        "manifest software differs from the installed executable"
    );
    let service = key(&data["Service.key"])?;
    ensure!(
        data["Service.key"].len() == 32
            && service.verifying_key().to_bytes() == profile.role()?.service_key,
        "service identity differs from the dedicated role"
    );
    let info: Value = serde_json::from_slice(&files::podman(&files::strings(&[
        "info", "--format", "json",
    ]))?)?;
    ensure!(
        info["host"]["security"]["rootless"] == true
            && info["host"]["cgroupVersion"] == "v2"
            && info["host"]["security"]["selinuxEnabled"] == profile.selinux,
        "installed services require rootless Podman, cgroup v2 and the current SELinux mode"
    );
    files::directory(&profile.root)?;
    for name in ["Config", "Authorization", "Manager"] {
        files::directory(&profile.root.join(name))?;
    }
    fs::set_permissions(
        profile.root.join("Authorization"),
        fs::Permissions::from_mode(0o755),
    )?;
    for (name, bytes) in &data {
        files::create(&profile.root.join("Config").join(name), bytes)?;
    }
    files::create(&profile.root.join("Operator.key"), &operator.to_bytes())?;
    files::publish_public(&profile.root.join("Authorization/HostConsent.cbor"), &host)?;
    files::publish_public(
        &profile.root.join("Authorization/Manifest.cbor"),
        &profile.manifest.encode()?,
    )?;
    files::publish_public(
        &profile.root.join("Authorization/Generation.json"),
        profile.manifest.generation.to_string().as_bytes(),
    )?;
    files::publish_public(&profile.root.join("Authorization/Withdrawal.json"), b"0")?;
    files::save(&profile.root.join("ServiceProfile.json"), &profile)?;
    files::reserve(&profile.root)?;
    let mut state = State {
        version: 1,
        profile_digest: profile.digest()?,
        consented: false,
        withdrawn: false,
        initialised: false,
        container: None,
        network: None,
        helper: None,
        egress: None,
        authority_control: None,
        last_time: files::now()?,
    };
    crate::runtime_audit::initialise(&profile.root, &profile.manifest)?;
    save(&profile, &mut state)?;
    preview(&profile, &state)
}
pub(in crate::runtime_management) fn operator(p: &Profile) -> Result<SigningKey> {
    key(&Zeroizing::new(files::read(
        &p.root.join("Operator.key"),
        32,
    )?))
}
pub fn consent(p: &Profile, s: &mut State, expected: &str) -> Result<Value> {
    p.check_artifacts()?;
    ensure!(
        !s.withdrawn && expected == p.digest()?,
        "review the exact local service profile before consenting"
    );
    host_consent(
        &p.manifest,
        &files::public_read(
            &p.root.join("Authorization/HostConsent.cbor"),
            wire::MAXIMUM,
        )?,
    )?;
    let key = operator(p)?;
    ensure!(
        key.verifying_key().to_bytes() == p.manifest.operator,
        "local operator identity changed"
    );
    let payload = runtime_service_authorization::local_consent(
        &p.manifest,
        p.role()?.role,
        p.manifest.generation,
        &p.artifacts,
    )?;
    crate::runtime_audit::record(&p.root, &p.manifest, "Consent", "Prepared")?;
    files::publish_public(
        &p.root.join("Authorization/LocalConsent.cbor"),
        &wire::sign_envelope(&payload, &key)?,
    )?;
    s.consented = true;
    save(p, s)?;
    crate::runtime_audit::record(&p.root, &p.manifest, "Consent", "Committed")?;
    preview(p, s)
}
