// SPDX-License-Identifier: MIT
//! Renew signed route consent without changing permanent bindings, exposure or budgets.
use super::{files, services};
use crate::{
    authority_domains::{routes::RegisteredProfile, streams},
    route_config::Configuration,
    runtime_manifest::Manifest,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    route_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_configuration: Option<String>,
}
impl Selection {
    pub(super) fn bytes(&self) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        ensure!(
            self.route_profile.len() <= 65536
                && self
                    .application_configuration
                    .as_ref()
                    .is_none_or(|v| v.len() <= 32768),
            "Renewed route artifacts exceed their bounds"
        );
        let route = hex::decode(&self.route_profile)?;
        let configuration = self
            .application_configuration
            .as_ref()
            .map(hex::decode)
            .transpose()?;
        ensure!(
            hex::encode(&route) == self.route_profile
                && configuration.as_ref().map(hex::encode) == self.application_configuration,
            "Noncanonical renewed route encoding"
        );
        Ok((route, configuration))
    }
}
pub(super) fn prepare(
    root: &Path,
    service: bool,
    successor: &Manifest,
    route: Option<&Path>,
    configuration: Option<&Path>,
) -> Result<Option<Selection>> {
    let Some(route) = route else {
        ensure!(
            configuration.is_none(),
            "Application renewal requires its exact route profile"
        );
        return Ok(None);
    };
    ensure!(service, "Authority successors cannot change route bindings");
    let selection = Selection {
        route_profile: hex::encode(files::public_read(route, 32768)?),
        application_configuration: configuration
            .map(|p| files::public_read(p, 16384).map(hex::encode))
            .transpose()?,
    };
    validate(root, successor, &selection)?;
    Ok(Some(selection))
}
fn same_route(
    old: &RegisteredProfile,
    new: &RegisteredProfile,
    successor: &Manifest,
) -> Result<()> {
    successor.permits_definition(&new.manifest)?;
    let certificates_changed = successor.transport_changed(&old.manifest);
    let identity_matches = new.identity == old.identity
        || certificates_changed && new.identity.certificate_successor_of(&old.identity).is_ok();
    ensure!(
        new.manifest.generation >= old.manifest.generation
            && new.deployment == old.deployment
            && new.service == old.service
            && new.operator == old.operator
            && new.endpoint == old.endpoint
            && identity_matches
            && new.address == old.address
            && new.domain == old.domain
            && new.protocol == old.protocol
            && new.mode == old.mode
            && new.relay == old.relay
            && new.limits == old.limits
            && new.maximum_connections == old.maximum_connections
            && new.assurance == old.assurance,
        "Route renewal cannot change identity, operator, endpoint, privacy, protocol or budgets"
    );
    ensure!(
        new.validity.1 <= successor.validity.1,
        "Renewed route exceeds successor hosting consent"
    );
    Ok(())
}
fn same_configuration(
    old: &Configuration,
    new: &Configuration,
    route: &RegisteredProfile,
    manifest: &Manifest,
) -> Result<()> {
    let relay_matches = old.relay_identity == new.relay_identity
        || match (&old.relay_identity, &new.relay_identity) {
            (Some(before), Some(after)) if manifest.transport_certificates.is_some() => {
                after.certificate_successor_of(before).is_ok()
            }
            _ => false,
        };
    ensure!(
        old.version == new.version && relay_matches && old.relay_address == new.relay_address,
        "Renewal cannot change relay transport or route mode"
    );
    match (&old.application, &new.application) {
        (None, None) => Ok(()),
        (Some(old), Some(new)) => {
            ensure!(
                old.binding == new.binding,
                "Renewal cannot change the local application binding"
            );
            let before = streams::Registration::parse(
                &old.registration,
                manifest.network,
                manifest.incarnation,
            )?;
            let after = streams::Registration::parse(
                &new.registration,
                manifest.network,
                manifest.incarnation,
            )?;
            new.binding.registration(&after, route)?;
            ensure!(
                after.id == before.id
                    && after.owner == before.owner
                    && after.operator == before.operator
                    && after.protocol == before.protocol
                    && after.binding == before.binding
                    && after.limits == before.limits
                    && after.route.id == before.route.id
                    && after.route.generation >= before.route.generation
                    && after.validity.0 >= route.validity.0
                    && after.validity.1 <= route.validity.1,
                "Application renewal cannot change owner, scope or limits and must remain within the renewed route"
            );
            Ok(())
        }
        _ => anyhow::bail!("Renewal cannot add or remove an application binding"),
    }
}
pub(super) fn validate(root: &Path, successor: &Manifest, selection: &Selection) -> Result<()> {
    let (profile, state) = services::load(root)?;
    ensure!(
        !state.withdrawn
            && state.consented
            && state.container.is_none()
            && state.helper.is_none()
            && state.egress.is_none()
            && state.network.is_none(),
        "Stop every owned service resource before reviewing binding renewal"
    );
    ensure!(
        profile.role()?.role == 5,
        "Binding renewal requires a role5 service"
    );
    for name in ["RouteProfile.cbor", "ServiceConfig.json"] {
        let bytes = files::read(&root.join("Config").join(name), 32768)?;
        ensure!(
            profile.artifacts.get(name) == Some(&crate::trust_wire::digest(&bytes)),
            "Preceding route or application configuration differs from recorded consent"
        );
    }
    let old_route = RegisteredProfile::parse(
        &files::read(&root.join("Config/RouteProfile.cbor"), 32768)?,
        successor.network,
        successor.incarnation,
    )?;
    let old_configuration = files::read(&root.join("Config/ServiceConfig.json"), 16384)?;
    let (route, configuration) = selection.bytes()?;
    let new_route = RegisteredProfile::parse(&route, successor.network, successor.incarnation)?;
    same_route(&old_route, &new_route, successor)?;
    let before: Configuration = serde_json::from_slice(&old_configuration)?;
    ensure!(
        if before.application.is_some() {
            configuration.is_some()
        } else {
            configuration.is_none() || successor.transport_changed(&old_route.manifest)
        },
        "Application routes require renewed owner consent; other configuration changes require an exact certificate successor"
    );
    let configuration = configuration.as_deref().unwrap_or(&old_configuration);
    let after: Configuration = serde_json::from_slice(configuration)?;
    same_configuration(&before, &after, &new_route, successor)?;
    profile.validate_route_successor(successor, &route, configuration)
}
pub(super) fn summary(selection: &Selection, successor: &Manifest) -> Result<Value> {
    let (bytes, configuration) = selection.bytes()?;
    let route = RegisteredProfile::parse(&bytes, successor.network, successor.incarnation)?;
    let application = configuration.as_ref().map(|bytes| -> Result<Option<Value>> {
        let config: Configuration = serde_json::from_slice(bytes)?;
        let Some(binding) = config.application else { return Ok(None) };
        let registration = streams::Registration::parse(&binding.registration, successor.network, successor.incarnation)?;
        Ok(Some(json!({"service":hex::encode(registration.id),"owner":hex::encode(registration.owner),
            "validFromMs":registration.validity.0,"validUntilMs":registration.validity.1,
            "routeGeneration":registration.route.generation,"configurationSha256":files::hex_digest(bytes)})))
    }).transpose()?.flatten();
    Ok(
        json!({"routeSha256":files::hex_digest(&bytes),"operator":hex::encode(route.operator),
        "service":hex::encode(route.identity.service),"manifestGeneration":route.manifest.generation,
        "validFromMs":route.validity.0,"validUntilMs":route.validity.1,"application":application,
        "configurationSha256":configuration.as_ref().map(|bytes|files::hex_digest(bytes)),
        "samePermanentIdentity":true,"unchangedExposurePrivacyAndBudgets":true}),
    )
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeTransitionBindingsTests.rs"]
mod tests;
