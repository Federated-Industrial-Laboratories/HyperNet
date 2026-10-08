// SPDX-License-Identifier: MIT
use crate::{
    policy::{PolicyInput, effective},
    protocol::{VerifiedRequest, fixed_hex},
    types::*,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const MAX_MEMBERS: usize = 1024;
const MAX_INVITATIONS: usize = 1024;
const MAX_RECEIPTS: usize = 2048;
const MAX_DURATION: u64 = 7 * 24 * 60 * 60;

fn grants(member: &Member, now: u64, epoch: u64) -> u64 {
    effective(PolicyInput {
        requested: ALL,
        network: member.grants,
        user: ALL,
        host: ALL,
        application: ALL,
        now,
        expires: member.expires,
        current_epoch: epoch,
        minimum_epoch: epoch,
        host_active: !member.revoked,
    })
}

fn require(state: &State, key: &str, mask: u64, now: u64) -> Result<(), &'static str> {
    let member = state.members.get(key).ok_or("NotMember")?;
    if grants(member, now, state.epoch) & mask != mask {
        return Err("PermissionDenied");
    }
    Ok(())
}

fn validate_grants(mask: u64) -> Result<(), &'static str> {
    if mask & !ALL != 0 || mask & MEMBER == 0 {
        return Err("InvalidGrant");
    }
    Ok(())
}

fn valid_expiry(expires: u64, now: u64) -> Result<(), &'static str> {
    if expires <= now || expires > now.saturating_add(MAX_DURATION) {
        return Err("InvalidExpiry");
    }
    Ok(())
}

fn preserve_admin(
    state: &State,
    target: &str,
    mask: u64,
    expires: u64,
    now: u64,
) -> Result<(), &'static str> {
    if mask & ADMIN != 0 && expires > now {
        return Ok(());
    }
    if state
        .members
        .iter()
        .any(|(key, member)| key != target && grants(member, now, state.epoch) & ADMIN != 0)
    {
        return Ok(());
    }
    Err("LastAdministrator")
}

fn check_existing_permission(
    state: &State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
) -> Result<(), &'static str> {
    match &request.request.command {
        Command::Redeem { .. } => Ok(()),
        Command::Withdraw => {
            if state.members.contains_key(&request.key) {
                Ok(())
            } else {
                Err("NotMember")
            }
        }
        Command::Invite { .. } | Command::Grant { .. } | Command::Revoke { .. } => {
            require(state, &request.key, ADMIN | MEMBER, now)
        }
        Command::Consent { .. } => require(state, &request.key, HOST | MEMBER, now),
        Command::Heartbeat { profile } => {
            require(state, &request.key, HOST | MEMBER, now)?;
            let consent = state.consents.get(&request.key).ok_or("ConsentRequired")?;
            if !consent.active
                || consent.expires <= now
                || consent.profile != *profile
                || consent.grants & HOST == 0
            {
                return Err("ConsentRequired");
            }
            if certificate != Some(consent.certificate.as_str()) {
                return Err("ClientCertificateRequired");
            }
            Ok(())
        }
        Command::Status { device_key } => {
            require(state, &request.key, MEMBER, now)?;
            if device_key.as_deref().is_some_and(|key| key != request.key) {
                require(state, &request.key, ADMIN, now)?;
            }
            Ok(())
        }
    }
}

// The caller commits this transition with a compare against the read revision.
pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
) -> Result<Reply, &'static str> {
    if state.version != 1 {
        return Err("UnsupportedState");
    }
    if state.high_water_time > now.saturating_add(2) {
        return Err("ClockRollback");
    }
    check_existing_permission(state, request, certificate, now)?;
    let receipt_key = format!("{}:{}", request.key, request.request.request_id);
    if let Some(receipt) = state.receipts.get(&receipt_key) {
        if receipt.digest != request.digest {
            return Err("RequestConflict");
        }
        if matches!(request.request.command, Command::Redeem { .. }) {
            require(state, &request.key, MEMBER, now)?;
        }
        state.high_water_time = state.high_water_time.max(now);
        return Ok(receipt.reply.clone());
    }
    state.receipts.retain(|_, receipt| receipt.expires >= now);
    let read_only = matches!(
        request.request.command,
        Command::Status { .. } | Command::Heartbeat { .. }
    );
    if !read_only && state.receipts.len() >= MAX_RECEIPTS {
        return Err("CapacityExceeded");
    }
    let mut changed = false;
    let result = match &request.request.command {
        Command::Status { device_key } => {
            let key = device_key.as_deref().unwrap_or(&request.key);
            fixed_hex::<32>(key)?;
            let member = state.members.get(key).ok_or("NotMember")?;
            let mut result = json!({"deviceKey":key,"member":member,"consent":state.consents.get(key),"authorityRevision":revision});
            if state
                .members
                .get(&request.key)
                .is_some_and(|member| grants(member, now, state.epoch) & ADMIN != 0)
            {
                result["memberCount"] = json!(state.members.len());
                result["invitationCount"] = json!(state.invitations.len());
            }
            result
        }
        Command::Invite {
            verifier,
            device_key,
            grants: mask,
            expires,
        } => {
            fixed_hex::<32>(verifier)?;
            fixed_hex::<32>(device_key)?;
            validate_grants(*mask)?;
            if let Some(existing) = state.invitations.get(verifier) {
                if existing.issuer != request.key
                    || existing.device_key != *device_key
                    || existing.grants != *mask
                    || existing.expires != *expires
                {
                    return Err("InvitationExists");
                }
            } else {
                valid_expiry(*expires, now)?;
                if state.members.contains_key(device_key) {
                    return Err("DeviceExists");
                }
                if state.invitations.len() >= MAX_INVITATIONS {
                    return Err("CapacityExceeded");
                }
                state.invitations.insert(
                    verifier.clone(),
                    Invitation {
                        issuer: request.key.clone(),
                        device_key: device_key.clone(),
                        grants: *mask,
                        expires: *expires,
                        redeemed: false,
                    },
                );
                changed = true;
            }
            json!({"verifier":verifier,"deviceKey":device_key,"grants":mask,"expires":expires})
        }
        Command::Redeem { secret } => {
            let secret = fixed_hex::<32>(secret)?;
            let verifier = hex::encode(Sha256::digest(secret));
            let invitation = state
                .invitations
                .get(&verifier)
                .ok_or("InvalidInvitation")?
                .clone();
            if invitation.device_key != request.key {
                return Err("InvalidInvitation");
            }
            if invitation.redeemed {
                let member = state.members.get(&request.key).ok_or("InvalidInvitation")?;
                if grants(member, now, state.epoch) & MEMBER == 0 {
                    return Err("PermissionDenied");
                }
            } else {
                if invitation.expires <= now {
                    return Err("InvalidInvitation");
                }
                require(state, &invitation.issuer, ADMIN | MEMBER, now)?;
                if state.members.contains_key(&request.key) {
                    return Err("DeviceExists");
                }
                if state.members.len() >= MAX_MEMBERS {
                    return Err("CapacityExceeded");
                }
                state
                    .invitations
                    .get_mut(&verifier)
                    .ok_or("InvalidInvitation")?
                    .redeemed = true;
                state.members.insert(
                    request.key.clone(),
                    Member {
                        grants: invitation.grants,
                        expires: invitation.expires,
                        revoked: false,
                    },
                );
                changed = true;
            }
            json!({"deviceKey":request.key,"member":state.members.get(&request.key)})
        }
        Command::Grant {
            device_key,
            grants: mask,
            expires,
        } => {
            fixed_hex::<32>(device_key)?;
            validate_grants(*mask)?;
            valid_expiry(*expires, now)?;
            preserve_admin(state, device_key, *mask, *expires, now)?;
            let member = state.members.get_mut(device_key).ok_or("NotMember")?;
            if member.revoked {
                return Err("PermanentlyRevoked");
            }
            member.grants = *mask;
            member.expires = *expires;
            changed = true;
            json!({"deviceKey":device_key,"member":member})
        }
        Command::Revoke { device_key } => {
            fixed_hex::<32>(device_key)?;
            preserve_admin(state, device_key, 0, 0, now)?;
            let member = state.members.get_mut(device_key).ok_or("NotMember")?;
            member.revoked = true;
            member.grants = 0;
            if let Some(consent) = state.consents.get_mut(device_key) {
                consent.active = false;
            }
            changed = true;
            json!({"deviceKey":device_key,"revoked":true})
        }
        Command::Consent {
            profile,
            grants: mask,
            expires,
            certificate,
        } => {
            fixed_hex::<32>(profile)?;
            fixed_hex::<32>(certificate)?;
            valid_expiry(*expires, now)?;
            if *mask != HOST {
                return Err("InvalidGrant");
            }
            let member = state.members.get(&request.key).ok_or("NotMember")?;
            if *expires > member.expires {
                return Err("InvalidExpiry");
            }
            state.consents.insert(
                request.key.clone(),
                Consent {
                    profile: profile.clone(),
                    grants: *mask,
                    expires: *expires,
                    certificate: certificate.clone(),
                    active: true,
                },
            );
            changed = true;
            json!({"deviceKey":request.key,"consent":state.consents.get(&request.key)})
        }
        Command::Withdraw => {
            if let Some(consent) = state.consents.get_mut(&request.key) {
                consent.active = false;
            }
            changed = true;
            json!({"deviceKey":request.key,"active":false})
        }
        Command::Heartbeat { profile } => {
            let member = state.members.get(&request.key).ok_or("NotMember")?;
            let consent = state.consents.get(&request.key).ok_or("ConsentRequired")?;
            let expiry = member
                .expires
                .min(consent.expires)
                .min(now.saturating_add(5));
            let mask = effective(PolicyInput {
                requested: HOST,
                network: member.grants,
                user: ALL,
                host: consent.grants,
                application: HOST,
                now,
                expires: expiry,
                current_epoch: state.epoch,
                minimum_epoch: state.epoch,
                host_active: consent.active && !member.revoked,
            });
            if mask != HOST {
                return Err("PermissionDenied");
            }
            json!({"effectiveGrants":mask,"leaseExpires":expiry,"profile":profile,"authorityRevision":revision})
        }
    };
    if changed {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }
    state.high_water_time = state.high_water_time.max(now);
    let reply = Reply::success(state.epoch, result);
    if !read_only {
        state.receipts.insert(
            receipt_key,
            Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(key: &str, id: u8, command: Command) -> VerifiedRequest {
        VerifiedRequest {
            key: key.into(),
            digest: format!("Digest{id}"),
            request: Request {
                version: 1,
                request_id: hex::encode([id; 16]),
                issued_at: 100,
                command,
            },
        }
    }
    fn setup() -> (State, String, String) {
        let admin = hex::encode([1; 32]);
        let user = hex::encode([2; 32]);
        (
            State::initial(hex::encode([9; 32]), admin.clone(), 100),
            admin,
            user,
        )
    }
    fn enrol(state: &mut State, admin: &str, user: &str) {
        apply(
            state,
            &request(
                admin,
                1,
                Command::Invite {
                    verifier: hex::encode(Sha256::digest([5; 32])),
                    device_key: user.into(),
                    grants: 3,
                    expires: 1000,
                },
            ),
            None,
            100,
            1,
        )
        .unwrap();
        apply(
            state,
            &request(
                user,
                2,
                Command::Redeem {
                    secret: hex::encode([5; 32]),
                },
            ),
            None,
            100,
            2,
        )
        .unwrap();
    }
    #[test]
    fn invitation_cannot_change_key_or_resurrect_revocation() {
        let (mut state, admin, user) = setup();
        enrol(&mut state, &admin, &user);
        assert!(
            apply(
                &mut state,
                &request(
                    &hex::encode([7; 32]),
                    3,
                    Command::Redeem {
                        secret: hex::encode([5; 32])
                    }
                ),
                None,
                100,
                3
            )
            .is_err()
        );
        assert!(
            apply(
                &mut state,
                &request(
                    &user,
                    4,
                    Command::Redeem {
                        secret: hex::encode([5; 32])
                    }
                ),
                None,
                100,
                4
            )
            .is_ok()
        );
        apply(
            &mut state,
            &request(
                &admin,
                5,
                Command::Revoke {
                    device_key: user.clone(),
                },
            ),
            None,
            100,
            5,
        )
        .unwrap();
        assert!(
            apply(
                &mut state,
                &request(
                    &user,
                    6,
                    Command::Redeem {
                        secret: hex::encode([5; 32])
                    }
                ),
                None,
                100,
                6
            )
            .is_err()
        );
        assert!(
            apply(
                &mut state,
                &request(
                    &admin,
                    7,
                    Command::Grant {
                        device_key: user,
                        grants: 3,
                        expires: 1000
                    }
                ),
                None,
                100,
                7
            )
            .is_err()
        );
    }
    #[test]
    fn hosting_needs_matching_certificate_consent_and_current_grants() {
        let (mut state, admin, user) = setup();
        enrol(&mut state, &admin, &user);
        let profile = hex::encode([3; 32]);
        let cert = hex::encode([4; 32]);
        apply(
            &mut state,
            &request(
                &user,
                3,
                Command::Consent {
                    profile: profile.clone(),
                    grants: HOST,
                    expires: 900,
                    certificate: cert.clone(),
                },
            ),
            None,
            100,
            3,
        )
        .unwrap();
        let heartbeat = request(
            &user,
            4,
            Command::Heartbeat {
                profile: profile.clone(),
            },
        );
        assert!(apply(&mut state, &heartbeat, None, 100, 4).is_err());
        let reply = apply(&mut state, &heartbeat, Some(&cert), 100, 4).unwrap();
        assert_eq!(reply.result["leaseExpires"], 105);
        apply(
            &mut state,
            &request(&user, 5, Command::Withdraw),
            None,
            100,
            5,
        )
        .unwrap();
        assert!(apply(&mut state, &heartbeat, Some(&cert), 100, 6).is_err());
        assert!(
            apply(
                &mut state,
                &request(&user, 6, Command::Heartbeat { profile }),
                Some(&cert),
                100,
                6
            )
            .is_err()
        );
    }
    #[test]
    fn mutation_retries_survive_unrelated_changes_and_reads_stay_current() {
        let (mut state, admin, user) = setup();
        enrol(&mut state, &admin, &user);
        let original = request(
            &user,
            2,
            Command::Redeem {
                secret: hex::encode([5; 32]),
            },
        );
        let old_epoch = state.epoch;
        apply(
            &mut state,
            &request(
                &admin,
                3,
                Command::Grant {
                    device_key: user.clone(),
                    grants: MEMBER,
                    expires: 900,
                },
            ),
            None,
            100,
            3,
        )
        .unwrap();
        let replay = apply(&mut state, &original, None, 100, 4).unwrap();
        assert_eq!(replay.epoch, old_epoch);
        let receipts = state.receipts.len();
        let status = request(&user, 4, Command::Status { device_key: None });
        let reply = apply(&mut state, &status, None, 100, 5).unwrap();
        assert_eq!(reply.result["member"]["grants"], MEMBER);
        assert_eq!(state.receipts.len(), receipts);
        apply(
            &mut state,
            &request(&admin, 5, Command::Revoke { device_key: user }),
            None,
            100,
            6,
        )
        .unwrap();
        assert!(apply(&mut state, &status, None, 100, 7).is_err());
        assert!(apply(&mut state, &original, None, 100, 8).is_err());
    }
    #[test]
    fn clock_rollback_and_last_admin_changes_fail_closed() {
        let (mut state, admin, _) = setup();
        assert_eq!(
            apply(
                &mut state,
                &request(&admin, 1, Command::Status { device_key: None }),
                None,
                97,
                1
            )
            .err(),
            Some("ClockRollback")
        );
        assert_eq!(
            apply(
                &mut state,
                &request(
                    &admin,
                    2,
                    Command::Revoke {
                        device_key: admin.clone()
                    }
                ),
                None,
                100,
                1
            )
            .err(),
            Some("LastAdministrator")
        );
    }
}
