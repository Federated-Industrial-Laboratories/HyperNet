// SPDX-License-Identifier: MIT
// A read-only chrony observation bounds clock error; absence never means healthy.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAXIMUM_ERROR_MS: u64 = 250;
pub const SAMPLE_LIFETIME_MS: u64 = 1000;
const MAXIMUM_PROBE_MS: u64 = 500;
const MAXIMUM_SOURCE_AGE_SECONDS: u64 = 120;
// This is an explicit hardware assumption, not a value inferred from NTP reachability.
const HOLDOVER_PPM: u64 = 1000;

#[derive(Clone, Copy, Debug)]
pub struct Moment {
    pub wall_ms: u64,
    pub boot_ms: u64,
}
pub fn moment() -> Result<Moment> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr()) } == 0,
        "suspend-aware clock unavailable"
    );
    let time = unsafe { time.assume_init() };
    ensure!(
        (0..1_000_000_000).contains(&time.tv_nsec),
        "invalid clock precision"
    );
    let boot_ms = u64::try_from(time.tv_sec)?
        .checked_mul(1000)
        .and_then(|v| v.checked_add(time.tv_nsec as u64 / 1_000_000))
        .context("boot clock overflow")?;
    let wall_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(Moment { wall_ms, boot_ms })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Witness {
    pub(crate) version: u64,
    pub(crate) kernel_boot: String,
    pub(crate) sample_wall_ms: u64,
    pub(crate) sample_boot_ms: u64,
    pub(crate) valid_until_boot_ms: u64,
    pub(crate) maximum_error_ms: u64,
    pub(crate) source: IpAddr,
}
impl Witness {
    /// The file containing this observation must come from the trusted local monitor.
    pub fn health(
        &self,
        kernel_boot: &str,
        now: Moment,
    ) -> Result<crate::authority_challenge::ClockHealth> {
        ensure!(
            self.version == 1 && self.kernel_boot == kernel_boot && valid_boot(kernel_boot),
            "clock observation belongs to another kernel boot"
        );
        ensure!(
            self.valid_until_boot_ms
                == self
                    .sample_boot_ms
                    .checked_add(SAMPLE_LIFETIME_MS)
                    .context("clock validity overflow")?,
            "unsupported clock observation lifetime"
        );
        ensure!(
            now.boot_ms >= self.sample_boot_ms && now.boot_ms < self.valid_until_boot_ms,
            "clock observation is stale"
        );
        let predicted = self
            .sample_wall_ms
            .checked_add(now.boot_ms - self.sample_boot_ms)
            .context("clock progression overflow")?;
        ensure!(
            self.maximum_error_ms
                .checked_add(now.wall_ms.abs_diff(predicted))
                .is_some_and(|e| e <= MAXIMUM_ERROR_MS),
            "clock error exceeds the permitted bound"
        );
        crate::authority_challenge::ClockHealth::new(
            self.sample_wall_ms,
            self.sample_boot_ms,
            self.valid_until_boot_ms,
            self.maximum_error_ms,
        )
    }
}
fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && value
            .bytes()
            .any(|b| (b'1'..=b'9').contains(&b) || (b'a'..=b'f').contains(&b))
}
pub fn kernel_boot() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim_end_matches('\n');
    ensure!(valid_boot(value), "invalid kernel boot identity");
    Ok(value.to_owned())
}

fn rows(text: &str, arity: usize) -> Result<Vec<Vec<&str>>> {
    ensure!(
        text.len() <= 16384 && text.is_ascii() && !text.contains('\r'),
        "invalid chrony report"
    );
    let mut rows = Vec::new();
    for line in text.lines() {
        let row: Vec<_> = line.split(',').collect();
        ensure!(
            row.len() == arity && rows.len() < 16,
            "unsupported chrony report shape"
        );
        rows.push(row);
    }
    ensure!(!rows.is_empty(), "empty chrony report");
    Ok(rows)
}
// Decimal parsing uses checked integers and rounds away from zero. NaN, infinity
// and exponent spellings cannot silently turn an unknown bound into zero.
fn decimal_nanos(text: &str, signed: bool) -> Result<u64> {
    let text = if signed {
        text.strip_prefix('-')
            .or_else(|| text.strip_prefix('+'))
            .unwrap_or(text)
    } else {
        text
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    ensure!(
        !whole.is_empty()
            && whole.len() <= 12
            && fraction.len() <= 12
            && whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit()),
        "invalid chrony decimal"
    );
    let integer: u64 = whole.parse()?;
    let mut fraction_value = 0u64;
    for i in 0..9 {
        fraction_value =
            fraction_value * 10 + fraction.as_bytes().get(i).map_or(0, |b| (b - b'0') as u64);
    }
    if fraction
        .as_bytes()
        .get(9..)
        .is_some_and(|v| v.iter().any(|b| *b != b'0'))
    {
        fraction_value += 1;
    }
    integer
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(fraction_value))
        .context("chrony decimal overflow")
}
fn number(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "invalid chrony integer"
    );
    Ok(text.parse()?)
}
struct Tracking {
    reference: String,
    source: IpAddr,
    reference_ns: u64,
    bound_ns: u64,
}
fn tracking(text: &str, now: Moment) -> Result<Tracking> {
    let rows = rows(text, 14)?;
    ensure!(rows.len() == 1, "ambiguous tracking observation");
    let f = &rows[0];
    ensure!(
        f[0].len() == 8
            && f[0].bytes().all(|b| b.is_ascii_hexdigit())
            && f[0] != "7F7F0101"
            && f[0] != "00000000"
            && f[13] == "Normal"
            && (1..=15).contains(&number(f[2])?),
        "clock is unsynchronised, local, or near an unsupported leap transition"
    );
    let source: IpAddr = f[1].parse()?;
    ensure!(
        !source.is_unspecified() && !source.is_loopback(),
        "external authenticated time source required"
    );
    let reference_ns = decimal_nanos(f[3], false)?;
    let now_ns = now
        .wall_ms
        .checked_mul(1_000_000)
        .context("wall clock overflow")?;
    ensure!(
        reference_ns <= now_ns.saturating_add(MAXIMUM_ERROR_MS * 1_000_000)
            && now_ns.saturating_sub(reference_ns) <= MAXIMUM_SOURCE_AGE_SECONDS * 1_000_000_000,
        "chrony reference sample is stale"
    );
    let offset = decimal_nanos(f[4], true)?;
    decimal_nanos(f[5], true)?;
    decimal_nanos(f[6], false)?;
    decimal_nanos(f[7], true)?;
    decimal_nanos(f[8], true)?;
    let skew_ppm_nanos = decimal_nanos(f[9], false)?;
    ensure!(
        skew_ppm_nanos <= HOLDOVER_PPM * 1_000_000_000,
        "clock frequency uncertainty is too large"
    );
    let delay = decimal_nanos(f[10], false)?;
    let dispersion = decimal_nanos(f[11], false)?;
    decimal_nanos(f[12], false)?;
    let bound_ns = offset
        .checked_add(dispersion)
        .and_then(|v| v.checked_add(delay.div_ceil(2)))
        .context("clock error overflow")?;
    Ok(Tracking {
        reference: f[0].to_owned(),
        source,
        reference_ns,
        bound_ns,
    })
}

fn sources(text: &str) -> Result<BTreeMap<IpAddr, char>> {
    let mut result = BTreeMap::new();
    for f in rows(text, 10)? {
        ensure!(
            f[0] == "^" && matches!(f[1], "*" | "+" | "-" | "?" | "x" | "~"),
            "only authenticated remote server sources are supported"
        );
        let source: IpAddr = f[2].parse()?;
        ensure!(
            !source.is_unspecified() && !source.is_loopback(),
            "invalid remote source"
        );
        if matches!(f[1], "*" | "+") {
            ensure!(
                (1..=15).contains(&number(f[3])?)
                    && u16::from_str_radix(f[5], 8)? > 0
                    && number(f[6])? <= MAXIMUM_SOURCE_AGE_SECONDS,
                "selected source is not fresh"
            );
        }
        ensure!(
            result.insert(source, f[1].as_bytes()[0] as char).is_none(),
            "duplicate time source"
        );
    }
    ensure!(
        result.values().filter(|v| **v == '*').count() == 1,
        "one selected time source required"
    );
    Ok(result)
}
fn authenticate(
    sources: &BTreeMap<IpAddr, char>,
    auth: &str,
    ntp: &str,
    tracking: &Tracking,
) -> Result<()> {
    let mut authenticated = BTreeMap::new();
    for f in rows(auth, 10)? {
        let ip: IpAddr = f[0].parse()?;
        ensure!(
            f[1] == "NTS"
                && number(f[3])? > 0
                && number(f[4])? >= 128
                && authenticated.insert(ip, ()).is_none(),
            "time source lacks NTS authentication"
        );
    }
    ensure!(
        authenticated.keys().eq(sources.keys()),
        "time source authentication set changed"
    );
    let mut verified = BTreeMap::new();
    // Chrony 4.5 has 34 fields. 4.6 adds four timestamp counters after them;
    // neither profile changes the authentication fields checked below.
    let columns = ntp
        .lines()
        .next()
        .context("empty NTP report")?
        .split(',')
        .count();
    ensure!(
        matches!(columns, 34 | 38),
        "unsupported chrony NTP report shape"
    );
    for f in rows(ntp, columns)? {
        let ip: IpAddr = f[0].parse()?;
        ensure!(
            sources.contains_key(&ip) && verified.insert(ip, ()).is_none(),
            "unexpected NTP source"
        );
        if matches!(sources[&ip], '*' | '+') {
            ensure!(
                f[5] == "Normal"
                    && f[6] == "4"
                    && f[7] == "Server"
                    && f[27] == "Yes"
                    && number(f[33])? > 0,
                "selected time sample lacks authenticated NTP evidence"
            );
        }
        if sources[&ip] == '*' {
            ensure!(
                ip == tracking.source && f[1] == tracking.reference,
                "tracking source changed during observation"
            );
        }
    }
    ensure!(
        verified.keys().eq(sources.keys()),
        "incomplete authenticated time evidence"
    );
    Ok(())
}

/// Only the fixed read-only commands reach the locally configured chrony socket.
pub fn probe(mut query: impl FnMut(&str) -> Result<String>) -> Result<Witness> {
    let boot = kernel_boot()?;
    let before = moment()?;
    let first_tracking = query("tracking")?;
    let first_sources = query("sources")?;
    let auth = query("authdata")?;
    let ntp = query("ntpdata")?;
    let last_sources = query("sources")?;
    let last_tracking = query("tracking")?;
    let after = moment()?;
    ensure!(
        boot == kernel_boot()?,
        "kernel boot changed during clock observation"
    );
    qualify(
        &boot,
        before,
        after,
        &first_tracking,
        &last_tracking,
        &first_sources,
        &last_sources,
        &auth,
        &ntp,
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn qualify(
    boot: &str,
    before: Moment,
    after: Moment,
    first_tracking: &str,
    last_tracking: &str,
    first_sources: &str,
    last_sources: &str,
    auth: &str,
    ntp: &str,
) -> Result<Witness> {
    ensure!(
        valid_boot(boot) && after.boot_ms >= before.boot_ms && after.wall_ms >= before.wall_ms,
        "clock reversed during observation"
    );
    let duration = after.boot_ms - before.boot_ms;
    ensure!(
        duration <= MAXIMUM_PROBE_MS,
        "clock-health observation took too long"
    );
    let first = tracking(first_tracking, before)?;
    let last = tracking(last_tracking, after)?;
    ensure!(
        first.source == last.source
            && first.reference == last.reference
            && first.reference_ns == last.reference_ns,
        "chrony reference changed during observation; retry required"
    );
    let selected = sources(first_sources)?;
    ensure!(
        selected == sources(last_sources)?,
        "time-source selection changed during observation"
    );
    authenticate(&selected, auth, ntp, &last)?;
    let progression = (after.wall_ms - before.wall_ms).abs_diff(duration);
    // Account for observation latency, timestamp rounding, holdover, and any
    // intervening system-clock adjustment before exposing the bound.
    let holdover_ms = (SAMPLE_LIFETIME_MS + duration)
        .checked_mul(HOLDOVER_PPM)
        .context("holdover overflow")?
        .div_ceil(1_000_000);
    let maximum_error_ms = first
        .bound_ns
        .max(last.bound_ns)
        .div_ceil(1_000_000)
        .checked_add(duration)
        .and_then(|v| v.checked_add(progression))
        .and_then(|v| v.checked_add(holdover_ms + 2))
        .context("clock bound overflow")?;
    ensure!(
        maximum_error_ms <= MAXIMUM_ERROR_MS,
        "clock error exceeds the authority bound"
    );
    let value = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: after.wall_ms,
        sample_boot_ms: after.boot_ms,
        valid_until_boot_ms: after
            .boot_ms
            .checked_add(SAMPLE_LIFETIME_MS)
            .context("clock lifetime overflow")?,
        maximum_error_ms,
        source: last.source,
    };
    value.health(boot, after)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
    #[test]
    fn decimal_bounds_round_up_and_refuse_unknown_values() {
        assert_eq!(decimal_nanos("-0.0000000001", true).unwrap(), 1);
        assert_eq!(decimal_nanos("0.9999999999", false).unwrap(), 1_000_000_000);
        for value in ["NaN", "inf", "1e-9", "-0.1", "1..0", "18446744073709551615"] {
            assert!(decimal_nanos(value, false).is_err());
        }
    }
    fn reports() -> (String, String, String, String) {
        let tracking = "C0000201,192.0.2.1,2,1000.000000000,0.001000000,0.001,0.001,0.010,0.001,0.020,0.020,0.001,16.0,Normal\n".into();
        let sources = "^,*,192.0.2.1,1,4,377,0,0.001,0.001,0.001\n".into();
        let auth = "192.0.2.1,NTS,1,15,256,1,0,0,8,100\n".into();
        let mut ntp = vec!["0"; 38];
        ntp[0] = "192.0.2.1";
        ntp[1] = "C0000201";
        ntp[5] = "Normal";
        ntp[6] = "4";
        ntp[7] = "Server";
        ntp[27] = "Yes";
        ntp[33] = "8";
        (tracking, sources, auth, ntp.join(","))
    }
    #[test]
    fn health_requires_matching_authenticated_fresh_observations() {
        let (t, s, a, n) = reports();
        let before = Moment {
            wall_ms: 1000010,
            boot_ms: 100,
        };
        let after = Moment {
            wall_ms: 1000030,
            boot_ms: 120,
        };
        let w = qualify(BOOT, before, after, &t, &t, &s, &s, &a, &n).unwrap();
        assert!(w.maximum_error_ms >= 35);
        assert!(
            w.health(
                BOOT,
                Moment {
                    wall_ms: 1001030,
                    boot_ms: 1120
                }
            )
            .is_err()
        );
        assert!(
            w.health("22345678-1234-1234-1234-123456789abc", after)
                .is_err()
        );
        assert!(
            w.health(
                BOOT,
                Moment {
                    wall_ms: 1001030,
                    boot_ms: 121
                }
            )
            .is_err()
        );
        assert!(
            qualify(
                BOOT,
                before,
                after,
                &t,
                &t,
                &s,
                &s,
                &a,
                &n.replace("Yes", "No")
            )
            .is_err()
        );
        assert!(
            qualify(
                BOOT,
                before,
                after,
                &t,
                &t,
                &s,
                &s,
                &a.replace("NTS", "-"),
                &n
            )
            .is_err()
        );
        assert!(
            qualify(
                BOOT,
                before,
                after,
                &t,
                &t.replace("Normal", "Not synchronised"),
                &s,
                &s,
                &a,
                &n
            )
            .is_err()
        );
        assert!(
            qualify(
                BOOT,
                before,
                after,
                &t,
                &t,
                &s,
                &s.replace("192.0.2.1", "192.0.2.2"),
                &a,
                &n
            )
            .is_err()
        );
    }
}
