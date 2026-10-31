// SPDX-License-Identifier: MIT
// Temporary observation expiry suspends serving within unchanged local consent.
use super::{Active, Guard};
use crate::consensus_clock::ObservationExpired;
use anyhow::Result;
use std::os::unix::net::UnixListener;

#[derive(Default)]
pub(crate) struct Gate {
    suspended: bool,
}
impl Gate {
    fn evaluate(
        &mut self,
        outcome: Result<()>,
        local: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        match outcome {
            Ok(()) => {
                if self.suspended {
                    local()?;
                    eprintln!("HyperNet service clock: FreshObservation");
                    self.suspended = false;
                }
                Ok(true)
            }
            Err(error) if error.is::<ObservationExpired>() => {
                local()?;
                if !self.suspended {
                    eprintln!("HyperNet service clock: Suspended");
                    self.suspended = true;
                }
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    pub(crate) fn result(
        &mut self,
        active: &Active,
        guard: &Guard,
        outcome: Result<()>,
    ) -> Result<bool> {
        self.evaluate(outcome, || {
            active.check_local(guard)?;
            guard.check_configuration()
        })
    }
    pub(crate) fn ready(&mut self, active: &Active, guard: &Guard) -> Result<bool> {
        self.result(active, guard, active.check(guard))
    }
    pub(crate) fn accepting(
        &mut self,
        active: &Active,
        guard: &Guard,
        listener: &UnixListener,
    ) -> Result<bool> {
        let ready = self.ready(active, guard)?;
        if !ready {
            discard_waiting(listener)?;
        }
        Ok(ready)
    }
}

fn discard_waiting(listener: &UnixListener) -> Result<()> {
    // Bound each maintenance turn even if another process continually reconnects.
    for _ in 0..64 {
        match listener.accept() {
            Ok((stream, _)) => drop(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeServiceClockUnitTests.rs"]
mod tests;
