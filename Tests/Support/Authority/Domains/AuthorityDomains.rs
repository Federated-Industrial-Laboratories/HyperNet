// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn evaluate(
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
) -> Result<Decision> {
    Operation::parse(intent)?.prepare(state, records, reserved, intent, at, replay, true)
}
