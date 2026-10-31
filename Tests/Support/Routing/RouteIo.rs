// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub async fn forward<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    left: A,
    right: B,
    limits: Limits,
) -> Result<()> {
    let deadline = crate::authority_challenge::boot_time_ms()?.saturating_add(limits.duration_ms);
    forward_guarded(left, right, limits, Gate::new(deadline), deadline).await
}
