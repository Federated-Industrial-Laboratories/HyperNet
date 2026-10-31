// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Keys {
    #[cfg(test)]
    pub fn encode(&self, network: [u8; 32], incarnation: [u8; 32]) -> Result<Vec<u8>> {
        let b = |id: &[u8; 32]| V::Bytes(id.to_vec());
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(131),
            V::Uint(1),
            b(&network),
            b(&incarnation),
            V::Uint(1),
            V::Null,
            V::Array(
                self.authority_transports
                    .iter()
                    .map(|(voter, transport)| V::Array(vec![b(voter), b(transport)]))
                    .collect(),
            ),
            V::Array(self.clock_monitors.iter().map(b).collect()),
            V::Array(
                self.route_transports
                    .iter()
                    .map(|(class, (id, key))| V::Array(vec![V::Uint(*class), b(id), b(key)]))
                    .collect(),
            ),
        ]))?;
        Self::parse(&bytes, network, incarnation)?;
        Ok(bytes)
    }
}
