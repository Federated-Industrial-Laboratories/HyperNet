// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Engine {
    #[cfg(test)]
    pub fn apply_turn(
        &mut self,
        mut execute: impl FnMut(&[u8], &Committed) -> Result<Execution>,
    ) -> Result<Turn> {
        self.apply_turn_with_inputs(|prior, committed| Ok((execute(prior, committed)?, vec![])))
    }

    #[cfg(test)]
    pub fn apply_committed(
        &mut self,
        mut execute: impl FnMut(&[u8], &Committed) -> Result<Execution>,
    ) -> Result<Vec<ExecutionRecord>> {
        let mut result = Vec::new();
        for _ in 0..MAX_NODES * 2 {
            match self.apply_turn(&mut execute)? {
                Turn::Idle | Turn::Blocked(_) | Turn::Unavailable(_) => return Ok(result),
                Turn::Result(_, record) => result.push(record),
                Turn::Inert | Turn::Progress => {}
            }
        }
        anyhow::bail!("Test application turns exceeded retained capacity")
    }
}
