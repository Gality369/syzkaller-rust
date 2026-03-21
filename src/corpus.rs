use crate::program::Program;
use std::collections::HashSet;

/// Minimal corpus: a set of programs that have produced new coverage.
pub struct Corpus {
    pub programs: Vec<Program>,
    /// Maximum signal set: all unique coverage signals seen.
    pub max_signal: HashSet<u64>,
    /// New signal accumulated since last sync to runners.
    pub new_signal: Vec<u64>,
}

impl Corpus {
    pub fn new() -> Self {
        Corpus {
            programs: Vec::new(),
            max_signal: HashSet::new(),
            new_signal: Vec::new(),
        }
    }

    /// Add execution signals and return whether any new signal was found.
    /// If new signal was found, also add the program to the corpus.
    pub fn add_result(&mut self, prog: &Program, signals: &[u64]) -> bool {
        let mut has_new = false;
        for &sig in signals {
            if sig != 0 && self.max_signal.insert(sig) {
                has_new = true;
                self.new_signal.push(sig);
            }
        }
        if has_new {
            self.programs.push(prog.clone());
        }
        has_new
    }

    /// Take new signal for syncing to runners, clearing the buffer.
    pub fn take_new_signal(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.new_signal)
    }

    /// Get a random program from the corpus for mutation.
    pub fn random_program(&self, rng: &mut impl rand::Rng) -> Option<&Program> {
        if self.programs.is_empty() {
            None
        } else {
            Some(&self.programs[rng.gen_range(0..self.programs.len())])
        }
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn signal_count(&self) -> usize {
        self.max_signal.len()
    }
}
