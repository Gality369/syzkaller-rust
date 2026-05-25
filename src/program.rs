use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================
// Syscall metadata for Linux/amd64 minimal subset
// ============================================================

/// Argument type for syscall parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgType {
    /// Integer constant or flags.
    Const {
        size: usize,      // 1, 2, 4, or 8 bytes
        values: Vec<u64>, // possible values (empty = any)
        range: Option<(u64, u64)>,
        endian: ScalarEndian,
    },
    /// Resource handle passed between calls.
    Resource(ResourceDesc),
    /// Fixed-length array of a supported inner type.
    Array { inner: Box<ArgType>, len: usize },
    /// Pointer to another argument type.
    Ptr {
        inner: Box<ArgType>,
        dir: PtrDir,
        optional: bool,
    },
    /// Fixed-size struct layout serialized into bytes.
    Struct { fields: Vec<ArgType>, size: usize },
    /// Length of another argument's materialized data.
    Len {
        target: usize,
        size: usize,
        kind: LengthKind,
    },
    /// Raw data buffer.
    Buffer {
        min_size: usize,
        max_size: usize,
        dir: BufferDir,
    },
    /// Filename string.
    Filename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrDir {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarEndian {
    Native,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferDir {
    Plain,
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthKind {
    Auto,
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyscallAttrs {
    pub automatic_helper: bool,
    pub no_generate: bool,
    pub disabled: bool,
}

/// Syscall descriptor.
#[derive(Debug, Clone)]
pub struct SyscallDesc {
    pub name: String,
    pub id: u64, // syzkaller internal ID (index into executor's syscalls[] table for linux/amd64)
    pub args: Vec<ArgType>,
    pub ret: ReturnType,
    pub attrs: SyscallAttrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDesc {
    pub kind: String,
    pub size: usize,
    pub values: Vec<u64>,
    pub lineage: Vec<String>,
}

impl ResourceDesc {
    pub fn default_value(&self) -> u64 {
        self.values.first().copied().unwrap_or(0)
    }

    pub fn accepts(&self, actual: &ResourceDesc) -> bool {
        actual.lineage.starts_with(&self.lineage)
    }

    pub fn compatible_keys(&self) -> &[String] {
        &self.lineage
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnType {
    None,
    Resource(ResourceDesc),
    Int,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResultRef {
    pub call_idx: usize,
    pub result_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceSource {
    ReturnValue,
    PointerElement {
        arg_idx: usize,
        element_idx: usize,
        offset: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceOutput {
    pub resource: ResourceDesc,
    pub source: ResourceSource,
}

/// A concrete argument value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgValue {
    Const(u64),
    ResultRef(ResultRef),
    Buffer(Vec<u8>),
    Filename(String),
    OutPtr,
    Null,
}

/// A single syscall invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    pub syscall_idx: usize, // index into SYSCALLS
    pub args: Vec<ArgValue>,
}

/// A test program: a sequence of syscall invocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub calls: Vec<Call>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallAvailability {
    pub enabled: Vec<usize>,
    pub disabled: HashMap<usize, String>,
}

#[derive(Debug, Clone)]
pub struct SyscallChoiceTable {
    enabled: Vec<usize>,
    enabled_flags: Vec<bool>,
    weights: Vec<Vec<u32>>,
    runs: Vec<Vec<u32>>,
    startup_weights: Vec<u32>,
    startup_run: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

impl Program {
    pub fn validate(&self, descs: &[SyscallDesc]) -> Result<(), ValidationError> {
        validate_program(self, descs)
    }
}

// ============================================================
// Physical memory layout (matching syzkaller)
// ============================================================

/// Base virtual address for data in the test process.
pub const DATA_OFFSET: u64 = 0x0000_2000_0000;
/// Page size for argument allocation.
pub const PAGE_SIZE: u64 = 4096;

const TIMEOUT_EDGE_PRIORITY_PENALTY: u32 = 8;
const TIMEOUT_SYSCALL_PRIORITY_PENALTY: u32 = 4;

// ============================================================
// Linux/amd64 syscall table
// ============================================================

pub(crate) const BUILTIN_LINUX_AMD64_DESCRIPTIONS: &str =
    include_str!("../descriptions/linux/amd64-minimal.txt");

pub fn load_syscall_descs(path: Option<&str>) -> Result<Vec<SyscallDesc>, String> {
    let descs = match path {
        Some(path) => crate::description::parse_syscall_descs_from_path(path)?,
        None => crate::description::parse_syscall_descs(BUILTIN_LINUX_AMD64_DESCRIPTIONS)?,
    };
    validate_syscall_descs(&descs)
        .map_err(|err| format!("invalid syscall descriptions: {}", err))?;
    Ok(descs)
}

/// Get the builtin syscall descriptors.
pub fn get_syscall_descs() -> Vec<SyscallDesc> {
    load_syscall_descs(None).expect("builtin linux target descriptions must parse")
}

pub fn stable_program_key(prog: &Program) -> String {
    serde_json::to_string(prog).expect("program serialization for stable keys should succeed")
}

pub fn program_shape_key(prog: &Program, descs: &[SyscallDesc]) -> String {
    prog.calls
        .iter()
        .map(|call| descs[call.syscall_idx].name.as_str())
        .collect::<Vec<_>>()
        .join("->")
}

/// Generate random filenames for fuzzing.
pub fn random_filename(rng: &mut impl Rng) -> String {
    let names = [
        "./file0",
        "./file1",
        "./file2",
        "./dir0/file0",
        "./dir1/file1",
        "/tmp/syz0",
        "/tmp/syz1",
        "./a",
        "./b",
        "./c",
    ];
    names[rng.gen_range(0..names.len())].to_string()
}

/// Collect indices of syscalls that produce resources.
pub fn resource_producing_syscalls(descs: &[SyscallDesc]) -> Vec<usize> {
    descs
        .iter()
        .enumerate()
        .filter(|(_, desc)| !resource_outputs(desc).is_empty())
        .map(|(i, _)| i)
        .collect()
}

/// Collect indices of syscalls that consume resources.
pub fn resource_consuming_syscalls(descs: &[SyscallDesc]) -> Vec<usize> {
    descs
        .iter()
        .enumerate()
        .filter(|(_, d)| d.args.iter().any(arg_type_contains_resource_input))
        .map(|(i, _)| i)
        .collect()
}

pub fn arg_type_is_timeout_prone(arg_type: &ArgType) -> bool {
    match arg_type {
        ArgType::Ptr { .. } | ArgType::Buffer { .. } | ArgType::Filename => true,
        ArgType::Array { inner, .. } => arg_type_is_timeout_prone(inner),
        ArgType::Struct { fields, .. } => fields.iter().any(arg_type_is_timeout_prone),
        _ => false,
    }
}

pub fn syscall_is_timeout_prone(desc: &SyscallDesc) -> bool {
    desc.args.iter().any(arg_type_is_timeout_prone)
}

pub fn timeout_prone_edge_key(
    descs: &[SyscallDesc],
    src_idx: usize,
    dst_idx: usize,
) -> Option<String> {
    let src = descs.get(src_idx)?;
    let dst = descs.get(dst_idx)?;
    if !syscall_is_timeout_prone(src) || !syscall_is_timeout_prone(dst) {
        return None;
    }
    Some(format!("{}->{}", src.name, dst.name))
}

pub fn arg_type_fixed_size(arg_type: &ArgType) -> Option<usize> {
    match arg_type {
        ArgType::Const { size, .. } => Some(*size),
        ArgType::Resource(resource) => Some(resource.size),
        ArgType::Array { inner, len } => arg_type_fixed_size(inner)?.checked_mul(*len),
        ArgType::Struct { size, .. } => Some(*size),
        ArgType::Len { size, .. } => Some(*size),
        ArgType::Buffer {
            min_size, max_size, ..
        } if min_size == max_size => Some(*max_size),
        _ => None,
    }
}

pub fn materialized_arg_size(arg_type: &ArgType, arg_value: &ArgValue) -> Option<usize> {
    match (arg_type, arg_value) {
        (ArgType::Ptr { inner: _, .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::Ptr { inner, .. }, ArgValue::OutPtr) => arg_type_fixed_size(inner),
        (ArgType::Ptr { .. }, ArgValue::Null) => Some(0),
        (ArgType::Buffer { .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::Filename, ArgValue::Filename(name)) => Some(name.len() + 1),
        (arg_type, _) => arg_type_fixed_size(arg_type),
    }
}

pub fn derived_arg_length(
    arg_type: &ArgType,
    arg_value: &ArgValue,
    kind: LengthKind,
) -> Option<usize> {
    match kind {
        LengthKind::Bytes => materialized_arg_size(arg_type, arg_value),
        LengthKind::Auto => match (arg_type, arg_value) {
            (ArgType::Array { len, .. }, _) => Some(*len),
            (ArgType::Ptr { inner, .. }, ArgValue::Buffer(data)) => match inner.as_ref() {
                ArgType::Array { inner: _, len } => Some(*len),
                _ => Some(data.len()),
            },
            (ArgType::Ptr { inner, .. }, ArgValue::OutPtr) => match inner.as_ref() {
                ArgType::Array { inner: _, len } => Some(*len),
                _ => arg_type_fixed_size(inner),
            },
            (ArgType::Ptr { .. }, ArgValue::Null) => Some(0),
            (ArgType::Buffer { .. }, ArgValue::Buffer(data)) => Some(data.len()),
            (ArgType::Filename, ArgValue::Filename(name)) => Some(name.len() + 1),
            (arg_type, _) => arg_type_fixed_size(arg_type),
        },
    }
}

pub fn encode_scalar_bytes(size: usize, value: u64) -> Vec<u8> {
    encode_scalar_bytes_endian(size, value, ScalarEndian::Native)
}

pub fn encode_scalar_bytes_endian(size: usize, value: u64, endian: ScalarEndian) -> Vec<u8> {
    let full = value.to_le_bytes();
    let mut bytes = full[..size.min(full.len())].to_vec();
    if endian == ScalarEndian::Big {
        bytes.reverse();
    }
    bytes
}

pub fn decode_scalar_bytes(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes)
}

pub fn resource_outputs(desc: &SyscallDesc) -> Vec<ResourceOutput> {
    let mut outputs = Vec::new();
    if let ReturnType::Resource(resource) = &desc.ret {
        outputs.push(ResourceOutput {
            resource: resource.clone(),
            source: ResourceSource::ReturnValue,
        });
    }
    for (arg_idx, arg_type) in desc.args.iter().enumerate() {
        if let ArgType::Ptr {
            inner,
            dir: PtrDir::Out | PtrDir::InOut,
            ..
        } = arg_type
        {
            collect_pointer_resource_outputs(inner, arg_idx, &mut outputs);
        }
    }
    outputs
}

pub fn input_resources(desc: &SyscallDesc) -> Vec<ResourceDesc> {
    let mut resources = Vec::new();
    let mut seen = HashSet::new();
    for arg in &desc.args {
        collect_input_resources(arg, &mut seen, &mut resources);
    }
    resources
}

pub fn resource_constructor_syscalls(descs: &[SyscallDesc], required: &ResourceDesc) -> Vec<usize> {
    let mut syscalls = Vec::new();
    for (syscall_idx, desc) in descs.iter().enumerate() {
        if resource_outputs(desc)
            .iter()
            .any(|output| required.accepts(&output.resource))
        {
            syscalls.push(syscall_idx);
        }
    }
    syscalls
}

pub fn transitively_enabled_syscalls(descs: &[SyscallDesc]) -> SyscallAvailability {
    transitively_available_syscalls(descs, false)
}

pub fn transitively_generatable_syscalls(descs: &[SyscallDesc]) -> SyscallAvailability {
    transitively_available_syscalls(descs, true)
}

fn transitively_available_syscalls(
    descs: &[SyscallDesc],
    generatable_only: bool,
) -> SyscallAvailability {
    let mut enabled = Vec::new();
    let mut enabled_set = HashSet::new();
    let mut creatable_resources = HashSet::new();

    loop {
        let mut progress = false;

        for (syscall_idx, desc) in descs.iter().enumerate() {
            if enabled_set.contains(&syscall_idx) {
                continue;
            }
            if syscall_unavailable_reason(desc, generatable_only).is_some() {
                continue;
            }
            if input_resources(desc)
                .iter()
                .all(|resource| creatable_resources.contains(&resource.kind))
            {
                enabled.push(syscall_idx);
                enabled_set.insert(syscall_idx);
                for output in resource_outputs(desc) {
                    for key in output.resource.compatible_keys() {
                        creatable_resources.insert(key.clone());
                    }
                }
                progress = true;
            }
        }

        if !progress {
            break;
        }
    }

    let mut disabled = HashMap::new();
    for (syscall_idx, desc) in descs.iter().enumerate() {
        if enabled_set.contains(&syscall_idx) {
            continue;
        }
        if let Some(reason) = syscall_unavailable_reason(desc, generatable_only) {
            disabled.insert(syscall_idx, reason);
            continue;
        }
        disabled.insert(
            syscall_idx,
            disabled_syscall_reason(descs, desc, &creatable_resources),
        );
    }

    SyscallAvailability { enabled, disabled }
}

pub fn static_syscall_priorities(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
) -> Vec<Vec<u32>> {
    let mut priorities = vec![vec![0; descs.len()]; descs.len()];
    let input_resources = descs.iter().map(input_resources).collect::<Vec<_>>();
    let output_resources = descs.iter().map(resource_outputs).collect::<Vec<_>>();

    for &src_idx in enabled_syscalls {
        for &dst_idx in enabled_syscalls {
            if src_idx == dst_idx {
                continue;
            }

            let mut score = 0;
            for output in &output_resources[src_idx] {
                for input in &input_resources[dst_idx] {
                    if input.accepts(&output.resource) {
                        score += 12;
                    }
                }
            }
            for src_input in &input_resources[src_idx] {
                for dst_input in &input_resources[dst_idx] {
                    if resources_overlap(src_input, dst_input) {
                        score += 4;
                    }
                }
            }
            for src_output in &output_resources[src_idx] {
                for dst_output in &output_resources[dst_idx] {
                    if resources_overlap(&src_output.resource, &dst_output.resource) {
                        score += 2;
                    }
                }
            }

            priorities[src_idx][dst_idx] = score;
        }

        let row_max = priorities[src_idx].iter().copied().max().unwrap_or(0);
        priorities[src_idx][src_idx] = if row_max == 0 { 1 } else { (row_max * 3) / 4 };
    }

    priorities
}

pub fn dynamic_syscall_priorities(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    corpus: &[Program],
) -> Vec<Vec<u32>> {
    let mut priorities = vec![vec![0; descs.len()]; descs.len()];
    let enabled_set = enabled_syscalls.iter().copied().collect::<HashSet<_>>();

    for prog in corpus {
        for (call_idx, call) in prog.calls.iter().enumerate() {
            if !enabled_set.contains(&call.syscall_idx) {
                continue;
            }
            for next_call in &prog.calls[call_idx + 1..] {
                if enabled_set.contains(&next_call.syscall_idx) {
                    priorities[call.syscall_idx][next_call.syscall_idx] += 1;
                }
            }
        }
    }

    for &src_idx in enabled_syscalls {
        for &dst_idx in enabled_syscalls {
            let count = priorities[src_idx][dst_idx];
            if count == 0 {
                continue;
            }
            priorities[src_idx][dst_idx] = ((count as f64).sqrt() * 6.0).round() as u32;
        }
    }

    priorities
}

pub fn combined_syscall_priorities(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    corpus: &[Program],
) -> Vec<Vec<u32>> {
    let mut combined = static_syscall_priorities(descs, enabled_syscalls);
    let dynamic = dynamic_syscall_priorities(descs, enabled_syscalls, corpus);

    for &src_idx in enabled_syscalls {
        for &dst_idx in enabled_syscalls {
            combined[src_idx][dst_idx] += dynamic[src_idx][dst_idx];
        }
    }

    combined
}

pub fn avoidance_adjusted_syscall_priorities(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    corpus: &[Program],
    timeout_edge_failures: &HashMap<String, u32>,
    timeout_syscall_failures: &HashMap<String, u32>,
) -> Vec<Vec<u32>> {
    let mut adjusted = combined_syscall_priorities(descs, enabled_syscalls, corpus);

    for &dst_idx in enabled_syscalls {
        let desc = &descs[dst_idx];
        let failure_count = timeout_syscall_failures
            .get(&desc.name)
            .copied()
            .unwrap_or(0);
        if failure_count == 0 || !syscall_is_timeout_prone(desc) {
            continue;
        }
        let penalty = failure_count.saturating_mul(TIMEOUT_SYSCALL_PRIORITY_PENALTY);
        for &src_idx in enabled_syscalls {
            adjusted[src_idx][dst_idx] = adjusted[src_idx][dst_idx].saturating_sub(penalty);
        }
    }

    for &src_idx in enabled_syscalls {
        for &dst_idx in enabled_syscalls {
            let Some(edge_key) = timeout_prone_edge_key(descs, src_idx, dst_idx) else {
                continue;
            };
            let failure_count = timeout_edge_failures.get(&edge_key).copied().unwrap_or(0);
            if failure_count == 0 {
                continue;
            }
            let penalty = failure_count.saturating_mul(TIMEOUT_EDGE_PRIORITY_PENALTY);
            adjusted[src_idx][dst_idx] = adjusted[src_idx][dst_idx].saturating_sub(penalty);
        }
    }

    adjusted
}

impl SyscallChoiceTable {
    pub fn build(descs: &[SyscallDesc], corpus: &[Program]) -> Self {
        Self::build_with_avoidance(descs, corpus, &HashMap::new(), &HashMap::new())
    }

    pub fn build_with_avoidance(
        descs: &[SyscallDesc],
        corpus: &[Program],
        timeout_edge_failures: &HashMap<String, u32>,
        timeout_syscall_failures: &HashMap<String, u32>,
    ) -> Self {
        let availability = transitively_generatable_syscalls(descs);
        assert!(
            !availability.enabled.is_empty(),
            "target has no transitively generatable syscalls"
        );

        let weights = avoidance_adjusted_syscall_priorities(
            descs,
            &availability.enabled,
            corpus,
            timeout_edge_failures,
            timeout_syscall_failures,
        );
        let mut enabled_flags = vec![false; descs.len()];
        for &syscall_idx in &availability.enabled {
            enabled_flags[syscall_idx] = true;
        }

        let mut runs = vec![vec![]; descs.len()];
        for &src_idx in &availability.enabled {
            let mut row = vec![0; descs.len()];
            let mut sum = 0u32;
            for dst_idx in 0..descs.len() {
                if enabled_flags[dst_idx] {
                    sum = sum.saturating_add(weights[src_idx][dst_idx]);
                }
                row[dst_idx] = sum;
            }
            runs[src_idx] = row;
        }

        let startup_weights = build_startup_weights(
            descs,
            &availability.enabled,
            &weights,
            timeout_syscall_failures,
        );
        let startup_run = build_cumulative_run(&startup_weights, &enabled_flags);

        Self {
            enabled: availability.enabled,
            enabled_flags,
            weights,
            runs,
            startup_weights,
            startup_run,
        }
    }

    pub fn enabled_syscalls(&self) -> &[usize] {
        &self.enabled
    }

    pub fn generatable(&self, syscall_idx: usize) -> bool {
        self.enabled_flags
            .get(syscall_idx)
            .copied()
            .unwrap_or(false)
    }

    pub fn weight(&self, src_idx: usize, dst_idx: usize) -> u32 {
        self.weights
            .get(src_idx)
            .and_then(|row| row.get(dst_idx))
            .copied()
            .unwrap_or(0)
    }

    pub fn startup_weight(&self, syscall_idx: usize) -> u32 {
        self.startup_weights.get(syscall_idx).copied().unwrap_or(0)
    }

    pub fn choose(&self, previous_syscall_idx: Option<usize>, rng: &mut impl Rng) -> usize {
        assert!(
            !self.enabled.is_empty(),
            "choice table must contain at least one enabled syscall"
        );

        if rng.gen_ratio(1, 20) {
            return self.enabled[rng.gen_range(0..self.enabled.len())];
        }

        let Some(previous_syscall_idx) = previous_syscall_idx.filter(|&idx| self.generatable(idx))
        else {
            return self.choose_startup(rng);
        };

        let run = &self.runs[previous_syscall_idx];
        let run_sum = run.last().copied().unwrap_or(0);
        if run_sum == 0 {
            return self.choose_startup(rng);
        }

        let target = rng.gen_range(1..=run_sum);
        let idx = run.partition_point(|&sum| sum < target);
        if self.generatable(idx) {
            idx
        } else {
            self.choose_startup(rng)
        }
    }

    pub fn choose_subset(
        &self,
        candidates: &[usize],
        previous_syscall_idx: Option<usize>,
        rng: &mut impl Rng,
    ) -> usize {
        assert!(
            !candidates.is_empty(),
            "candidate subset must contain at least one syscall"
        );
        if candidates.len() == 1 {
            return candidates[0];
        }

        let Some(previous_syscall_idx) = previous_syscall_idx.filter(|&idx| self.generatable(idx))
        else {
            return self.choose_startup_subset(candidates, rng);
        };

        let total_weight = candidates
            .iter()
            .map(|&candidate| self.weight(previous_syscall_idx, candidate) as u64)
            .sum::<u64>();
        if total_weight == 0 {
            return self.choose_startup_subset(candidates, rng);
        }

        let mut pick = rng.gen_range(0..total_weight);
        for &candidate in candidates {
            let weight = self.weight(previous_syscall_idx, candidate) as u64;
            if weight == 0 {
                continue;
            }
            if pick < weight {
                return candidate;
            }
            pick -= weight;
        }

        *candidates
            .iter()
            .find(|&&candidate| self.weight(previous_syscall_idx, candidate) > 0)
            .expect("subset choice must find a positive-weight candidate")
    }

    fn choose_startup(&self, rng: &mut impl Rng) -> usize {
        choose_from_run(&self.enabled, &self.startup_run, rng)
            .unwrap_or_else(|| self.enabled[rng.gen_range(0..self.enabled.len())])
    }

    fn choose_startup_subset(&self, candidates: &[usize], rng: &mut impl Rng) -> usize {
        choose_from_weights(candidates, |candidate| self.startup_weight(candidate), rng)
            .unwrap_or_else(|| candidates[rng.gen_range(0..candidates.len())])
    }
}

fn build_startup_weights(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    weights: &[Vec<u32>],
    timeout_syscall_failures: &HashMap<String, u32>,
) -> Vec<u32> {
    let mut startup_weights = vec![0; descs.len()];

    for &dst_idx in enabled_syscalls {
        let mut weight = 1u32;
        for &src_idx in enabled_syscalls {
            weight = weight.saturating_add(
                weights
                    .get(src_idx)
                    .and_then(|row| row.get(dst_idx))
                    .copied()
                    .unwrap_or(0),
            );
        }

        let failure_count = timeout_syscall_failures
            .get(&descs[dst_idx].name)
            .copied()
            .unwrap_or(0);
        if failure_count > 0 && syscall_is_timeout_prone(&descs[dst_idx]) {
            let penalty = failure_count.saturating_mul(TIMEOUT_SYSCALL_PRIORITY_PENALTY);
            weight = weight.saturating_sub(penalty);
        }

        startup_weights[dst_idx] = weight;
    }

    startup_weights
}

fn build_cumulative_run(weights: &[u32], enabled_flags: &[bool]) -> Vec<u32> {
    let mut run = vec![0; weights.len()];
    let mut sum = 0u32;
    for idx in 0..weights.len() {
        if enabled_flags.get(idx).copied().unwrap_or(false) {
            sum = sum.saturating_add(weights[idx]);
        }
        run[idx] = sum;
    }
    run
}

fn choose_from_run(enabled_syscalls: &[usize], run: &[u32], rng: &mut impl Rng) -> Option<usize> {
    let run_sum = run.last().copied().unwrap_or(0);
    if run_sum == 0 {
        return None;
    }

    let target = rng.gen_range(1..=run_sum);
    let idx = run.partition_point(|&sum| sum < target);
    if enabled_syscalls.contains(&idx) {
        Some(idx)
    } else {
        None
    }
}

fn choose_from_weights(
    candidates: &[usize],
    weight_of: impl Fn(usize) -> u32,
    rng: &mut impl Rng,
) -> Option<usize> {
    let total_weight = candidates
        .iter()
        .map(|&candidate| weight_of(candidate) as u64)
        .sum::<u64>();
    if total_weight == 0 {
        return None;
    }

    let mut pick = rng.gen_range(0..total_weight);
    for &candidate in candidates {
        let weight = weight_of(candidate) as u64;
        if weight == 0 {
            continue;
        }
        if pick < weight {
            return Some(candidate);
        }
        pick -= weight;
    }

    candidates
        .iter()
        .copied()
        .find(|&candidate| weight_of(candidate) > 0)
}

pub fn register_available_resource(
    available_resources: &mut std::collections::HashMap<String, Vec<ResultRef>>,
    resource: &ResourceDesc,
    result_ref: ResultRef,
) {
    for key in resource.compatible_keys() {
        available_resources
            .entry(key.clone())
            .or_default()
            .push(result_ref.clone());
    }
}

pub fn used_results(prog: &Program) -> HashSet<ResultRef> {
    let mut used = HashSet::new();
    for call in &prog.calls {
        for arg in &call.args {
            if let ArgValue::ResultRef(result_ref) = arg {
                used.insert(result_ref.clone());
            }
        }
    }
    used
}

pub fn validate_syscall_descs(descs: &[SyscallDesc]) -> Result<(), ValidationError> {
    for (syscall_idx, desc) in descs.iter().enumerate() {
        if desc.name.trim().is_empty() {
            return Err(ValidationError::new(format!(
                "syscall #{} has an empty name",
                syscall_idx
            )));
        }
        for (arg_idx, arg_type) in desc.args.iter().enumerate() {
            validate_arg_type(arg_type).map_err(|err| {
                ValidationError::new(format!(
                    "syscall {} argument {} is invalid: {}",
                    desc.name, arg_idx, err
                ))
            })?;
        }
        if let ReturnType::Resource(resource) = &desc.ret {
            validate_resource_desc(resource).map_err(|err| {
                ValidationError::new(format!(
                    "syscall {} return type is invalid: {}",
                    desc.name, err
                ))
            })?;
        }
    }
    Ok(())
}

pub fn validate_program(prog: &Program, descs: &[SyscallDesc]) -> Result<(), ValidationError> {
    let used_results = used_results(prog);

    for (call_idx, call) in prog.calls.iter().enumerate() {
        let desc = descs.get(call.syscall_idx).ok_or_else(|| {
            ValidationError::new(format!(
                "call #{} references unknown syscall index {}",
                call_idx, call.syscall_idx
            ))
        })?;

        if call.args.len() != desc.args.len() {
            return Err(ValidationError::new(format!(
                "call #{} {} has {} arguments, expected {}",
                call_idx,
                desc.name,
                call.args.len(),
                desc.args.len()
            )));
        }

        for (result_idx, output) in resource_outputs(desc).iter().enumerate() {
            if used_results.contains(&ResultRef {
                call_idx,
                result_idx,
            }) && output.resource.size > 8
            {
                return Err(ValidationError::new(format!(
                    "call #{} {} result {} has unsupported copyout size {}",
                    call_idx, desc.name, result_idx, output.resource.size
                )));
            }
        }

        for (arg_idx, (arg_type, arg_value)) in desc.args.iter().zip(call.args.iter()).enumerate() {
            validate_arg_value(prog, descs, call_idx, desc, arg_idx, arg_type, arg_value)?;
        }
    }

    Ok(())
}

fn collect_pointer_resource_outputs(
    arg_type: &ArgType,
    arg_idx: usize,
    outputs: &mut Vec<ResourceOutput>,
) {
    let mut next_element_idx = 0usize;
    collect_pointer_resource_outputs_inner(arg_type, arg_idx, 0, &mut next_element_idx, outputs);
}

fn collect_pointer_resource_outputs_inner(
    arg_type: &ArgType,
    arg_idx: usize,
    base_offset: usize,
    next_element_idx: &mut usize,
    outputs: &mut Vec<ResourceOutput>,
) {
    match arg_type {
        ArgType::Resource(resource) => {
            outputs.push(ResourceOutput {
                resource: resource.clone(),
                source: ResourceSource::PointerElement {
                    arg_idx,
                    element_idx: *next_element_idx,
                    offset: base_offset,
                },
            });
            *next_element_idx += 1;
        }
        ArgType::Array { inner, len } => {
            let Some(element_size) = arg_type_fixed_size(inner) else {
                return;
            };
            for element_idx in 0..*len {
                collect_pointer_resource_outputs_inner(
                    inner,
                    arg_idx,
                    base_offset + (element_idx * element_size),
                    next_element_idx,
                    outputs,
                );
            }
        }
        ArgType::Struct { fields, .. } => {
            let mut field_offset = base_offset;
            for field in fields {
                collect_pointer_resource_outputs_inner(
                    field,
                    arg_idx,
                    field_offset,
                    next_element_idx,
                    outputs,
                );
                let Some(field_size) = arg_type_fixed_size(field) else {
                    return;
                };
                field_offset += field_size;
            }
        }
        _ => {}
    }
}

fn collect_input_resources(
    arg_type: &ArgType,
    seen: &mut HashSet<String>,
    resources: &mut Vec<ResourceDesc>,
) {
    match arg_type {
        ArgType::Resource(resource) => {
            if seen.insert(resource.kind.clone()) {
                resources.push(resource.clone());
            }
        }
        ArgType::Array { inner, .. } => collect_input_resources(inner, seen, resources),
        ArgType::Struct { fields, .. } => {
            for field in fields {
                collect_input_resources(field, seen, resources);
            }
        }
        ArgType::Ptr {
            inner,
            dir: PtrDir::In | PtrDir::InOut,
            ..
        } => collect_input_resources(inner, seen, resources),
        _ => {}
    }
}

fn arg_type_contains_resource_input(arg_type: &ArgType) -> bool {
    match arg_type {
        ArgType::Resource(_) => true,
        ArgType::Array { inner, .. } => arg_type_contains_resource_input(inner),
        ArgType::Struct { fields, .. } => fields.iter().any(arg_type_contains_resource_input),
        ArgType::Ptr { inner, dir, .. } => {
            *dir != PtrDir::Out && arg_type_contains_resource_input(inner)
        }
        _ => false,
    }
}

fn disabled_syscall_reason(
    descs: &[SyscallDesc],
    desc: &SyscallDesc,
    creatable_resources: &HashSet<String>,
) -> String {
    for resource in input_resources(desc) {
        if creatable_resources.contains(&resource.kind) {
            continue;
        }
        let mut ctor_names = resource_constructor_syscalls(descs, &resource)
            .into_iter()
            .map(|syscall_idx| descs[syscall_idx].name.as_str())
            .collect::<Vec<_>>();
        ctor_names.sort_unstable();
        ctor_names.dedup();

        if ctor_names.is_empty() {
            return format!(
                "requires resource '{}' but no compatible constructors are available",
                resource.kind
            );
        }

        let preview = if ctor_names.len() > 4 {
            format!(
                "{}, {}, ..., {}",
                ctor_names[0],
                ctor_names[1],
                ctor_names[ctor_names.len() - 1]
            )
        } else {
            ctor_names.join(", ")
        };
        return format!(
            "requires resource '{}' but its constructors are not transitively enabled: {}",
            resource.kind, preview
        );
    }

    "not transitively reachable".to_string()
}

fn syscall_unavailable_reason(desc: &SyscallDesc, generatable_only: bool) -> Option<String> {
    if desc.attrs.disabled {
        Some("marked disabled".to_string())
    } else if generatable_only && desc.attrs.no_generate {
        Some("marked no_generate".to_string())
    } else {
        None
    }
}

fn resources_overlap(expected: &ResourceDesc, actual: &ResourceDesc) -> bool {
    expected.accepts(actual) || actual.accepts(expected)
}

fn validate_arg_type(arg_type: &ArgType) -> Result<(), String> {
    match arg_type {
        ArgType::Const { size, .. } => validate_native_size(*size, "const argument"),
        ArgType::Resource(resource) => validate_resource_desc(resource),
        ArgType::Array { inner, len } => {
            if *len == 0 {
                return Err("array length must be greater than zero".to_string());
            }
            validate_arg_type(inner)
        }
        ArgType::Struct { fields, size } => {
            if fields.is_empty() {
                return Err("struct must have at least one field".to_string());
            }
            let total = fields.iter().try_fold(0usize, |acc, field| {
                validate_arg_type(field)?;
                let field_size = arg_type_fixed_size(field)
                    .ok_or_else(|| "struct fields must be fixed-size".to_string())?;
                acc.checked_add(field_size)
                    .ok_or_else(|| "struct size overflow".to_string())
            })?;
            if total > *size {
                return Err(format!(
                    "struct fields require {} bytes but declared size is {}",
                    total, size
                ));
            }
            Ok(())
        }
        ArgType::Ptr { inner, .. } => validate_arg_type(inner),
        ArgType::Len { size, .. } => validate_native_size(*size, "length argument"),
        ArgType::Buffer {
            min_size, max_size, ..
        } => validate_buffer_range(*min_size, *max_size),
        ArgType::Filename => Ok(()),
    }
}

fn validate_arg_value(
    prog: &Program,
    descs: &[SyscallDesc],
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    arg_type: &ArgType,
    arg_value: &ArgValue,
) -> Result<(), ValidationError> {
    match (arg_type, arg_value) {
        (ArgType::Const { .. }, ArgValue::Const(_)) => Ok(()),
        (ArgType::Len { target, size, kind }, ArgValue::Const(value)) => {
            validate_len_value(prog, call_idx, desc, arg_idx, *target, *size, *kind, *value)
        }
        (ArgType::Resource(resource), ArgValue::Const(_)) => validate_resource_desc(resource)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (ArgType::Resource(resource), ArgValue::Null) => validate_resource_desc(resource)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (ArgType::Resource(resource), ArgValue::ResultRef(result_ref)) => {
            validate_result_ref(prog, descs, call_idx, desc, arg_idx, resource, result_ref)
        }
        (
            ArgType::Ptr {
                inner,
                dir,
                optional: _,
            },
            ArgValue::Buffer(data),
        ) => validate_pointer_buffer(prog, call_idx, desc, arg_idx, inner, *dir, data),
        (ArgType::Struct { size, .. }, ArgValue::Buffer(data)) => {
            if data.len() != *size {
                Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    format!("struct buffer has size {}, expected {}", data.len(), size),
                ))
            } else {
                Ok(())
            }
        }
        (ArgType::Ptr { optional: true, .. }, ArgValue::Null) => Ok(()),
        (
            ArgType::Ptr {
                dir: PtrDir::Out | PtrDir::InOut,
                ..
            },
            ArgValue::OutPtr,
        ) => Ok(()),
        (
            ArgType::Ptr {
                dir: PtrDir::Out | PtrDir::InOut,
                optional: false,
                ..
            },
            ArgValue::Null,
        ) => Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            "non-optional output pointer must reserve storage instead of using NULL",
        )),
        (
            ArgType::Buffer {
                min_size, max_size, ..
            },
            ArgValue::Buffer(data),
        ) => validate_buffer_size(data.len(), *min_size, *max_size)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (ArgType::Filename, ArgValue::Filename(name)) => {
            if name.as_bytes().contains(&0) {
                return Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    "filename contains an embedded NUL byte",
                ));
            }
            Ok(())
        }
        _ => Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "expected {}, got {}",
                describe_arg_type(arg_type),
                describe_arg_value(arg_value)
            ),
        )),
    }
}

fn validate_result_ref(
    prog: &Program,
    descs: &[SyscallDesc],
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    resource: &ResourceDesc,
    result_ref: &ResultRef,
) -> Result<(), ValidationError> {
    validate_resource_desc(resource).map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))?;

    if result_ref.call_idx >= call_idx {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "resource result reference must point to an earlier call, got call #{}",
                result_ref.call_idx
            ),
        ));
    }

    let target_call = prog.calls.get(result_ref.call_idx).ok_or_else(|| {
        invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "resource result reference points past the program: {}",
                result_ref.call_idx
            ),
        )
    })?;
    let target_desc = descs.get(target_call.syscall_idx).ok_or_else(|| {
        invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "resource result reference targets call #{} with unknown syscall index {}",
                result_ref.call_idx, target_call.syscall_idx
            ),
        )
    })?;

    let outputs = resource_outputs(target_desc);
    let target_output = outputs.get(result_ref.result_idx).ok_or_else(|| {
        invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "resource result reference targets missing result {} on call #{}",
                result_ref.result_idx, result_ref.call_idx
            ),
        )
    })?;

    if !resource.accepts(&target_output.resource) {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "resource result reference expects compatible '{}', got '{}' from call #{} result {}",
                resource.kind,
                target_output.resource.kind,
                result_ref.call_idx,
                result_ref.result_idx
            ),
        ));
    }

    Ok(())
}

fn validate_len_value(
    prog: &Program,
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    target: usize,
    size: usize,
    kind: LengthKind,
    value: u64,
) -> Result<(), ValidationError> {
    validate_native_size(size, "length argument")
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))?;
    let Some(target_type) = desc.args.get(target) else {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!("length argument targets missing argument {}", target),
        ));
    };
    let Some(target_value) = prog.calls[call_idx].args.get(target) else {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!("length argument targets missing runtime value {}", target),
        ));
    };
    let Some(expected) = derived_arg_length(target_type, target_value, kind) else {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!("cannot derive length from argument {}", target),
        ));
    };
    if value != expected as u64 {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "expected derived length {} from argument {}, got {}",
                expected, target, value
            ),
        ));
    }
    Ok(())
}

fn validate_pointer_buffer(
    prog: &Program,
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
) -> Result<(), ValidationError> {
    if dir == PtrDir::Out {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            "pure output pointers should reserve storage instead of supplying input bytes",
        ));
    }
    match inner {
        ArgType::Buffer {
            min_size, max_size, ..
        } => validate_buffer_size(data.len(), *min_size, *max_size)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        ArgType::Len { target, size, kind } => {
            if data.len() != *size {
                return Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    format!(
                        "length pointer buffer has size {}, expected {}",
                        data.len(),
                        size
                    ),
                ));
            }
            validate_len_value(
                prog,
                call_idx,
                desc,
                arg_idx,
                *target,
                *size,
                *kind,
                decode_scalar_bytes(data),
            )
        }
        _ => {
            let Some(expected_size) = arg_type_fixed_size(inner) else {
                return Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    "pointer data requires a fixed-size inner type",
                ));
            };
            if data.len() != expected_size {
                return Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    format!(
                        "pointer data has size {}, expected fixed size {}",
                        data.len(),
                        expected_size
                    ),
                ));
            }
            Ok(())
        }
    }
}

fn validate_resource_desc(resource: &ResourceDesc) -> Result<(), String> {
    if resource.kind.trim().is_empty() {
        return Err("resource kind is empty".to_string());
    }
    if resource.lineage.is_empty() {
        return Err(format!("resource '{}' has empty lineage", resource.kind));
    }
    if resource.lineage.last() != Some(&resource.kind) {
        return Err(format!(
            "resource '{}' lineage must end with its own kind",
            resource.kind
        ));
    }
    validate_native_size(resource.size, &format!("resource '{}'", resource.kind))
}

fn validate_native_size(size: usize, what: &str) -> Result<(), String> {
    if (1..=8).contains(&size) {
        Ok(())
    } else {
        Err(format!("{} has unsupported native size {}", what, size))
    }
}

fn validate_buffer_range(min_size: usize, max_size: usize) -> Result<(), String> {
    if min_size > max_size {
        Err(format!(
            "buffer size range is invalid: min {} is greater than max {}",
            min_size, max_size
        ))
    } else {
        Ok(())
    }
}

fn validate_buffer_size(size: usize, min_size: usize, max_size: usize) -> Result<(), String> {
    validate_buffer_range(min_size, max_size)?;
    if size < min_size || size > max_size {
        Err(format!(
            "buffer has size {}, expected {}..={}",
            size, min_size, max_size
        ))
    } else {
        Ok(())
    }
}

fn invalid_arg(
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    detail: impl Into<String>,
) -> ValidationError {
    ValidationError::new(format!(
        "call #{} {} argument {} is invalid: {}",
        call_idx,
        desc.name,
        arg_idx,
        detail.into()
    ))
}

fn describe_arg_type(arg_type: &ArgType) -> &'static str {
    match arg_type {
        ArgType::Const { .. } => "const",
        ArgType::Len { .. } => "length",
        ArgType::Resource(_) => "resource",
        ArgType::Array { .. } => "array",
        ArgType::Struct { .. } => "struct",
        ArgType::Ptr { .. } => "pointer",
        ArgType::Buffer { .. } => "buffer",
        ArgType::Filename => "filename",
    }
}

fn describe_arg_value(arg_value: &ArgValue) -> &'static str {
    match arg_value {
        ArgValue::Const(_) => "const",
        ArgValue::ResultRef(_) => "result reference",
        ArgValue::Buffer(_) => "buffer",
        ArgValue::Filename(_) => "filename",
        ArgValue::OutPtr => "out pointer",
        ArgValue::Null => "null",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe2_exposes_two_resource_outputs() {
        let descs = get_syscall_descs();
        let pipe2 = descs.iter().find(|desc| desc.name == "pipe2").unwrap();
        let outputs = resource_outputs(pipe2);

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].resource.kind, "fd");
        assert_eq!(outputs[1].resource.kind, "fd");
        match outputs[1].source {
            ResourceSource::PointerElement {
                arg_idx,
                element_idx,
                offset,
            } => {
                assert_eq!(arg_idx, 0);
                assert_eq!(element_idx, 1);
                assert_eq!(offset, 4);
            }
            ref other => panic!("unexpected output source: {:?}", other),
        }
    }

    #[test]
    fn socketpair_exposes_two_sock_outputs() {
        let descs = get_syscall_descs();
        let socketpair = descs.iter().find(|desc| desc.name == "socketpair").unwrap();
        let outputs = resource_outputs(socketpair);

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].resource.kind, "sock");
        assert_eq!(outputs[1].resource.kind, "sock");
    }

    #[test]
    fn struct_pointer_outputs_expose_resource_offsets() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                socketpair(domain const[1], type const[1], proto int32, fds ptr[out, sock_pair])
                sock_pair {
                    fd0 sock
                    fd1 sock
                }
            "#,
        )
        .expect("test target should parse");
        let outputs = resource_outputs(&descs[0]);

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].resource.kind, "sock");
        assert_eq!(outputs[1].resource.kind, "sock");
        match outputs[1].source {
            ResourceSource::PointerElement {
                arg_idx,
                element_idx,
                offset,
            } => {
                assert_eq!(arg_idx, 3);
                assert_eq!(element_idx, 1);
                assert_eq!(offset, 4);
            }
            ref other => panic!("unexpected output source: {:?}", other),
        }
    }

    #[test]
    fn derived_resource_can_flow_into_parent_consumer() {
        let fd = ResourceDesc {
            kind: "fd".to_string(),
            size: 4,
            values: vec![(-1i64) as u64],
            lineage: vec!["fd".to_string()],
        };
        let sock = ResourceDesc {
            kind: "sock".to_string(),
            size: 4,
            values: vec![(-1i64) as u64],
            lineage: vec!["fd".to_string(), "sock".to_string()],
        };

        assert!(fd.accepts(&sock));
        assert!(!sock.accepts(&fd));
    }

    #[test]
    fn constructor_lookup_respects_resource_subtyping() {
        let descs = get_syscall_descs();
        let socket = descs.iter().find(|desc| desc.name == "socket").unwrap();
        let close = descs.iter().find(|desc| desc.name == "close").unwrap();

        let fd_input = match &close.args[0] {
            ArgType::Resource(resource) => resource.clone(),
            other => panic!("unexpected close arg: {:?}", other),
        };
        let sock_output = match &socket.ret {
            ReturnType::Resource(resource) => resource.clone(),
            other => panic!("unexpected socket return: {:?}", other),
        };

        let fd_ctors = resource_constructor_syscalls(&descs, &fd_input);
        let sock_ctors = resource_constructor_syscalls(&descs, &sock_output);

        assert!(fd_ctors.contains(&6)); // socket -> sock can satisfy fd consumers
        assert!(sock_ctors.contains(&6));
        assert!(!sock_ctors.contains(&9)); // eventfd2 -> fd is not precise enough for sock
    }

    #[test]
    fn transitively_disables_calls_without_resource_constructors() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall close@2 -> int(fd)
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);

        assert_eq!(availability.enabled, vec![0]);
        assert_eq!(
            availability
                .disabled
                .get(&1)
                .expect("close should be disabled"),
            "requires resource 'fd' but no compatible constructors are available"
        );
    }

    #[test]
    fn transitively_disables_calls_behind_unreachable_constructors() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource gate[4] = -1
                resource token[4] = -1
                syscall getpid@1 -> int()
                syscall mint@2 -> token(gate)
                syscall use_token@3 -> int(token)
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);

        assert_eq!(availability.enabled, vec![0]);
        assert_eq!(
            availability
                .disabled
                .get(&1)
                .expect("mint should be disabled"),
            "requires resource 'gate' but no compatible constructors are available"
        );
        assert!(availability
            .disabled
            .get(&2)
            .expect("use_token should be disabled")
            .contains("constructors are not transitively enabled: mint"));
    }

    #[test]
    fn generatable_availability_respects_no_generate_attrs() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall eventfd2@2 -> fd(const[4; 0], const[4; 0]) (no_generate)
                syscall close@3 -> int(fd)
            "#,
        )
        .expect("test target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0, 1, 2]);
        assert_eq!(generatable.enabled, vec![0]);
        assert_eq!(
            generatable
                .disabled
                .get(&1)
                .expect("eventfd2 should be excluded from generation"),
            "marked no_generate"
        );
        assert!(generatable
            .disabled
            .get(&2)
            .expect("close should not be generatable without a live fd constructor")
            .contains("constructors are not transitively enabled: eventfd2"));
    }

    #[test]
    fn static_priorities_favor_resource_followups() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                syscall listen@2 -> int(sock, const[4; 1, 8])
                syscall close@3 -> int(fd)
                syscall getpid@4 -> int()
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);
        let priorities = static_syscall_priorities(&descs, &availability.enabled);

        assert!(priorities[0][1] > priorities[0][3]);
        assert!(priorities[0][2] > priorities[0][3]);
        assert!(priorities[0][0] > 0);
    }

    #[test]
    fn dynamic_priorities_follow_corpus_sequences() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall alpha@1 -> int()
                syscall beta@2 -> int()
                syscall gamma@3 -> int()
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);
        let corpus = vec![Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
            ],
        }];
        let priorities = dynamic_syscall_priorities(&descs, &availability.enabled, &corpus);

        assert!(priorities[0][1] > 0);
        assert_eq!(priorities[0][2], 0);
        assert_eq!(priorities[1][0], 0);
    }

    #[test]
    fn choice_table_caches_dynamic_followups() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall alpha@1 -> int()
                syscall beta@2 -> int()
                syscall gamma@3 -> int()
            "#,
        )
        .expect("test target should parse");
        let corpus = vec![Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![],
                },
            ],
        }];
        let table = SyscallChoiceTable::build(&descs, &corpus);

        assert!(table.generatable(0));
        assert!(table.weight(0, 1) > table.weight(0, 2));
        assert_eq!(table.enabled_syscalls(), &[0, 1, 2]);
    }

    #[test]
    fn avoidance_priorities_penalize_failed_edges() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                resource sock[fd]
                sock_pair {
                    fd0 sock
                    fd1 sock
                }
                socketpair(domain const[1], type const[1], proto int32, fds ptr[out, sock_pair])
                bind(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
                connect(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let availability = transitively_generatable_syscalls(&descs);
        let timeout_edge_failures = HashMap::from([
            ("socketpair->bind".to_string(), 1),
            ("bind->connect".to_string(), 2),
        ]);

        let priorities = avoidance_adjusted_syscall_priorities(
            &descs,
            &availability.enabled,
            &[],
            &timeout_edge_failures,
            &HashMap::new(),
        );

        assert!(priorities[0][1] < priorities[0][2]);
        assert_eq!(priorities[1][2], 0);
    }

    #[test]
    fn avoidance_priorities_penalize_failed_syscalls_across_sources() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                resource sock[fd]
                sock_pair {
                    fd0 sock
                    fd1 sock
                }
                socketpair(domain const[1], type const[1], proto int32, fds ptr[out, sock_pair])
                bind(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
                connect(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let availability = transitively_generatable_syscalls(&descs);
        let timeout_syscall_failures = HashMap::from([("bind".to_string(), 1)]);

        let priorities = avoidance_adjusted_syscall_priorities(
            &descs,
            &availability.enabled,
            &[],
            &HashMap::new(),
            &timeout_syscall_failures,
        );

        assert!(priorities[0][1] < priorities[0][2]);
        assert!(priorities[2][1] < priorities[2][2]);
    }

    #[test]
    fn choice_table_build_with_avoidance_downweights_failed_followups() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                resource sock[fd]
                sock_pair {
                    fd0 sock
                    fd1 sock
                }
                socketpair(domain const[1], type const[1], proto int32, fds ptr[out, sock_pair])
                bind(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
                connect(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let timeout_edge_failures = HashMap::from([("socketpair->bind".to_string(), 1)]);

        let table = SyscallChoiceTable::build_with_avoidance(
            &descs,
            &[],
            &timeout_edge_failures,
            &HashMap::new(),
        );

        assert!(table.generatable(0));
        assert!(table.weight(0, 1) < table.weight(0, 2));
        assert_eq!(table.enabled_syscalls(), &[0, 1, 2]);
    }

    #[test]
    fn choice_table_build_with_avoidance_downweights_failed_startup_syscalls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                resource sock[fd]
                sock_pair {
                    fd0 sock
                    fd1 sock
                }
                socketpair(domain const[1], type const[1], proto int32, fds ptr[out, sock_pair])
                bind(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
                connect(fd sock, addr ptr[in, buffer[16:16]], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let timeout_syscall_failures = HashMap::from([("bind".to_string(), 1)]);

        let table = SyscallChoiceTable::build_with_avoidance(
            &descs,
            &[],
            &HashMap::new(),
            &timeout_syscall_failures,
        );

        assert!(table.startup_weight(1) < table.startup_weight(2));
    }

    #[test]
    fn rejects_forward_result_reference() {
        let descs = get_syscall_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: 9, // eventfd2 -> fd
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
            ],
        };

        let err = validate_program(&prog, &descs).expect_err("forward refs must be rejected");
        assert!(err
            .to_string()
            .contains("resource result reference must point to an earlier call"));
    }

    #[test]
    fn rejects_argument_value_type_mismatch() {
        let descs = get_syscall_descs();
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 1, // close(fd)
                args: vec![ArgValue::Buffer(vec![0, 1, 2, 3])],
            }],
        };

        let err = validate_program(&prog, &descs).expect_err("type mismatches must be rejected");
        assert!(err.to_string().contains("expected resource, got buffer"));
    }

    #[test]
    fn accepts_pointer_output_result_reference() {
        let descs = get_syscall_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 4, // pipe2([fd, fd], flags)
                    args: vec![ArgValue::OutPtr, ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 1,
                    })],
                },
            ],
        };

        prog.validate(&descs)
            .expect("pipe2 output fds should be valid resource refs");
    }

    #[test]
    fn validates_derived_length_arguments_and_optional_null_pointers() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                type sockaddr_storage buffer[16:16]
                bind(fd sock, addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
                accept(fd sock, peer ptr[out, sockaddr_storage, opt], peerlen ptr[inout, len[peer, int32]]) sock
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![
                        ArgValue::Const(0),
                        ArgValue::Buffer(vec![0u8; 16]),
                        ArgValue::Const(16),
                    ],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![
                        ArgValue::Const(0),
                        ArgValue::Null,
                        ArgValue::Buffer(encode_scalar_bytes(4, 0)),
                    ],
                },
            ],
        };

        prog.validate(&descs)
            .expect("derived lengths and optional null pointers should validate");
    }

    #[test]
    fn distinguishes_len_from_bytesize_for_pointer_arrays() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall measure@1(items ptr[in, array[int32, 3]], count len[items, int32], size bytesize[items, int32])
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Buffer(vec![0u8; 12]),
                    ArgValue::Const(3),
                    ArgValue::Const(12),
                ],
            }],
        };

        prog.validate(&descs)
            .expect("len should count array elements while bytesize counts bytes");
    }

    #[test]
    fn rejects_mismatched_derived_length_argument() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                type sockaddr_storage buffer[16:16]
                bind(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(0),
                    ArgValue::Buffer(vec![0u8; 16]),
                    ArgValue::Const(8),
                ],
            }],
        };

        let err = prog
            .validate(&descs)
            .expect_err("wrong derived lengths must be rejected");
        assert!(err.to_string().contains("expected derived length 16"));
    }

    #[test]
    fn accepts_socket_result_as_fd_argument() {
        let descs = get_syscall_descs();
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: 6, // socket(...) -> sock
                    args: vec![ArgValue::Const(2), ArgValue::Const(1), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: 1, // close(fd)
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 0,
                        result_idx: 0,
                    })],
                },
            ],
        };

        prog.validate(&descs)
            .expect("socket result should be usable where fd is expected");
    }
}
