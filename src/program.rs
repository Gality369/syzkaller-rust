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
        values: Vec<u64>, // possible values (empty = ranged, unconstrained, or unavailable)
        range: Option<(u64, u64)>,
        endian: ScalarEndian,
        allow_any: bool,
        bitfield_bits: Option<u8>,
    },
    /// Per-process scalar value with a process-relative subrange.
    Proc {
        size: usize,
        values_start: u64,
        values_per_proc: u64,
        endian: ScalarEndian,
    },
    /// Resource handle passed between calls.
    Resource(ResourceDesc),
    /// Resource handle that may legally fall back to its default/null value.
    OptionalResource(ResourceDesc),
    /// Array of a supported inner type, optionally ranged.
    Array {
        inner: Box<ArgType>,
        min_len: usize,
        max_len: usize,
    },
    /// Pointer to another argument type.
    Ptr {
        inner: Box<ArgType>,
        dir: PtrDir,
        optional: bool,
    },
    /// Zero-sized placeholder field used in some struct layouts.
    Void,
    /// Fixed-size struct layout serialized into bytes.
    Struct {
        type_name: Option<String>,
        fields: Vec<ArgType>,
        field_names: Vec<String>,
        size: usize,
        varlen: bool,
        packed: bool,
        align: Option<usize>,
        overlay_start: Option<usize>,
    },
    /// Union layout serialized into bytes. Fixed unions use `size`, varlen unions
    /// materialize one field-sized payload without padding.
    Union {
        type_name: Option<String>,
        fields: Vec<ArgType>,
        field_names: Vec<String>,
        size: usize,
        varlen: bool,
        packed: bool,
        align: Option<usize>,
    },
    /// Virtual memory area address with an associated mapped length.
    Vma {
        min_pages: usize,
        max_pages: usize,
        optional: bool,
    },
    /// Length of another argument's materialized data.
    Len {
        target: LengthTarget,
        size: usize,
        kind: LengthKind,
        endian: ScalarEndian,
        scale: usize,
        bitfield_bits: Option<u8>,
    },
    /// Raw data buffer.
    Buffer {
        min_size: usize,
        max_size: usize,
        dir: BufferDir,
    },
    /// String-like data, optionally fixed-size and/or non-NUL-terminated.
    String {
        values: Vec<Vec<u8>>,
        noz: bool,
        fixed_len: Option<usize>,
        filename: bool,
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
    Offset,
}

pub const PROC_DEFAULT_VALUE: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthTarget {
    pub root: LengthTargetRoot,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LengthTargetRoot {
    Arg(String),
    Current,
    Parent(usize),
    Type(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyscallAttrs {
    pub automatic_helper: bool,
    pub no_generate: bool,
    pub disabled: bool,
    pub ignore_return: bool,
    pub breaks_returns: bool,
    pub no_minimize: bool,
    pub no_squash: bool,
    pub remote_cover: bool,
    pub snapshot: bool,
    pub kfuzz_test: bool,
    pub timeout_ms: Option<u64>,
    pub prog_timeout_ms: Option<u64>,
    pub fsck_command: Option<String>,
}

/// Syscall descriptor.
#[derive(Debug, Clone)]
pub struct SyscallDesc {
    pub name: String,
    pub id: u64, // syzkaller internal ID (index into executor's syscalls[] table for linux/amd64)
    pub arg_names: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlinePointerValue {
    pub offset: usize,
    pub value: Box<ArgValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineStructLayout {
    pub base_offset: usize,
    pub field_ranges: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceSource {
    ReturnValue,
    PointerElement {
        arg_idx: usize,
        element_idx: usize,
        offset: usize,
        pointer_chain: Vec<usize>,
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
    Composite {
        data: Vec<u8>,
        pointers: Vec<InlinePointerValue>,
        struct_layouts: Vec<InlineStructLayout>,
    },
    Array {
        data: Vec<u8>,
        pointers: Vec<InlinePointerValue>,
        element_sizes: Vec<usize>,
        struct_layouts: Vec<InlineStructLayout>,
    },
    Filename(String),
    Vma {
        addr: u64,
        size: u64,
    },
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
    pub(crate) fn new(message: impl Into<String>) -> Self {
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
/// Number of available pages in the executor data mapping, matching syzkaller's default 16MB arena.
pub const VMA_NUM_PAGES: u64 = (16 << 20) / PAGE_SIZE;
pub const VMA_MAX_BYTES: u64 = VMA_NUM_PAGES * PAGE_SIZE;
pub const VMA_RESERVED_START_PAGE: u64 = 256;

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
        ArgType::Ptr { .. }
        | ArgType::Buffer { .. }
        | ArgType::String { .. }
        | ArgType::Filename => true,
        ArgType::Array { inner, .. } => arg_type_is_timeout_prone(inner),
        ArgType::Struct { fields, .. } => fields.iter().any(arg_type_is_timeout_prone),
        ArgType::Union { fields, .. } => fields.iter().any(arg_type_is_timeout_prone),
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

#[derive(Clone, Copy)]
struct BitfieldSpec {
    unit_size: usize,
    endian: ScalarEndian,
    bit_len: u8,
}

fn arg_type_bitfield_spec(arg_type: &ArgType) -> Option<BitfieldSpec> {
    match arg_type {
        ArgType::Const {
            size,
            endian,
            bitfield_bits: Some(bit_len),
            ..
        }
        | ArgType::Len {
            size,
            endian,
            bitfield_bits: Some(bit_len),
            ..
        } => Some(BitfieldSpec {
            unit_size: *size,
            endian: *endian,
            bit_len: *bit_len,
        }),
        _ => None,
    }
}

pub(crate) fn scale_length_value(value: usize, scale: usize) -> usize {
    if scale <= 1 {
        value
    } else {
        value / scale
    }
}

fn inferred_string_storage_len(
    values: &[Vec<u8>],
    noz: bool,
    fixed_len: Option<usize>,
) -> Option<usize> {
    if let Some(fixed_len) = fixed_len {
        return Some(fixed_len);
    }
    let mut iter = values.iter();
    let first = iter.next()?;
    let encoded_len = first.len().checked_add(usize::from(!noz))?;
    if iter.all(|value| value.len().checked_add(usize::from(!noz)) == Some(encoded_len)) {
        Some(encoded_len)
    } else {
        None
    }
}

pub fn arg_type_fixed_size(arg_type: &ArgType) -> Option<usize> {
    match arg_type {
        ArgType::Const { size, .. } => Some(*size),
        ArgType::Proc { size, .. } => Some(*size),
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => Some(resource.size),
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } if min_len == max_len => arg_type_fixed_size(inner)?.checked_mul(*min_len),
        ArgType::Ptr { .. } => Some(8),
        ArgType::Void => Some(0),
        ArgType::Struct { size, varlen, .. } if !*varlen => Some(*size),
        ArgType::Union { size, varlen, .. } if !*varlen => Some(*size),
        ArgType::Vma { .. } => Some(8),
        ArgType::Len { size, .. } => Some(*size),
        ArgType::String {
            values,
            noz,
            fixed_len,
            ..
        } => inferred_string_storage_len(values, *noz, *fixed_len),
        ArgType::Buffer {
            min_size, max_size, ..
        } if min_size == max_size => Some(*max_size),
        _ => None,
    }
}

pub fn arg_type_alignment(arg_type: &ArgType) -> Option<usize> {
    match arg_type {
        ArgType::Const { size, .. } => Some(*size),
        ArgType::Proc { size, .. } => Some(*size),
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => Some(resource.size),
        ArgType::Array { inner, .. } => arg_type_alignment(inner),
        ArgType::Ptr { .. } => Some(8),
        ArgType::Void => Some(1),
        ArgType::Struct {
            fields,
            packed,
            align,
            ..
        } => struct_type_alignment(fields, *packed, *align).ok(),
        ArgType::Union {
            fields,
            packed,
            align,
            ..
        } => union_type_alignment(fields, *packed, *align).ok(),
        ArgType::Vma { .. } => Some(8),
        ArgType::Len { size, .. } => Some(*size),
        ArgType::Buffer { .. } | ArgType::String { .. } | ArgType::Filename => Some(1),
    }
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(value);
    }
    if !align.is_power_of_two() {
        return None;
    }
    let rounded = value.checked_add(align - 1)?;
    Some(rounded & !(align - 1))
}

pub(crate) fn struct_type_alignment(
    fields: &[ArgType],
    packed: bool,
    align: Option<usize>,
) -> Result<usize, String> {
    if let Some(align) = align {
        return validate_alignment_value(align).map(|_| align);
    }
    if packed {
        return Ok(1);
    }
    let mut struct_align = 1usize;
    for field in fields {
        let field_align = arg_type_alignment(field)
            .ok_or_else(|| "struct fields must have a known alignment".to_string())?;
        struct_align = struct_align.max(field_align);
    }
    Ok(struct_align)
}

pub(crate) fn union_type_alignment(
    fields: &[ArgType],
    packed: bool,
    align: Option<usize>,
) -> Result<usize, String> {
    if let Some(align) = align {
        return validate_alignment_value(align).map(|_| align);
    }
    if packed {
        return Ok(1);
    }
    let mut union_align = 1usize;
    for field in fields {
        let field_align = arg_type_alignment(field)
            .ok_or_else(|| "union fields must have a known alignment".to_string())?;
        union_align = union_align.max(field_align);
    }
    Ok(union_align)
}

fn validate_alignment_value(align: usize) -> Result<(), String> {
    if align == 0 || !align.is_power_of_two() {
        Err(format!(
            "alignment {} is invalid (must be a non-zero power of two)",
            align
        ))
    } else {
        Ok(())
    }
}

pub fn materialized_arg_size(arg_type: &ArgType, arg_value: &ArgValue) -> Option<usize> {
    match (arg_type, arg_value) {
        (ArgType::Ptr { inner: _, .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::Ptr { inner: _, .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
        (ArgType::Ptr { inner: _, .. }, ArgValue::Array { data, .. }) => Some(data.len()),
        (ArgType::Ptr { inner, .. }, ArgValue::OutPtr) => arg_type_fixed_size(inner),
        (ArgType::Ptr { .. }, ArgValue::Null) => Some(0),
        (ArgType::Vma { .. }, ArgValue::Vma { size, .. }) => usize::try_from(*size).ok(),
        (ArgType::Vma { .. }, ArgValue::Null) => Some(0),
        (ArgType::String { .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::String { .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
        (ArgType::String { .. }, ArgValue::Array { data, .. }) => Some(data.len()),
        (ArgType::Buffer { .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::Buffer { .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
        (ArgType::Buffer { .. }, ArgValue::Array { data, .. }) => Some(data.len()),
        (ArgType::Array { .. }, ArgValue::Array { data, .. }) => Some(data.len()),
        (ArgType::Array { .. }, ArgValue::Buffer(data)) => Some(data.len()),
        (ArgType::Array { .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
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
        LengthKind::Offset => None,
        LengthKind::Auto => match (arg_type, arg_value) {
            (ArgType::Array { .. }, ArgValue::Array { element_sizes, .. }) => {
                Some(element_sizes.len())
            }
            (
                ArgType::Array {
                    min_len, max_len, ..
                },
                _,
            ) if min_len == max_len => Some(*min_len),
            (ArgType::Ptr { inner, .. }, ArgValue::Buffer(data)) => match inner.as_ref() {
                ArgType::Array { inner, .. } => derive_array_len_from_bytes(inner, data),
                _ => Some(data.len()),
            },
            (ArgType::Ptr { inner, .. }, ArgValue::Composite { data, .. }) => {
                match inner.as_ref() {
                    ArgType::Array { inner, .. } => derive_array_len_from_bytes(inner, data),
                    _ => Some(data.len()),
                }
            }
            (
                ArgType::Ptr { inner, .. },
                ArgValue::Array {
                    data,
                    element_sizes,
                    ..
                },
            ) => match inner.as_ref() {
                ArgType::Array { .. } => Some(element_sizes.len()),
                _ => Some(data.len()),
            },
            (ArgType::Ptr { inner, .. }, ArgValue::OutPtr) => match inner.as_ref() {
                ArgType::Array {
                    min_len, max_len, ..
                } if min_len == max_len => Some(*min_len),
                _ => arg_type_fixed_size(inner),
            },
            (ArgType::Ptr { .. }, ArgValue::Null) => Some(0),
            (ArgType::Vma { .. }, ArgValue::Vma { size, .. }) => usize::try_from(*size).ok(),
            (ArgType::Vma { .. }, ArgValue::Null) => Some(0),
            (ArgType::String { .. }, ArgValue::Buffer(data)) => Some(data.len()),
            (ArgType::String { .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
            (ArgType::String { .. }, ArgValue::Array { data, .. }) => Some(data.len()),
            (ArgType::Buffer { .. }, ArgValue::Buffer(data)) => Some(data.len()),
            (ArgType::Buffer { .. }, ArgValue::Composite { data, .. }) => Some(data.len()),
            (ArgType::Buffer { .. }, ArgValue::Array { data, .. }) => Some(data.len()),
            (ArgType::Filename, ArgValue::Filename(name)) => Some(name.len() + 1),
            (arg_type, _) => arg_type_fixed_size(arg_type),
        },
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LengthTargetFrame<'a> {
    pub type_name: Option<&'a str>,
    pub fields: &'a [ArgType],
    pub field_names: &'a [String],
    pub size: usize,
    pub is_union: bool,
    pub varlen: bool,
    pub packed: bool,
    pub align: Option<usize>,
    pub overlay_start: Option<usize>,
    pub data: Option<&'a [u8]>,
    pub pointers: Option<&'a [InlinePointerValue]>,
    pub struct_layouts: Option<&'a [InlineStructLayout]>,
    pub base_offset: usize,
}

#[derive(Clone, Copy)]
struct ResolvedLengthValue<'a> {
    arg_type: &'a ArgType,
    arg_value: Option<&'a ArgValue>,
    data: Option<&'a [u8]>,
    null_pointer: bool,
}

pub(crate) fn derive_target_length(
    desc: &SyscallDesc,
    args: &[ArgValue],
    target: &LengthTarget,
    kind: LengthKind,
) -> Option<usize> {
    if kind == LengthKind::Offset {
        return derive_target_offset(desc, target);
    }
    let resolved = resolve_target_from_args(desc, args, target)?;
    derive_resolved_length(resolved, kind)
}

pub(crate) fn derive_inline_target_length(
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
    target: &LengthTarget,
    kind: LengthKind,
) -> Option<usize> {
    if kind == LengthKind::Offset {
        return derive_inline_target_offset(desc, frames, target);
    }
    if target.fields.is_empty() {
        if let Some(frame) = resolve_frame_root(frames, &target.root) {
            return derive_frame_length(frame, kind);
        }
    }
    let resolved = resolve_inline_target(desc, args, frames, target)?;
    derive_resolved_length(resolved, kind)
}

fn derive_target_offset(desc: &SyscallDesc, target: &LengthTarget) -> Option<usize> {
    match &target.root {
        LengthTargetRoot::Arg(name) => {
            let arg_idx = desc_arg_index(desc, name)?;
            compute_path_offset(desc.args.get(arg_idx)?, &target.fields)
        }
        LengthTargetRoot::Current | LengthTargetRoot::Parent(_) | LengthTargetRoot::Type(_) => None,
    }
}

fn derive_inline_target_offset(
    desc: Option<&SyscallDesc>,
    frames: &[LengthTargetFrame<'_>],
    target: &LengthTarget,
) -> Option<usize> {
    match &target.root {
        LengthTargetRoot::Arg(name) => {
            let desc = desc?;
            let arg_idx = desc_arg_index(desc, name)?;
            compute_path_offset(desc.args.get(arg_idx)?, &target.fields)
        }
        LengthTargetRoot::Current | LengthTargetRoot::Parent(_) | LengthTargetRoot::Type(_) => {
            let frame = resolve_frame_root(frames, &target.root)?;
            compute_path_offset_in_container(
                frame.fields,
                frame.field_names,
                frame.is_union,
                frame.varlen,
                frame.packed,
                frame.align,
                frame.overlay_start,
                frame.struct_layouts,
                frame.base_offset,
                frame.size,
                &target.fields,
            )
        }
    }
}

fn resolve_target_from_args<'a>(
    desc: &'a SyscallDesc,
    args: &'a [ArgValue],
    target: &LengthTarget,
) -> Option<ResolvedLengthValue<'a>> {
    let LengthTargetRoot::Arg(name) = &target.root else {
        return None;
    };
    let arg_idx = desc_arg_index(desc, name)?;
    let arg_type = desc.args.get(arg_idx)?;
    let arg_value = args.get(arg_idx)?;
    if target.fields.is_empty() {
        return Some(ResolvedLengthValue {
            arg_type,
            arg_value: Some(arg_value),
            data: arg_value_bytes(arg_value),
            null_pointer: false,
        });
    }
    let (root_type, root_data, root_pointers, root_struct_layouts) = match (arg_type, arg_value) {
        (ArgType::Ptr { inner, .. }, ArgValue::Buffer(data)) => {
            (inner.as_ref(), Some(data.as_slice()), None, None)
        }
        (
            ArgType::Ptr { inner, .. },
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            },
        ) => (
            inner.as_ref(),
            Some(data.as_slice()),
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
        ),
        (
            ArgType::Ptr { inner, .. },
            ArgValue::Array {
                data,
                pointers,
                struct_layouts,
                ..
            },
        ) => (
            inner.as_ref(),
            Some(data.as_slice()),
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
        ),
        (ArgType::Ptr { inner, .. }, ArgValue::OutPtr) => (inner.as_ref(), None, None, None),
        (ArgType::Ptr { .. }, ArgValue::Null) => return None,
        _ => (
            arg_type,
            arg_value_bytes(arg_value),
            arg_value_pointers(arg_value),
            arg_value_struct_layouts(arg_value),
        ),
    };
    resolve_path_value(
        root_type,
        root_data,
        root_pointers,
        root_struct_layouts,
        0,
        &target.fields,
    )
}

fn resolve_inline_target<'a>(
    desc: Option<&'a SyscallDesc>,
    args: Option<&'a [ArgValue]>,
    frames: &[LengthTargetFrame<'a>],
    target: &LengthTarget,
) -> Option<ResolvedLengthValue<'a>> {
    match &target.root {
        LengthTargetRoot::Arg(_) => resolve_target_from_args(desc?, args?, target),
        LengthTargetRoot::Current | LengthTargetRoot::Parent(_) | LengthTargetRoot::Type(_) => {
            let frame = resolve_frame_root(frames, &target.root)?;
            resolve_path_in_container(
                frame.fields,
                frame.field_names,
                frame.is_union,
                frame.varlen,
                frame.packed,
                frame.align,
                frame.overlay_start,
                frame.data,
                frame.pointers,
                frame.struct_layouts,
                frame.base_offset,
                &target.fields,
            )
        }
    }
}

fn resolve_frame_root<'a>(
    frames: &[LengthTargetFrame<'a>],
    root: &LengthTargetRoot,
) -> Option<LengthTargetFrame<'a>> {
    match root {
        LengthTargetRoot::Current => frames.last().copied(),
        LengthTargetRoot::Parent(hops) => {
            if *hops == 0 || *hops > frames.len() {
                None
            } else {
                frames.get(frames.len() - *hops).copied()
            }
        }
        LengthTargetRoot::Type(type_name) => frames
            .iter()
            .rev()
            .copied()
            .find(|frame| frame.type_name == Some(type_name.as_str())),
        LengthTargetRoot::Arg(_) => None,
    }
}

fn resolve_path_in_container<'a>(
    fields: &'a [ArgType],
    field_names: &'a [String],
    is_union: bool,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    data: Option<&'a [u8]>,
    pointers: Option<&'a [InlinePointerValue]>,
    struct_layouts: Option<&'a [InlineStructLayout]>,
    base_offset: usize,
    path: &[String],
) -> Option<ResolvedLengthValue<'a>> {
    let field_idx = find_field_index(field_names, &path[0])?;
    let field = fields.get(field_idx)?;
    let field_offset = if is_union {
        0
    } else if let Some(field_ranges) =
        lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
    {
        field_ranges
            .get(field_idx)
            .copied()
            .map(|(start, _)| start.checked_sub(base_offset))??
    } else if let Some(data) = data {
        compute_struct_field_ranges(fields, varlen, packed, align, overlay_start, data.len())?
            .get(field_idx)
            .copied()
            .map(|(start, _)| start)?
    } else {
        compute_struct_field_offset(fields, field_idx, varlen, packed, overlay_start)?
    };
    let field_data = if is_union {
        slice_union_field_data(field, data)?
    } else {
        slice_struct_field_data(
            fields,
            field_idx,
            varlen,
            packed,
            align,
            overlay_start,
            data,
            struct_layouts,
            base_offset,
        )?
    };
    resolve_path_value(
        field,
        field_data,
        pointers,
        struct_layouts,
        base_offset + field_offset,
        &path[1..],
    )
}

fn resolve_path_value<'a>(
    arg_type: &'a ArgType,
    data: Option<&'a [u8]>,
    pointers: Option<&'a [InlinePointerValue]>,
    struct_layouts: Option<&'a [InlineStructLayout]>,
    base_offset: usize,
    path: &[String],
) -> Option<ResolvedLengthValue<'a>> {
    if let ArgType::Ptr { inner, .. } = arg_type {
        let pointer_value = inline_pointer_value_at_offset(pointers, base_offset);
        if path.is_empty() {
            let null_pointer = match pointer_value {
                Some(ArgValue::Null) => true,
                Some(_) => false,
                None => {
                    data.is_some_and(|bytes| bytes.len() == 8 && decode_scalar_bytes(bytes) == 0)
                }
            };
            return Some(ResolvedLengthValue {
                arg_type,
                arg_value: pointer_value,
                data: pointer_value.and_then(arg_value_bytes),
                null_pointer,
            });
        }
        let pointer_value = pointer_value?;
        return match pointer_value {
            ArgValue::Buffer(data) => {
                resolve_path_value(inner, Some(data.as_slice()), None, None, 0, path)
            }
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            } => resolve_path_value(
                inner,
                Some(data.as_slice()),
                Some(pointers.as_slice()),
                Some(struct_layouts.as_slice()),
                0,
                path,
            ),
            ArgValue::Array {
                data,
                pointers,
                struct_layouts,
                ..
            } => resolve_path_value(
                inner,
                Some(data.as_slice()),
                Some(pointers.as_slice()),
                Some(struct_layouts.as_slice()),
                0,
                path,
            ),
            _ => None,
        };
    }
    if path.is_empty() {
        return Some(ResolvedLengthValue {
            arg_type,
            arg_value: None,
            data,
            null_pointer: false,
        });
    }
    match arg_type {
        ArgType::Struct {
            fields,
            field_names,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            let field_idx = find_field_index(field_names, &path[0])?;
            let field = fields.get(field_idx)?;
            let field_data = slice_struct_field_data(
                fields,
                field_idx,
                *varlen,
                *packed,
                *align,
                *overlay_start,
                data,
                struct_layouts,
                base_offset,
            )?;
            let field_offset = if let Some(field_ranges) =
                lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
            {
                field_ranges
                    .get(field_idx)
                    .copied()
                    .map(|(start, _)| start.checked_sub(base_offset))??
            } else {
                data.and_then(|data| {
                    compute_struct_field_ranges(
                        fields,
                        *varlen,
                        *packed,
                        *align,
                        *overlay_start,
                        data.len(),
                    )
                    .and_then(|ranges| ranges.get(field_idx).copied())
                    .map(|(start, _)| start)
                })?
            };
            resolve_path_value(
                field,
                field_data,
                pointers,
                struct_layouts,
                base_offset + field_offset,
                &path[1..],
            )
        }
        ArgType::Union {
            fields,
            field_names,
            ..
        } => {
            let field_idx = find_field_index(field_names, &path[0])?;
            let field = fields.get(field_idx)?;
            let field_data = slice_union_field_data(field, data)?;
            resolve_path_value(
                field,
                field_data,
                pointers,
                struct_layouts,
                base_offset,
                &path[1..],
            )
        }
        _ => None,
    }
}

fn inline_pointer_value_at_offset<'a>(
    pointers: Option<&'a [InlinePointerValue]>,
    offset: usize,
) -> Option<&'a ArgValue> {
    pointers?
        .iter()
        .find(|pointer| pointer.offset == offset)
        .map(|pointer| pointer.value.as_ref())
}

fn compute_path_offset(arg_type: &ArgType, path: &[String]) -> Option<usize> {
    if path.is_empty() {
        return Some(0);
    }
    match arg_type {
        ArgType::Ptr { inner, .. } => compute_path_offset(inner, path),
        ArgType::Struct {
            fields,
            field_names,
            varlen,
            packed,
            overlay_start,
            ..
        } => {
            let field_idx = find_field_index(field_names, &path[0])?;
            Some(
                compute_struct_field_offset(fields, field_idx, *varlen, *packed, *overlay_start)?
                    + compute_path_offset(fields.get(field_idx)?, &path[1..])?,
            )
        }
        ArgType::Union {
            fields,
            field_names,
            ..
        } => {
            let field_idx = find_field_index(field_names, &path[0])?;
            compute_path_offset(fields.get(field_idx)?, &path[1..])
        }
        _ => None,
    }
}

fn compute_path_offset_in_container(
    fields: &[ArgType],
    field_names: &[String],
    is_union: bool,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    struct_layouts: Option<&[InlineStructLayout]>,
    base_offset: usize,
    size: usize,
    path: &[String],
) -> Option<usize> {
    let field_idx = find_field_index(field_names, &path[0])?;
    let field_offset = if is_union {
        0
    } else if let Some(field_ranges) =
        lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
    {
        field_ranges
            .get(field_idx)
            .copied()
            .map(|(start, _)| start.checked_sub(base_offset))??
    } else {
        compute_struct_field_ranges(fields, varlen, packed, align, overlay_start, size)?
            .get(field_idx)
            .copied()
            .map(|(start, _)| start)?
    };
    Some(field_offset + compute_path_offset(fields.get(field_idx)?, &path[1..])?)
}

fn derive_resolved_length(resolved: ResolvedLengthValue<'_>, kind: LengthKind) -> Option<usize> {
    if resolved.null_pointer {
        return Some(0);
    }
    if let Some(arg_value) = resolved.arg_value {
        return derived_arg_length(resolved.arg_type, arg_value, kind);
    }
    if let Some(data) = resolved.data {
        return derive_inline_length(resolved.arg_type, data, kind);
    }
    derive_static_length(resolved.arg_type, kind)
}

fn derive_frame_length(frame: LengthTargetFrame<'_>, kind: LengthKind) -> Option<usize> {
    match kind {
        LengthKind::Bytes => frame.data.map(|data| data.len()).or(Some(frame.size)),
        LengthKind::Offset => None,
        LengthKind::Auto => Some(frame.size),
    }
}

fn derive_inline_length(arg_type: &ArgType, data: &[u8], kind: LengthKind) -> Option<usize> {
    match kind {
        LengthKind::Bytes => Some(data.len()),
        LengthKind::Offset => None,
        LengthKind::Auto => match arg_type {
            ArgType::Array { inner, .. } => derive_array_len_from_bytes(inner, data),
            _ => Some(data.len()),
        },
    }
}

fn derive_static_length(arg_type: &ArgType, kind: LengthKind) -> Option<usize> {
    match kind {
        LengthKind::Bytes => arg_type_fixed_size(arg_type),
        LengthKind::Offset => None,
        LengthKind::Auto => match arg_type {
            ArgType::Array {
                min_len, max_len, ..
            } if min_len == max_len => Some(*min_len),
            _ => arg_type_fixed_size(arg_type),
        },
    }
}

fn derive_array_len_from_bytes(inner: &ArgType, data: &[u8]) -> Option<usize> {
    let elem_size = arg_type_fixed_size(inner)?;
    if elem_size == 0 {
        return Some(0);
    }
    if data.len() % elem_size != 0 {
        return None;
    }
    Some(data.len() / elem_size)
}

fn desc_arg_index(desc: &SyscallDesc, name: &str) -> Option<usize> {
    desc.arg_names.iter().position(|arg_name| arg_name == name)
}

fn arg_value_bytes(arg_value: &ArgValue) -> Option<&[u8]> {
    match arg_value {
        ArgValue::Buffer(data) => Some(data.as_slice()),
        ArgValue::Composite { data, .. } => Some(data.as_slice()),
        ArgValue::Array { data, .. } => Some(data.as_slice()),
        _ => None,
    }
}

fn arg_value_pointers(arg_value: &ArgValue) -> Option<&[InlinePointerValue]> {
    match arg_value {
        ArgValue::Composite { pointers, .. } => Some(pointers.as_slice()),
        ArgValue::Array { pointers, .. } => Some(pointers.as_slice()),
        _ => None,
    }
}

fn arg_value_struct_layouts(arg_value: &ArgValue) -> Option<&[InlineStructLayout]> {
    match arg_value {
        ArgValue::Composite { struct_layouts, .. } => Some(struct_layouts.as_slice()),
        ArgValue::Array { struct_layouts, .. } => Some(struct_layouts.as_slice()),
        _ => None,
    }
}

pub(crate) fn lookup_inline_struct_layout<'a>(
    struct_layouts: Option<&'a [InlineStructLayout]>,
    base_offset: usize,
    field_count: usize,
) -> Option<&'a [(usize, usize)]> {
    struct_layouts?
        .iter()
        .find(|layout| {
            layout.base_offset == base_offset && layout.field_ranges.len() == field_count
        })
        .map(|layout| layout.field_ranges.as_slice())
}

fn arg_type_type_name(arg_type: &ArgType) -> Option<&str> {
    match arg_type {
        ArgType::Struct { type_name, .. } | ArgType::Union { type_name, .. } => {
            type_name.as_deref()
        }
        _ => None,
    }
}

fn find_field_index(field_names: &[String], name: &str) -> Option<usize> {
    field_names.iter().position(|field_name| field_name == name)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BitfieldFieldInfo {
    pub(crate) unit_size: usize,
    pub(crate) endian: ScalarEndian,
    pub(crate) bit_len: u8,
    pub(crate) bit_offset: usize,
    pub(crate) is_last_in_group: bool,
}

pub(crate) fn standalone_bitfield_field_info(
    size: usize,
    endian: ScalarEndian,
    bit_len: u8,
) -> Option<BitfieldFieldInfo> {
    if bit_len == 0 || usize::from(bit_len) > size.checked_mul(8)? {
        return None;
    }
    Some(BitfieldFieldInfo {
        unit_size: size,
        endian,
        bit_len,
        bit_offset: 0,
        is_last_in_group: true,
    })
}

pub(crate) fn encode_bitfield_storage_value(
    storage: &mut [u8],
    info: BitfieldFieldInfo,
    value: u64,
) -> Option<()> {
    if storage.len() != info.unit_size {
        return None;
    }
    let unit_bits = info.unit_size.checked_mul(8)?;
    let bit_len = usize::from(info.bit_len);
    if bit_len == 0 || info.bit_offset.checked_add(bit_len)? > unit_bits {
        return None;
    }

    let field_mask = if bit_len >= 64 {
        u128::from(u64::MAX)
    } else {
        (1u128 << bit_len) - 1
    };
    let shift = match info.endian {
        ScalarEndian::Native => info.bit_offset,
        ScalarEndian::Big => unit_bits.checked_sub(info.bit_offset.checked_add(bit_len)?)?,
    };
    let storage_mask = field_mask.checked_shl(shift as u32)?;
    let current = u128::from(decode_scalar_bytes_endian(storage, info.endian));
    let next = (current & !storage_mask) | ((u128::from(value) & field_mask) << shift);
    let encoded = encode_scalar_bytes_endian(info.unit_size, next as u64, info.endian);
    storage.copy_from_slice(&encoded);
    Some(())
}

pub(crate) fn compute_bitfield_field_info(
    fields: &[ArgType],
) -> Option<Vec<Option<BitfieldFieldInfo>>> {
    let mut infos = vec![None; fields.len()];
    let mut group_start_idx = None;
    let mut group_unit_size = 0usize;
    let mut group_endian = ScalarEndian::Native;
    let mut group_bits_used = 0usize;
    let mut last_idx = None;

    let finalize_group = |infos: &mut [Option<BitfieldFieldInfo>], last_idx: Option<usize>| {
        if let Some(last_idx) = last_idx {
            if let Some(info) = infos.get_mut(last_idx).and_then(Option::as_mut) {
                info.is_last_in_group = true;
            }
        }
    };

    for (idx, field) in fields.iter().enumerate() {
        let Some(spec) = arg_type_bitfield_spec(field) else {
            finalize_group(&mut infos, last_idx);
            group_start_idx = None;
            group_unit_size = 0;
            group_bits_used = 0;
            continue;
        };
        let unit_bits = spec.unit_size.checked_mul(8)?;
        if usize::from(spec.bit_len) > unit_bits {
            return None;
        }
        let compatible = group_start_idx.is_some()
            && group_unit_size == spec.unit_size
            && group_endian == spec.endian
            && group_bits_used.checked_add(usize::from(spec.bit_len))? <= unit_bits;
        if !compatible {
            finalize_group(&mut infos, last_idx);
            group_start_idx = Some(idx);
            group_unit_size = spec.unit_size;
            group_endian = spec.endian;
            group_bits_used = 0;
        }
        infos[idx] = Some(BitfieldFieldInfo {
            unit_size: spec.unit_size,
            endian: spec.endian,
            bit_len: spec.bit_len,
            bit_offset: group_bits_used,
            is_last_in_group: false,
        });
        group_bits_used = group_bits_used.checked_add(usize::from(spec.bit_len))?;
        last_idx = Some(idx);
    }
    finalize_group(&mut infos, last_idx);
    Some(infos)
}

fn effective_field_fixed_size(
    field: &ArgType,
    bitfield_info: Option<BitfieldFieldInfo>,
) -> Option<usize> {
    match bitfield_info {
        Some(info) => Some(if info.is_last_in_group {
            info.unit_size
        } else {
            0
        }),
        None => arg_type_fixed_size(field),
    }
}

fn effective_field_alignment(
    field: &ArgType,
    packed: bool,
    bitfield_info: Option<BitfieldFieldInfo>,
) -> Option<usize> {
    if packed {
        return Some(1);
    }
    match bitfield_info {
        Some(info) => Some(info.unit_size),
        None => arg_type_alignment(field),
    }
}

pub(crate) fn compute_struct_field_ranges(
    fields: &[ArgType],
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    total_size: usize,
) -> Option<Vec<(usize, usize)>> {
    let bitfield_info = compute_bitfield_field_info(fields)?;
    if let Some(overlay_start) = overlay_start {
        if varlen {
            return None;
        }
        let mut ranges = Vec::with_capacity(fields.len());
        for (idx, field) in fields.iter().enumerate() {
            let start =
                compute_struct_field_offset(fields, idx, false, packed, Some(overlay_start))?;
            let size = effective_field_fixed_size(field, bitfield_info[idx])?;
            let end = start.checked_add(size)?;
            ranges.push((start, end));
        }
        return Some(ranges);
    }
    if !varlen {
        let mut ranges = Vec::with_capacity(fields.len());
        for (idx, field) in fields.iter().enumerate() {
            let start = compute_struct_field_offset(fields, idx, false, packed, None)?;
            let size = effective_field_fixed_size(field, bitfield_info[idx])?;
            let end = start.checked_add(size)?;
            ranges.push((start, end));
        }
        return Some(ranges);
    }

    if packed {
        let var_indices = fields
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| arg_type_fixed_size(field).is_none().then_some(idx))
            .collect::<Vec<_>>();
        let var_idx = match var_indices.as_slice() {
            [var_idx] => *var_idx,
            _ => return None,
        };

        let mut ranges = Vec::with_capacity(fields.len());
        let mut offset = 0usize;
        for (field, info) in fields[..var_idx]
            .iter()
            .zip(bitfield_info[..var_idx].iter().copied())
        {
            let size = effective_field_fixed_size(field, info)?;
            let end = offset.checked_add(size)?;
            ranges.push((offset, end));
            offset = end;
        }

        let suffix_size = fields[var_idx + 1..]
            .iter()
            .zip(bitfield_info[var_idx + 1..].iter().copied())
            .try_fold(0usize, |acc, field| {
                let (field, info) = field;
                let size = effective_field_fixed_size(field, info)?;
                acc.checked_add(size)
            })?;
        let struct_align = struct_type_alignment(fields, true, align).ok()?;
        let var_size = infer_packed_var_field_size(
            &fields[var_idx],
            offset,
            suffix_size,
            total_size,
            struct_align,
        )?;
        let var_end = offset.checked_add(var_size)?;
        if var_end > total_size {
            return None;
        }
        ranges.push((offset, var_end));
        offset = var_end;

        for (field, info) in fields[var_idx + 1..]
            .iter()
            .zip(bitfield_info[var_idx + 1..].iter().copied())
        {
            let size = effective_field_fixed_size(field, info)?;
            let end = offset.checked_add(size)?;
            ranges.push((offset, end));
            offset = end;
        }
        if align_up(offset, struct_align)? != total_size {
            return None;
        }
        return Some(ranges);
    }

    let mut ranges = Vec::with_capacity(fields.len());
    for (idx, field) in fields.iter().enumerate() {
        let start = compute_struct_field_offset(fields, idx, true, false, None)?;
        let end = match effective_field_fixed_size(field, bitfield_info[idx]) {
            Some(size) => start.checked_add(size)?,
            None if idx + 1 == fields.len() => total_size,
            None => return None,
        };
        if end < start {
            return None;
        }
        ranges.push((start, end));
    }
    Some(ranges)
}

fn slice_struct_field_data<'a>(
    fields: &[ArgType],
    field_idx: usize,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    data: Option<&'a [u8]>,
    struct_layouts: Option<&'a [InlineStructLayout]>,
    base_offset: usize,
) -> Option<Option<&'a [u8]>> {
    let data = match data {
        Some(data) => data,
        None => return Some(None),
    };
    let (start, end) = if let Some(field_ranges) =
        lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
    {
        let (start, end) = *field_ranges.get(field_idx)?;
        (
            start.checked_sub(base_offset)?,
            end.checked_sub(base_offset)?,
        )
    } else {
        *compute_struct_field_ranges(fields, varlen, packed, align, overlay_start, data.len())?
            .get(field_idx)?
    };
    Some(Some(data.get(start..end)?))
}

pub(crate) fn compute_struct_field_offset(
    fields: &[ArgType],
    field_idx: usize,
    varlen: bool,
    packed: bool,
    overlay_start: Option<usize>,
) -> Option<usize> {
    let bitfield_info = compute_bitfield_field_info(fields)?;
    let mut offset = 0usize;
    for (idx, field) in fields.iter().enumerate() {
        if overlay_start == Some(idx) {
            offset = 0;
        }
        let field_align = effective_field_alignment(field, packed, bitfield_info[idx])?;
        offset = align_up(offset, field_align)?;
        if idx == field_idx {
            return Some(offset);
        }
        match effective_field_fixed_size(field, bitfield_info[idx]) {
            Some(field_size) => {
                offset = offset.checked_add(field_size)?;
            }
            None if varlen && idx + 1 == fields.len() => return None,
            None => return None,
        }
    }
    None
}

fn packed_struct_var_field_index(fields: &[ArgType]) -> Option<usize> {
    let var_indices = fields
        .iter()
        .enumerate()
        .filter_map(|(idx, field)| arg_type_fixed_size(field).is_none().then_some(idx))
        .collect::<Vec<_>>();
    match var_indices.as_slice() {
        [idx] => Some(*idx),
        _ => None,
    }
}

fn infer_packed_var_field_size(
    field: &ArgType,
    prefix_size: usize,
    suffix_size: usize,
    total_size: usize,
    struct_align: usize,
) -> Option<usize> {
    let max_padding = struct_align.saturating_sub(1);
    for tail_padding in (0..=max_padding).rev() {
        let logical_size = total_size.checked_sub(tail_padding)?;
        if align_up(logical_size, struct_align)? != total_size {
            continue;
        }
        let Some(prefix_and_suffix) = prefix_size.checked_add(suffix_size) else {
            return None;
        };
        let Some(var_size) = logical_size.checked_sub(prefix_and_suffix) else {
            continue;
        };
        if arg_type_accepts_inline_size(field, var_size) {
            return Some(var_size);
        }
    }
    None
}

fn arg_type_accepts_inline_size(arg_type: &ArgType, size: usize) -> bool {
    let mut seen = HashSet::new();
    arg_type_accepts_inline_size_inner(arg_type, size, &mut seen)
}

fn arg_type_accepts_inline_size_inner(
    arg_type: &ArgType,
    size: usize,
    seen: &mut HashSet<usize>,
) -> bool {
    let key = arg_type as *const ArgType as usize;
    if !seen.insert(key) {
        return false;
    }
    let accepted = match arg_type {
        _ if arg_type_fixed_size(arg_type).is_some() => arg_type_fixed_size(arg_type) == Some(size),
        ArgType::Buffer {
            min_size, max_size, ..
        } => size >= *min_size && size <= *max_size,
        ArgType::String { noz, fixed_len, .. } => match fixed_len {
            Some(fixed_len) => size == *fixed_len,
            None if *noz => true,
            None => size >= 1,
        },
        ArgType::Filename => size >= 1,
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            if let Some(elem_size) = arg_type_fixed_size(inner) {
                elem_size == 0
                    || (size % elem_size == 0 && {
                        let count = size / elem_size;
                        count >= *min_len && count <= *max_len
                    })
            } else if size == 0 {
                *min_len == 0
            } else if min_len == max_len && *min_len == 1 {
                arg_type_accepts_inline_size_inner(inner, size, seen)
            } else {
                false
            }
        }
        ArgType::Struct {
            fields,
            size: declared_size,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            if let Ok((prefix_size, has_var_fields)) =
                struct_layout_prefix_size(fields, *packed, *align, *overlay_start)
            {
                let struct_align = match struct_type_alignment(fields, *packed, *align) {
                    Ok(struct_align) => struct_align,
                    Err(_) => return false,
                };
                if !*varlen && !has_var_fields {
                    *declared_size == size
                } else if size < prefix_size || (struct_align > 1 && size % struct_align != 0) {
                    false
                } else if let Some(ranges) = compute_struct_field_ranges(
                    fields,
                    *varlen,
                    *packed,
                    *align,
                    *overlay_start,
                    size,
                ) {
                    fields
                        .iter()
                        .zip(ranges.iter())
                        .all(|(field, (start, end))| {
                            arg_type_accepts_inline_size_inner(
                                field,
                                end.saturating_sub(*start),
                                seen,
                            )
                        })
                } else {
                    false
                }
            } else {
                false
            }
        }
        ArgType::Union {
            fields,
            size: union_size,
            varlen,
            packed,
            align,
            ..
        } => {
            let union_align = match union_type_alignment(fields, *packed, *align) {
                Ok(union_align) => union_align,
                Err(_) => return false,
            };
            if *varlen {
                if union_align > 1 && size % union_align != 0 {
                    false
                } else {
                    fields
                        .iter()
                        .any(|field| arg_type_accepts_inline_size_inner(field, size, seen))
                }
            } else if *union_size != size {
                false
            } else {
                fields.iter().any(|field| {
                    arg_type_fixed_size(field).is_some_and(|field_size| field_size <= size)
                        || arg_type_accepts_inline_size_inner(field, size, seen)
                })
            }
        }
        _ => false,
    };
    seen.remove(&key);
    accepted
}

fn slice_union_field_data<'a>(field: &ArgType, data: Option<&'a [u8]>) -> Option<Option<&'a [u8]>> {
    let data = match data {
        Some(data) => data,
        None => return Some(None),
    };
    let field_size = arg_type_fixed_size(field)?;
    Some(Some(data.get(..field_size)?))
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
    decode_scalar_bytes_endian(data, ScalarEndian::Native)
}

pub fn decode_scalar_bytes_endian(data: &[u8], endian: ScalarEndian) -> u64 {
    let mut bytes = [0u8; 8];
    let len = data.len().min(bytes.len());
    if endian == ScalarEndian::Big {
        for (dst, src) in bytes[..len]
            .iter_mut()
            .rev()
            .zip(data[..len].iter().copied())
        {
            *dst = src;
        }
    } else {
        bytes[..len].copy_from_slice(&data[..len]);
    }
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
    let mut pointer_chain = Vec::new();
    collect_pointer_resource_outputs_inner(
        arg_type,
        arg_idx,
        0,
        &mut next_element_idx,
        &mut pointer_chain,
        outputs,
    );
}

fn collect_pointer_resource_outputs_inner(
    arg_type: &ArgType,
    arg_idx: usize,
    base_offset: usize,
    next_element_idx: &mut usize,
    pointer_chain: &mut Vec<usize>,
    outputs: &mut Vec<ResourceOutput>,
) {
    match arg_type {
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            outputs.push(ResourceOutput {
                resource: resource.clone(),
                source: ResourceSource::PointerElement {
                    arg_idx,
                    element_idx: *next_element_idx,
                    offset: base_offset,
                    pointer_chain: pointer_chain.clone(),
                },
            });
            *next_element_idx += 1;
        }
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } if min_len == max_len => {
            let Some(element_size) = arg_type_fixed_size(inner) else {
                return;
            };
            for element_idx in 0..*min_len {
                collect_pointer_resource_outputs_inner(
                    inner,
                    arg_idx,
                    base_offset + (element_idx * element_size),
                    next_element_idx,
                    pointer_chain,
                    outputs,
                );
            }
        }
        ArgType::Struct {
            fields,
            varlen,
            packed,
            overlay_start,
            ..
        } => {
            for (idx, field) in fields.iter().enumerate() {
                let Some(field_offset) =
                    compute_struct_field_offset(fields, idx, *varlen, *packed, *overlay_start)
                else {
                    return;
                };
                collect_pointer_resource_outputs_inner(
                    field,
                    arg_idx,
                    base_offset + field_offset,
                    next_element_idx,
                    pointer_chain,
                    outputs,
                );
            }
        }
        ArgType::Union { fields, .. } => {
            for field in fields {
                collect_pointer_resource_outputs_inner(
                    field,
                    arg_idx,
                    base_offset,
                    next_element_idx,
                    pointer_chain,
                    outputs,
                );
            }
        }
        ArgType::Ptr {
            inner,
            dir: PtrDir::Out | PtrDir::InOut,
            ..
        } => {
            pointer_chain.push(base_offset);
            collect_pointer_resource_outputs_inner(
                inner,
                arg_idx,
                0,
                next_element_idx,
                pointer_chain,
                outputs,
            );
            pointer_chain.pop();
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
        ArgType::OptionalResource(_) => {}
        ArgType::Array { inner, .. } => collect_input_resources(inner, seen, resources),
        ArgType::Struct { fields, .. } => {
            for field in fields {
                collect_input_resources(field, seen, resources);
            }
        }
        ArgType::Union { fields, .. } => {
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
        ArgType::OptionalResource(_) => false,
        ArgType::Array { inner, .. } => arg_type_contains_resource_input(inner),
        ArgType::Struct { fields, .. } => fields.iter().any(arg_type_contains_resource_input),
        ArgType::Union { fields, .. } => fields.iter().any(arg_type_contains_resource_input),
        ArgType::Ptr { inner, dir, .. } => {
            *dir != PtrDir::Out && arg_type_contains_resource_input(inner)
        }
        _ => false,
    }
}

fn const_has_no_valid_values(values: &[u64], range: Option<(u64, u64)>, allow_any: bool) -> bool {
    values.is_empty() && range.is_none() && !allow_any
}

fn proc_has_no_valid_values(values_per_proc: u64) -> bool {
    values_per_proc == 0
}

pub(crate) fn arg_type_generation_limitation(arg_type: &ArgType) -> Option<String> {
    match arg_type {
        ArgType::Array { inner, .. } | ArgType::Ptr { inner, .. } => {
            arg_type_generation_limitation(inner)
        }
        ArgType::Const {
            values,
            range,
            allow_any,
            bitfield_bits: _,
            ..
        } => {
            if const_has_no_valid_values(values, *range, *allow_any) {
                Some("contains a constant with no valid values on this target".to_string())
            } else {
                None
            }
        }
        ArgType::Proc {
            values_per_proc, ..
        } => {
            if proc_has_no_valid_values(*values_per_proc) {
                Some(
                    "contains a per-process scalar with no valid values on this target".to_string(),
                )
            } else {
                None
            }
        }
        ArgType::Struct {
            fields,
            varlen: _,
            packed: _,
            align: _,
            overlay_start,
            ..
        } => {
            if overlay_start.is_some() {
                return Some("contains out_overlay struct fields".to_string());
            }
            for field in fields {
                if let Some(reason) = arg_type_generation_limitation(field) {
                    return Some(reason);
                }
            }
            None
        }
        ArgType::Union { fields, .. } => {
            let mut first_reason = None;
            for field in fields {
                match arg_type_generation_limitation(field) {
                    None => return None,
                    Some(reason) if first_reason.is_none() => first_reason = Some(reason),
                    Some(_) => {}
                }
            }
            first_reason
        }
        _ => None,
    }
}

fn syscall_generation_limitation(desc: &SyscallDesc) -> Option<String> {
    for arg in &desc.args {
        if let Some(reason) = arg_type_generation_limitation(arg) {
            return Some(reason);
        }
    }
    None
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
    } else if generatable_only && desc.attrs.fsck_command.is_some() {
        Some("requires fsck helper support".to_string())
    } else if generatable_only && desc.attrs.snapshot {
        Some("requires snapshot-mode support".to_string())
    } else if generatable_only && desc.attrs.no_squash {
        Some("requires no_squash executor support".to_string())
    } else if generatable_only && desc.attrs.remote_cover {
        Some("requires remote coverage support".to_string())
    } else if generatable_only && desc.attrs.kfuzz_test {
        Some("requires kfuzz_test support".to_string())
    } else if generatable_only {
        syscall_generation_limitation(desc)
            .map(|reason| format!("{reason}, which generation does not support yet"))
    } else {
        None
    }
}

fn resources_overlap(expected: &ResourceDesc, actual: &ResourceDesc) -> bool {
    expected.accepts(actual) || actual.accepts(expected)
}

fn validate_bitfield_spec(
    size: usize,
    bitfield_bits: Option<u8>,
    label: &str,
) -> Result<(), String> {
    if let Some(bits) = bitfield_bits {
        if bits == 0 || usize::from(bits) > size * 8 {
            return Err(format!(
                "{label} bitfield width {} exceeds {}-byte storage",
                bits, size
            ));
        }
    }
    Ok(())
}

fn validate_arg_type(arg_type: &ArgType) -> Result<(), String> {
    match arg_type {
        ArgType::Const {
            size,
            bitfield_bits,
            ..
        } => {
            validate_native_size(*size, "const argument")?;
            validate_bitfield_spec(*size, *bitfield_bits, "const argument")
        }
        ArgType::Proc { size, .. } => validate_native_size(*size, "proc argument"),
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            validate_resource_desc(resource)
        }
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            if min_len > max_len {
                return Err("array minimum length exceeds maximum length".to_string());
            }
            validate_arg_type(inner)?;
            Ok(())
        }
        ArgType::Void => Ok(()),
        ArgType::Struct {
            fields,
            size,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            if fields.is_empty() {
                return Err("struct must have at least one field".to_string());
            }
            for field in fields {
                validate_arg_type(field)?;
            }
            validate_alignment_value(struct_type_alignment(fields, *packed, *align)?)?;
            let (prefix_size, has_var_tail) =
                struct_layout_prefix_size(fields, *packed, *align, *overlay_start)?;
            if prefix_size > *size {
                return Err(format!(
                    "struct fields require at least {} bytes but declared size is {}",
                    prefix_size, size
                ));
            }
            if *varlen != has_var_tail {
                return Err("struct varlen flag does not match field layout".to_string());
            }
            Ok(())
        }
        ArgType::Union {
            fields,
            size,
            varlen,
            packed,
            align,
            ..
        } => {
            if fields.is_empty() {
                return Err("union must have at least one field".to_string());
            }
            let max_field_size = fields.iter().try_fold(0usize, |acc, field| {
                validate_arg_type(field)?;
                let field_size = match arg_type_fixed_size(field) {
                    Some(field_size) => field_size,
                    None if *varlen => 0,
                    None => return Err("union fields must be fixed-size".to_string()),
                };
                Ok::<usize, String>(acc.max(field_size))
            })?;
            if *size < max_field_size {
                return Err(format!(
                    "union fields require up to {} bytes but declared size is {}",
                    max_field_size, size
                ));
            }
            if !*varlen && *size == 0 {
                return Err("union size must be greater than zero".to_string());
            }
            let union_align = union_type_alignment(fields, *packed, *align)?;
            if !*varlen && align_up(*size, union_align) != Some(*size) {
                return Err(format!(
                    "union declared size {} is not aligned to {}",
                    size, union_align
                ));
            }
            Ok(())
        }
        ArgType::Vma {
            min_pages,
            max_pages,
            ..
        } => {
            if *min_pages == 0 || *max_pages == 0 {
                return Err("vma page counts must be greater than zero".to_string());
            }
            if min_pages > max_pages {
                return Err(format!(
                    "vma minimum page count {} exceeds maximum {}",
                    min_pages, max_pages
                ));
            }
            Ok(())
        }
        ArgType::Ptr { inner, .. } => validate_arg_type(inner),
        ArgType::Len {
            size,
            bitfield_bits,
            scale,
            ..
        } => {
            if *scale == 0 {
                return Err("length scale must be greater than zero".to_string());
            }
            validate_native_size(*size, "length argument")?;
            validate_bitfield_spec(*size, *bitfield_bits, "length argument")
        }
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename: _,
        } => validate_string_type(values, *noz, *fixed_len),
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
        (
            ArgType::Const {
                values,
                range,
                allow_any,
                ..
            },
            ArgValue::Const(_),
        ) => {
            if const_has_no_valid_values(values, *range, *allow_any) {
                Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    "constant has no valid values on this target".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        (
            ArgType::Proc {
                values_per_proc, ..
            },
            ArgValue::Const(value),
        ) => {
            if proc_has_no_valid_values(*values_per_proc) {
                Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    "per-process scalar has no valid values on this target".to_string(),
                ))
            } else if *value != PROC_DEFAULT_VALUE && *value >= *values_per_proc {
                Err(invalid_arg(
                    call_idx,
                    desc,
                    arg_idx,
                    format!(
                        "per-process scalar value {} exceeds per-proc range {}",
                        value, values_per_proc
                    ),
                ))
            } else {
                Ok(())
            }
        }
        (
            ArgType::Len {
                target,
                size,
                kind,
                scale,
                ..
            },
            ArgValue::Const(value),
        ) => validate_len_value(
            prog, call_idx, desc, arg_idx, target, *size, *kind, *scale, *value,
        ),
        (ArgType::Array { .. }, ArgValue::Buffer(data)) => validate_inline_buffer(
            arg_type,
            data,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Array { .. },
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            },
        ) => validate_inline_value(
            arg_type,
            data,
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
            0,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Array {
                inner,
                min_len,
                max_len,
            },
            ArgValue::Array {
                data,
                pointers,
                element_sizes,
                struct_layouts,
            },
        ) => validate_array_value(
            inner,
            *min_len,
            *max_len,
            data,
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
            element_sizes,
            0,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (ArgType::Resource(resource) | ArgType::OptionalResource(resource), ArgValue::Const(_)) => {
            validate_resource_desc(resource)
                .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))
        }
        (ArgType::Resource(resource) | ArgType::OptionalResource(resource), ArgValue::Null) => {
            validate_resource_desc(resource)
                .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))
        }
        (
            ArgType::Resource(resource) | ArgType::OptionalResource(resource),
            ArgValue::ResultRef(result_ref),
        ) => validate_result_ref(prog, descs, call_idx, desc, arg_idx, resource, result_ref),
        (
            ArgType::Ptr {
                inner,
                dir,
                optional: _,
            },
            ArgValue::Array {
                data,
                pointers,
                element_sizes,
                struct_layouts,
            },
        ) => validate_pointer_array(
            prog,
            call_idx,
            desc,
            arg_idx,
            inner,
            *dir,
            data,
            pointers,
            element_sizes,
            struct_layouts,
        ),
        (
            ArgType::Ptr {
                inner,
                dir,
                optional: _,
            },
            ArgValue::Buffer(data),
        ) => validate_pointer_buffer(prog, call_idx, desc, arg_idx, inner, *dir, data),
        (
            ArgType::Ptr {
                inner,
                dir,
                optional: _,
            },
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            },
        ) => validate_pointer_composite(
            prog,
            call_idx,
            desc,
            arg_idx,
            inner,
            *dir,
            data,
            pointers,
            struct_layouts,
        ),
        (
            ArgType::Struct {
                type_name,
                fields,
                field_names,
                size,
                varlen,
                packed,
                align,
                overlay_start,
                ..
            },
            ArgValue::Buffer(data),
        ) => validate_struct_buffer(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            *overlay_start,
            data,
            None,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Struct {
                type_name,
                fields,
                field_names,
                size,
                varlen,
                packed,
                align,
                overlay_start,
                ..
            },
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            },
        ) => validate_struct_buffer_with_pointers(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            *overlay_start,
            data,
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
            0,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Union {
                type_name,
                fields,
                field_names,
                size,
                varlen,
                packed,
                align,
                ..
            },
            ArgValue::Buffer(data),
        ) => validate_union_buffer(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            data,
            None,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Union {
                type_name,
                fields,
                field_names,
                size,
                varlen,
                packed,
                align,
                ..
            },
            ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            },
        ) => validate_union_buffer_with_pointers(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            data,
            Some(pointers.as_slice()),
            Some(struct_layouts.as_slice()),
            0,
            Some(desc),
            Some(&prog.calls[call_idx].args),
            &[],
        )
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (
            ArgType::Vma {
                min_pages,
                max_pages,
                optional: _,
            },
            ArgValue::Vma { addr, size },
        ) => validate_vma_value(*min_pages, *max_pages, *addr, *size)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        (ArgType::Vma { optional: true, .. }, ArgValue::Null) => Ok(()),
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
        (ArgType::String { noz, fixed_len, .. }, ArgValue::Buffer(data)) => {
            validate_string_buffer(data, *noz, *fixed_len)
                .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))
        }
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
    target: &LengthTarget,
    size: usize,
    kind: LengthKind,
    scale: usize,
    value: u64,
) -> Result<(), ValidationError> {
    validate_native_size(size, "length argument")
        .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))?;
    let Some(expected) = derive_target_length(desc, &prog.calls[call_idx].args, target, kind)
    else {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!("cannot derive length from target {:?}", target),
        ));
    };
    let expected = scale_length_value(expected, scale);
    if value != expected as u64 {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            format!(
                "expected derived length {} from target {:?}, got {}",
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
    validate_pointer_bytes(prog, call_idx, desc, arg_idx, inner, dir, data, None, None)
}

fn validate_pointer_array(
    prog: &Program,
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
    pointers: &[InlinePointerValue],
    element_sizes: &[usize],
    struct_layouts: &[InlineStructLayout],
) -> Result<(), ValidationError> {
    if dir == PtrDir::Out {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            "pure output pointers should reserve storage instead of supplying input bytes",
        ));
    }
    let ArgType::Array {
        inner: element_type,
        min_len,
        max_len,
    } = inner
    else {
        return Err(invalid_arg(
            call_idx,
            desc,
            arg_idx,
            "array value can only be used with pointer-to-array arguments",
        ));
    };
    validate_array_value(
        element_type,
        *min_len,
        *max_len,
        data,
        Some(pointers),
        Some(struct_layouts),
        element_sizes,
        0,
        Some(desc),
        Some(&prog.calls[call_idx].args),
        &[],
    )
    .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))
}

fn validate_pointer_composite(
    prog: &Program,
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
    pointers: &[InlinePointerValue],
    struct_layouts: &[InlineStructLayout],
) -> Result<(), ValidationError> {
    validate_pointer_bytes(
        prog,
        call_idx,
        desc,
        arg_idx,
        inner,
        dir,
        data,
        Some(pointers),
        Some(struct_layouts),
    )
}

fn validate_pointer_bytes(
    prog: &Program,
    call_idx: usize,
    desc: &SyscallDesc,
    arg_idx: usize,
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
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
        ArgType::String { noz, fixed_len, .. } => validate_string_buffer(data, *noz, *fixed_len)
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err)),
        ArgType::Len {
            target,
            size,
            kind,
            scale,
            ..
        } => {
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
                target,
                *size,
                *kind,
                *scale,
                decode_scalar_bytes(data),
            )
        }
        _ => {
            if let ArgType::Union {
                type_name,
                fields,
                field_names,
                size,
                varlen,
                packed,
                align,
                ..
            } = inner
            {
                return validate_union_buffer_with_pointers(
                    type_name.as_deref(),
                    fields,
                    field_names,
                    *size,
                    *varlen,
                    *packed,
                    *align,
                    data,
                    pointers,
                    struct_layouts,
                    0,
                    Some(desc),
                    Some(&prog.calls[call_idx].args),
                    &[],
                )
                .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err));
            }
            validate_inline_value(
                inner,
                data,
                pointers,
                struct_layouts,
                0,
                Some(desc),
                Some(&prog.calls[call_idx].args),
                &[],
            )
            .map_err(|err| invalid_arg(call_idx, desc, arg_idx, err))
        }
    }
}

fn validate_inline_buffer(
    arg_type: &ArgType,
    data: &[u8],
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    validate_inline_value(arg_type, data, None, None, 0, desc, args, frames)
}

fn validate_array_value(
    inner: &ArgType,
    min_len: usize,
    max_len: usize,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    element_sizes: &[usize],
    base_offset: usize,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    if element_sizes.len() < min_len || element_sizes.len() > max_len {
        return Err(format!(
            "array field has {} elements, expected {}..={}",
            element_sizes.len(),
            min_len,
            max_len
        ));
    }
    let mut offset = 0usize;
    for &element_size in element_sizes {
        let end = offset
            .checked_add(element_size)
            .ok_or_else(|| "array element size overflow".to_string())?;
        let chunk = data
            .get(offset..end)
            .ok_or_else(|| "array element exceeds backing storage".to_string())?;
        validate_inline_value(
            inner,
            chunk,
            pointers,
            struct_layouts,
            base_offset + offset,
            desc,
            args,
            frames,
        )?;
        offset = end;
    }
    if offset != data.len() {
        return Err(format!(
            "array backing storage has {} trailing bytes beyond {} elements",
            data.len().saturating_sub(offset),
            element_sizes.len()
        ));
    }
    Ok(())
}

fn validate_inline_value(
    arg_type: &ArgType,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    base_offset: usize,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    match arg_type {
        ArgType::Const {
            size,
            values,
            range,
            allow_any,
            bitfield_bits,
            ..
        } => {
            if bitfield_bits.is_some() && data.is_empty() {
                return Ok(());
            }
            validate_exact_inline_size(data.len(), *size, "const field")?;
            if const_has_no_valid_values(values, *range, *allow_any) {
                return Err("const field has no valid values on this target".to_string());
            }
            Ok(())
        }
        ArgType::Proc {
            size,
            values_per_proc,
            ..
        } => {
            validate_exact_inline_size(data.len(), *size, "proc field")?;
            if proc_has_no_valid_values(*values_per_proc) {
                return Err("proc field has no valid values on this target".to_string());
            }
            Ok(())
        }
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            validate_exact_inline_size(data.len(), resource.size, "resource field")
        }
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            let elem_size = arg_type_fixed_size(inner).ok_or_else(|| {
                "variable-size inline arrays require explicit element boundaries".to_string()
            })?;
            if elem_size == 0 {
                return validate_exact_inline_size(data.len(), 0, "array field");
            }
            if data.len() % elem_size != 0 {
                return Err(format!(
                    "array field size {} is not a multiple of element size {}",
                    data.len(),
                    elem_size
                ));
            }
            let actual_len = data.len() / elem_size;
            if actual_len < *min_len || actual_len > *max_len {
                return Err(format!(
                    "array field has {} elements, expected {}..={}",
                    actual_len, min_len, max_len
                ));
            }
            for (element_idx, chunk) in data.chunks_exact(elem_size).enumerate() {
                validate_inline_value(
                    inner,
                    chunk,
                    pointers,
                    struct_layouts,
                    base_offset + (element_idx * elem_size),
                    desc,
                    args,
                    frames,
                )?;
            }
            Ok(())
        }
        ArgType::Void => validate_exact_inline_size(data.len(), 0, "void field"),
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            validate_exact_inline_size(data.len(), 8, "inline pointer field")?;
            match inline_pointer_value_at_offset(pointers, base_offset) {
                Some(ArgValue::Buffer(pointer_data)) => validate_pointer_value_for_inline_field(
                    inner,
                    *dir,
                    pointer_data,
                    None,
                    None,
                    desc,
                    args,
                ),
                Some(ArgValue::Composite {
                    data: pointer_data,
                    pointers: pointer_pointers,
                    struct_layouts: pointer_struct_layouts,
                }) => validate_pointer_value_for_inline_field(
                    inner,
                    *dir,
                    pointer_data,
                    Some(pointer_pointers.as_slice()),
                    Some(pointer_struct_layouts.as_slice()),
                    desc,
                    args,
                ),
                Some(ArgValue::Array {
                    data: pointer_data,
                    pointers: pointer_pointers,
                    element_sizes,
                    struct_layouts: pointer_struct_layouts,
                }) => validate_pointer_array_value_for_inline_field(
                    inner,
                    *dir,
                    pointer_data,
                    Some(pointer_pointers.as_slice()),
                    Some(pointer_struct_layouts.as_slice()),
                    element_sizes,
                    desc,
                    args,
                ),
                Some(ArgValue::OutPtr) if matches!(dir, PtrDir::Out | PtrDir::InOut) => Ok(()),
                Some(ArgValue::Null) if *optional => Ok(()),
                Some(other) => Err(format!(
                    "inline pointer field uses unsupported nested value {}",
                    describe_arg_value(other)
                )),
                None if *optional && decode_scalar_bytes(data) == 0 => Ok(()),
                None => Err("inline pointer field is missing nested storage".to_string()),
            }
        }
        ArgType::Struct {
            type_name,
            fields,
            field_names,
            size,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => validate_struct_buffer_with_pointers(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            *overlay_start,
            data,
            pointers,
            struct_layouts,
            base_offset,
            desc,
            args,
            frames,
        ),
        ArgType::Union {
            type_name,
            fields,
            field_names,
            size,
            varlen,
            packed,
            align,
            ..
        } => validate_union_buffer_with_pointers(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            data,
            pointers,
            struct_layouts,
            base_offset,
            desc,
            args,
            frames,
        ),
        ArgType::Vma { .. } => validate_exact_inline_size(data.len(), 8, "vma field"),
        ArgType::Len {
            target,
            size,
            kind,
            endian,
            scale,
            bitfield_bits,
        } => {
            if bitfield_bits.is_some() && data.is_empty() {
                return Ok(());
            }
            validate_exact_inline_size(data.len(), *size, "length field")?;
            if bitfield_bits.is_some() {
                return Ok(());
            }
            let expected = derive_inline_target_length(desc, args, frames, target, *kind);
            if let Some(expected) = expected {
                let actual = decode_scalar_bytes_endian(data, *endian);
                let expected = scale_length_value(expected, *scale);
                if actual != expected as u64 {
                    return Err(format!(
                        "derived inline field has value {}, expected {}",
                        actual, expected
                    ));
                }
            }
            Ok(())
        }
        ArgType::Buffer {
            min_size, max_size, ..
        } => validate_buffer_size(data.len(), *min_size, *max_size),
        ArgType::String { noz, fixed_len, .. } => validate_string_buffer(data, *noz, *fixed_len),
        ArgType::Filename => {
            if data.is_empty() || data.last().copied() != Some(0) {
                return Err("inline filename field must be NUL-terminated".to_string());
            }
            Ok(())
        }
    }
}

fn validate_pointer_value_for_inline_field(
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
) -> Result<(), String> {
    if dir == PtrDir::Out {
        return Ok(());
    }
    match inner {
        ArgType::Buffer {
            min_size, max_size, ..
        } => validate_buffer_size(data.len(), *min_size, *max_size),
        ArgType::String { noz, fixed_len, .. } => validate_string_buffer(data, *noz, *fixed_len),
        ArgType::Len {
            target,
            size,
            kind,
            endian,
            scale,
            bitfield_bits,
        } => {
            if bitfield_bits.is_some() && data.is_empty() {
                return Ok(());
            }
            validate_exact_inline_size(data.len(), *size, "length pointer buffer")?;
            if bitfield_bits.is_some() {
                return Ok(());
            }
            let expected = derive_inline_target_length(desc, args, &[], target, *kind)
                .ok_or_else(|| format!("cannot derive length from target {:?}", target))?;
            let actual = decode_scalar_bytes_endian(data, *endian) as usize;
            let expected = scale_length_value(expected, *scale);
            if actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "derived pointer field has value {}, expected {}",
                    actual, expected
                ))
            }
        }
        ArgType::Union {
            type_name,
            fields,
            field_names,
            size,
            varlen,
            packed,
            align,
            ..
        } => validate_union_buffer_with_pointers(
            type_name.as_deref(),
            fields,
            field_names,
            *size,
            *varlen,
            *packed,
            *align,
            data,
            pointers,
            struct_layouts,
            0,
            desc,
            args,
            &[],
        ),
        _ => validate_inline_value(inner, data, pointers, struct_layouts, 0, desc, args, &[]),
    }
}

fn validate_pointer_array_value_for_inline_field(
    inner: &ArgType,
    dir: PtrDir,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    element_sizes: &[usize],
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
) -> Result<(), String> {
    if dir == PtrDir::Out {
        return Ok(());
    }
    let ArgType::Array {
        inner: element_type,
        min_len,
        max_len,
    } = inner
    else {
        return Err("inline array value requires a pointer-to-array field".to_string());
    };
    validate_array_value(
        element_type,
        *min_len,
        *max_len,
        data,
        pointers,
        struct_layouts,
        element_sizes,
        0,
        desc,
        args,
        &[],
    )
}

fn validate_struct_buffer(
    type_name: Option<&str>,
    fields: &[ArgType],
    field_names: &[String],
    size: usize,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    data: &[u8],
    struct_layouts: Option<&[InlineStructLayout]>,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    validate_struct_buffer_with_pointers(
        type_name,
        fields,
        field_names,
        size,
        varlen,
        packed,
        align,
        overlay_start,
        data,
        None,
        struct_layouts,
        0,
        desc,
        args,
        frames,
    )
}

fn validate_struct_buffer_with_pointers(
    type_name: Option<&str>,
    fields: &[ArgType],
    field_names: &[String],
    size: usize,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    base_offset: usize,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    let (prefix_size, has_var_fields) =
        struct_layout_prefix_size(fields, packed, align, overlay_start)?;
    let struct_align = struct_type_alignment(fields, packed, align)?;
    if !varlen && !has_var_fields {
        validate_exact_inline_size(data.len(), size, "struct buffer")?;
    } else if data.len() < prefix_size {
        return Err(format!(
            "struct buffer has size {}, expected at least {}",
            data.len(),
            prefix_size
        ));
    } else if struct_align > 1 && data.len() % struct_align != 0 {
        return Err(format!(
            "struct buffer has size {}, expected alignment {}",
            data.len(),
            struct_align
        ));
    }
    let mut next_frames = frames.to_vec();
    next_frames.push(LengthTargetFrame {
        type_name,
        fields,
        field_names,
        size: data.len(),
        is_union: false,
        varlen,
        packed,
        align,
        overlay_start,
        data: Some(data),
        pointers,
        struct_layouts,
        base_offset,
    });
    let ranges = if let Some(field_ranges) =
        lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
    {
        field_ranges
            .iter()
            .map(|(start, end)| {
                Ok((
                    start
                        .checked_sub(base_offset)
                        .ok_or_else(|| "struct field start underflow".to_string())?,
                    end.checked_sub(base_offset)
                        .ok_or_else(|| "struct field end underflow".to_string())?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        compute_struct_field_ranges(fields, varlen, packed, align, overlay_start, data.len())
            .ok_or_else(|| "struct field layout overflow".to_string())?
    };
    for (field, (offset, end)) in fields.iter().zip(ranges.into_iter()) {
        validate_inline_value(
            field,
            &data[offset..end],
            pointers,
            struct_layouts,
            base_offset + offset,
            desc,
            args,
            &next_frames,
        )?;
    }
    Ok(())
}

fn compute_field_offsets(fields: &[ArgType], packed: bool) -> Result<Vec<usize>, String> {
    let mut offsets = Vec::with_capacity(fields.len());
    for idx in 0..fields.len() {
        offsets.push(
            compute_struct_field_offset(fields, idx, false, packed, None)
                .ok_or_else(|| "field offset overflow".to_string())?,
        );
    }
    Ok(offsets)
}

pub(crate) fn struct_layout_prefix_size(
    fields: &[ArgType],
    packed: bool,
    align: Option<usize>,
    overlay_start: Option<usize>,
) -> Result<(usize, bool), String> {
    if let Some(overlay_start) = overlay_start {
        if overlay_start == 0 || overlay_start >= fields.len() {
            return Err("overlay field index is out of bounds".to_string());
        }
        if fields
            .iter()
            .any(|field| arg_type_fixed_size(field).is_none())
        {
            return Err("overlay structs with variable-sized fields are not supported".to_string());
        }
        let lhs = struct_layout_prefix_size(&fields[..overlay_start], packed, None, None)?.0;
        let rhs = struct_layout_prefix_size(&fields[overlay_start..], packed, None, None)?.0;
        let struct_align = struct_type_alignment(fields, packed, align)?;
        let prefix_size = align_up(lhs.max(rhs), struct_align)
            .ok_or_else(|| "struct size overflow".to_string())?;
        return Ok((prefix_size, false));
    }
    let bitfield_info = compute_bitfield_field_info(fields)
        .ok_or_else(|| "bitfield layout overflow".to_string())?;
    let mut prefix_size = 0usize;
    let mut saw_var_field = false;
    for (idx, field) in fields.iter().enumerate() {
        let field_align = effective_field_alignment(field, packed, bitfield_info[idx])
            .ok_or_else(|| "struct fields must have a known alignment".to_string())?;
        prefix_size =
            align_up(prefix_size, field_align).ok_or_else(|| "struct size overflow".to_string())?;
        match effective_field_fixed_size(field, bitfield_info[idx]) {
            Some(field_size) => {
                prefix_size = prefix_size
                    .checked_add(field_size)
                    .ok_or_else(|| "struct size overflow".to_string())?;
            }
            None => {
                if !packed && idx + 1 != fields.len() {
                    return Err(
                        "only trailing variable-sized struct fields are supported".to_string()
                    );
                }
                saw_var_field = true;
            }
        }
    }
    if !saw_var_field {
        let struct_align = struct_type_alignment(fields, packed, align)?;
        prefix_size = align_up(prefix_size, struct_align)
            .ok_or_else(|| "struct size overflow".to_string())?;
    }
    Ok((prefix_size, saw_var_field))
}

fn validate_exact_inline_size(actual: usize, expected: usize, label: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} has size {actual}, expected {expected}"))
    }
}

fn validate_union_buffer(
    type_name: Option<&str>,
    fields: &[ArgType],
    field_names: &[String],
    size: usize,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    data: &[u8],
    struct_layouts: Option<&[InlineStructLayout]>,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    validate_union_buffer_with_pointers(
        type_name,
        fields,
        field_names,
        size,
        varlen,
        packed,
        align,
        data,
        None,
        struct_layouts,
        0,
        desc,
        args,
        frames,
    )
}

fn validate_union_buffer_with_pointers(
    type_name: Option<&str>,
    fields: &[ArgType],
    field_names: &[String],
    size: usize,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
    data: &[u8],
    pointers: Option<&[InlinePointerValue]>,
    struct_layouts: Option<&[InlineStructLayout]>,
    base_offset: usize,
    desc: Option<&SyscallDesc>,
    args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
) -> Result<(), String> {
    let field_sizes = fields.iter().map(arg_type_fixed_size).collect::<Vec<_>>();
    if !varlen && field_sizes.iter().any(|field_size| field_size.is_none()) {
        return Err("union fields must be fixed-size".to_string());
    }
    let fixed_field_sizes = field_sizes.iter().copied().flatten().collect::<Vec<_>>();
    if varlen
        && !field_sizes.iter().any(|field_size| field_size.is_none())
        && !fixed_field_sizes.contains(&data.len())
    {
        return Err(format!(
            "varlen union buffer has size {}, expected one of {:?}",
            data.len(),
            fixed_field_sizes
        ));
    }
    if !varlen && data.len() != size {
        return Err(format!(
            "union buffer has size {}, expected {}",
            data.len(),
            size
        ));
    }
    let union_align = union_type_alignment(fields, packed, align)?;
    if !varlen && data.len() % union_align != 0 {
        return Err(format!(
            "union buffer has size {}, expected alignment {}",
            data.len(),
            union_align
        ));
    }

    let mut next_frames = frames.to_vec();
    next_frames.push(LengthTargetFrame {
        type_name,
        fields,
        field_names,
        size,
        is_union: true,
        varlen,
        packed,
        align,
        overlay_start: None,
        data: Some(data),
        pointers,
        struct_layouts,
        base_offset,
    });

    let mut matched = false;
    for (field, field_size) in fields.iter().zip(field_sizes.iter().copied()) {
        if varlen {
            match field_size {
                Some(field_size) if field_size != data.len() => continue,
                Some(field_size) => {
                    if let Some(field_data) = data.get(..field_size) {
                        if validate_inline_value(
                            field,
                            field_data,
                            pointers,
                            struct_layouts,
                            base_offset,
                            desc,
                            args,
                            &next_frames,
                        )
                        .is_ok()
                        {
                            matched = true;
                            break;
                        }
                    }
                }
                None => {
                    if validate_inline_value(
                        field,
                        data,
                        pointers,
                        struct_layouts,
                        base_offset,
                        desc,
                        args,
                        &next_frames,
                    )
                    .is_ok()
                    {
                        matched = true;
                        break;
                    }
                }
            }
            continue;
        }
        let field_size = field_size.ok_or_else(|| "union fields must be fixed-size".to_string())?;
        if let Some(field_data) = data.get(..field_size) {
            if validate_inline_value(
                field,
                field_data,
                pointers,
                struct_layouts,
                base_offset,
                desc,
                args,
                &next_frames,
            )
            .is_ok()
            {
                matched = true;
                break;
            }
        }
    }
    if matched || fields.is_empty() {
        Ok(())
    } else if varlen && !fixed_field_sizes.is_empty() {
        Err(format!(
            "varlen union buffer has size {}, expected one of {:?} or a variable-sized field of {}",
            data.len(),
            fixed_field_sizes,
            type_name.unwrap_or("<anonymous>")
        ))
    } else {
        Err("union buffer does not match any field layout".to_string())
    }
}

fn validate_vma_value(
    min_pages: usize,
    max_pages: usize,
    addr: u64,
    size: u64,
) -> Result<(), String> {
    if addr < DATA_OFFSET {
        return Err(format!(
            "vma address 0x{addr:x} is below data offset 0x{:x}",
            DATA_OFFSET
        ));
    }
    let relative = addr - DATA_OFFSET;
    if relative % PAGE_SIZE != 0 {
        return Err(format!(
            "vma address 0x{addr:x} is not page-aligned to {}",
            PAGE_SIZE
        ));
    }
    if size == 0 || size % PAGE_SIZE != 0 {
        return Err(format!(
            "vma size 0x{size:x} must be a non-zero page multiple of {}",
            PAGE_SIZE
        ));
    }
    let page_count = size / PAGE_SIZE;
    if page_count < min_pages as u64 || page_count > max_pages as u64 {
        return Err(format!(
            "vma size 0x{size:x} spans {page_count} pages, expected {}..={} pages",
            min_pages, max_pages
        ));
    }
    let end = relative
        .checked_add(size)
        .ok_or_else(|| "vma region overflows address space".to_string())?;
    if end > VMA_MAX_BYTES {
        return Err(format!(
            "vma region 0x{addr:x}/0x{size:x} exceeds 0x{:x} byte arena",
            VMA_MAX_BYTES
        ));
    }
    Ok(())
}

fn validate_string_type(
    values: &[Vec<u8>],
    noz: bool,
    fixed_len: Option<usize>,
) -> Result<(), String> {
    if let Some(fixed_len) = fixed_len {
        if fixed_len == 0 {
            return Err("string fixed length must be greater than zero".to_string());
        }
    }
    for value in values {
        if let Some(fixed_len) = fixed_len {
            let encoded_len = if noz { value.len() } else { value.len() + 1 };
            if encoded_len > fixed_len {
                return Err(format!(
                    "string literal requires {} bytes but fixed size is {}",
                    encoded_len, fixed_len
                ));
            }
        }
    }
    Ok(())
}

fn validate_string_buffer(data: &[u8], noz: bool, fixed_len: Option<usize>) -> Result<(), String> {
    if let Some(fixed_len) = fixed_len {
        if data.len() != fixed_len {
            return Err(format!(
                "string buffer has size {}, expected fixed size {}",
                data.len(),
                fixed_len
            ));
        }
    }
    if !noz {
        if data.is_empty() {
            return Err("NUL-terminated string buffer may not be empty".to_string());
        }
        if data.last().copied() != Some(0) {
            return Err("NUL-terminated string buffer must end with a NUL byte".to_string());
        }
    }
    Ok(())
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
        ArgType::Proc { .. } => "proc",
        ArgType::Len { .. } => "length",
        ArgType::Resource(_) | ArgType::OptionalResource(_) => "resource",
        ArgType::Array { .. } => "array",
        ArgType::Struct { .. } => "struct",
        ArgType::Union { .. } => "union",
        ArgType::Vma { .. } => "vma",
        ArgType::Ptr { .. } => "pointer",
        ArgType::String { .. } => "string",
        ArgType::Buffer { .. } => "buffer",
        ArgType::Filename => "filename",
        ArgType::Void => "void",
    }
}

fn describe_arg_value(arg_value: &ArgValue) -> &'static str {
    match arg_value {
        ArgValue::Const(_) => "const",
        ArgValue::ResultRef(_) => "result reference",
        ArgValue::Buffer(_) => "buffer",
        ArgValue::Composite { .. } => "composite buffer",
        ArgValue::Array { .. } => "array buffer",
        ArgValue::Filename(_) => "filename",
        ArgValue::Vma { .. } => "vma",
        ArgValue::OutPtr => "out pointer",
        ArgValue::Null => "null",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall_idx(descs: &[SyscallDesc], name: &str) -> usize {
        descs
            .iter()
            .position(|desc| desc.name == name)
            .unwrap_or_else(|| panic!("missing syscall {name}"))
    }

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
                ref pointer_chain,
            } => {
                assert_eq!(arg_idx, 0);
                assert_eq!(element_idx, 1);
                assert_eq!(offset, 4);
                assert!(pointer_chain.is_empty());
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
                ref pointer_chain,
            } => {
                assert_eq!(arg_idx, 3);
                assert_eq!(element_idx, 1);
                assert_eq!(offset, 4);
                assert!(pointer_chain.is_empty());
            }
            ref other => panic!("unexpected output source: {:?}", other),
        }
    }

    #[test]
    fn nested_pointer_outputs_expose_resource_offsets_and_pointer_chain() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource handle[intptr]
                type inner {
                    h0 handle
                    h1 handle
                }
                type wrapper {
                    out ptr[out, inner]
                }
                syscall make@1 -> int(arg ptr[inout, wrapper])
            "#,
        )
        .expect("test target should parse");
        let outputs = resource_outputs(&descs[0]);

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].resource.kind, "handle");
        assert_eq!(outputs[1].resource.kind, "handle");
        match outputs[1].source {
            ResourceSource::PointerElement {
                arg_idx,
                element_idx,
                offset,
                ref pointer_chain,
            } => {
                assert_eq!(arg_idx, 0);
                assert_eq!(element_idx, 1);
                assert_eq!(offset, 8);
                assert_eq!(pointer_chain, &vec![0]);
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
        let socket_idx = syscall_idx(&descs, "socket");
        let eventfd2_idx = syscall_idx(&descs, "eventfd2");

        let fd_input = match &close.args[0] {
            ArgType::Resource(resource) | ArgType::OptionalResource(resource) => resource.clone(),
            other => panic!("unexpected close arg: {:?}", other),
        };
        let sock_output = match &socket.ret {
            ReturnType::Resource(resource) => resource.clone(),
            other => panic!("unexpected socket return: {:?}", other),
        };

        let fd_ctors = resource_constructor_syscalls(&descs, &fd_input);
        let sock_ctors = resource_constructor_syscalls(&descs, &sock_output);

        assert!(fd_ctors.contains(&socket_idx)); // socket -> sock can satisfy fd consumers
        assert!(sock_ctors.contains(&socket_idx));
        assert!(!sock_ctors.contains(&eventfd2_idx)); // eventfd2 -> fd is not precise enough for sock
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
    fn optional_resource_inputs_do_not_block_self_constructing_resources() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource ring[4] = -1
                syscall setup@1 -> ring(parent ring[opt])
                syscall use_ring@2 -> int(fd ring)
            "#,
        )
        .expect("optional resource target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0, 1]);
        assert_eq!(generatable.enabled, vec![0, 1]);
        assert!(generatable.disabled.is_empty());
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
    fn generatable_availability_accepts_packed_structs_with_multiple_variable_fields() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type binfmt_register_like {
                    colon0 const[':', int8]
                    name stringnoz["syz0"]
                    colon1 const[':', int8]
                    kind stringnoz["M"]
                    colon2 const[':', int8]
                    magic stringnoz
                    colon3 const[':', int8]
                    mask stringnoz
                } [packed]
                syscall register_like@1 -> int(arg ptr[in, binfmt_register_like])
            "#,
        )
        .expect("test target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0]);
        assert_eq!(generatable.enabled, vec![0]);
        assert!(!generatable.disabled.contains_key(&0));
    }

    #[test]
    fn generatable_availability_accepts_packed_varlen_structs_with_explicit_alignment() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type packed_mid_aligned {
                    prefix int32
                    payload array[int64]
                    payload_words len[payload, intptr]
                    tail ptr[in, array[int8, 4]]
                } [packed, align[8]]
                syscall use_mid@1 -> int(arg ptr[in, packed_mid_aligned], arglen len[arg, intptr])
            "#,
        )
        .expect("test target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0]);
        assert_eq!(generatable.enabled, vec![0]);
        assert!(!generatable.disabled.contains_key(&0));
    }

    #[test]
    fn generatable_availability_accepts_bitfield_backed_structs() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type ipv4_like {
                    ihl bytesize4[parent, int8:4]
                    version const[4, int8:4]
                    payload array[int8, 3:3]
                } [packed]
                syscall use_ipv4_like@1 -> int(arg ptr[in, ipv4_like], arglen len[arg, intptr])
            "#,
        )
        .expect("test target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0]);
        assert_eq!(generatable.enabled, vec![0]);
        assert!(!generatable.disabled.contains_key(&0));
    }

    #[test]
    fn generatable_availability_excludes_unimplemented_syscall_attrs() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall stable@1 -> int()
                syscall freeze@2 -> int() (snapshot)
                syscall seccompish@3 -> int() (breaks_returns)
                syscall vmcall@4 -> int() (no_squash)
                syscall coverme@5 -> int() (remote_cover)
                syscall fuzztest@6 -> int() (kfuzz_test, timeout[300])
                syscall needs_fsck@7 -> int() (fsck["fsck.ext4 -n"])
                syscall longprog@8 -> int() (prog_timeout[3000])
            "#,
        )
        .expect("attribute target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(generatable.enabled, vec![0, 2, 7]);
        assert_eq!(
            generatable
                .disabled
                .get(&1)
                .expect("snapshot syscall should be excluded"),
            "requires snapshot-mode support"
        );
        assert_eq!(
            generatable
                .disabled
                .get(&3)
                .expect("no_squash syscall should be excluded"),
            "requires no_squash executor support"
        );
        assert_eq!(
            generatable
                .disabled
                .get(&4)
                .expect("remote_cover syscall should be excluded"),
            "requires remote coverage support"
        );
        assert_eq!(
            generatable
                .disabled
                .get(&5)
                .expect("kfuzz_test syscall should be excluded"),
            "requires kfuzz_test support"
        );
        assert_eq!(
            generatable
                .disabled
                .get(&6)
                .expect("fsck syscall should be excluded"),
            "requires fsck helper support"
        );
    }

    #[test]
    fn generatable_availability_accepts_breaks_returns_resource_chains() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource listenerfd[4] = -1
                syscall make_listener@1 -> listenerfd() (breaks_returns)
                syscall use_listener@2 -> int(fd listenerfd) (breaks_returns)
            "#,
        )
        .expect("breaks_returns resource target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);

        assert_eq!(enabled.enabled, vec![0, 1]);
        assert_eq!(generatable.enabled, vec![0, 1]);
        assert!(generatable.disabled.is_empty());
    }

    #[test]
    fn out_overlay_structs_compute_layouts_but_are_not_generatable_yet() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type overlay_args {
                    kind int32
                    devid int32 (out_overlay)
                    magic int32
                } [size[8]]
                syscall use_overlay@1 -> int(arg ptr[inout, overlay_args])
            "#,
        )
        .expect("overlay-bearing target should parse");

        let enabled = transitively_enabled_syscalls(&descs);
        let generatable = transitively_generatable_syscalls(&descs);
        assert_eq!(enabled.enabled, vec![0]);
        assert!(generatable.enabled.is_empty());
        assert_eq!(
            generatable
                .disabled
                .get(&0)
                .expect("overlay syscall should be excluded from generation"),
            "contains out_overlay struct fields, which generation does not support yet"
        );

        let overlay = match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => inner.as_ref(),
            other => panic!("unexpected overlay arg: {:?}", other),
        };

        match overlay {
            ArgType::Struct {
                fields,
                size,
                packed,
                align,
                overlay_start,
                ..
            } => {
                assert_eq!(*size, 8);
                assert_eq!(*overlay_start, Some(1));
                assert_eq!(
                    compute_struct_field_offset(fields, 0, false, *packed, *overlay_start),
                    Some(0)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 1, false, *packed, *overlay_start),
                    Some(0)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 2, false, *packed, *overlay_start),
                    Some(4)
                );
                assert_eq!(
                    struct_layout_prefix_size(fields, *packed, *align, *overlay_start)
                        .expect("overlay layout should compute"),
                    (8, false)
                );
            }
            other => panic!("unexpected overlay type: {:?}", other),
        }
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
        let close = syscall_idx(&descs, "close");
        let eventfd2 = syscall_idx(&descs, "eventfd2");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
                Call {
                    syscall_idx: eventfd2,
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
                syscall_idx: syscall_idx(&descs, "close"),
                args: vec![ArgValue::Buffer(vec![0, 1, 2, 3])],
            }],
        };

        let err = validate_program(&prog, &descs).expect_err("type mismatches must be rejected");
        assert!(err.to_string().contains("expected resource, got buffer"));
    }

    #[test]
    fn accepts_pointer_output_result_reference() {
        let descs = get_syscall_descs();
        let pipe2 = syscall_idx(&descs, "pipe2");
        let close = syscall_idx(&descs, "close");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: pipe2,
                    args: vec![ArgValue::OutPtr, ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: close,
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
    fn validates_fixed_and_varlen_union_buffers() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                packet [
                    short buffer[2:2]
                    word buffer[4:4]
                ]
                flex_packet [
                    short buffer[2:2]
                    word buffer[4:4]
                ] [varlen]
                syscall take_value@1 -> int(arg packet)
                syscall take_ptr@2 -> int(arg ptr[in, flex_packet])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![
                Call {
                    syscall_idx: 0,
                    args: vec![ArgValue::Buffer(vec![0; 4])],
                },
                Call {
                    syscall_idx: 1,
                    args: vec![ArgValue::Buffer(vec![0; 2])],
                },
            ],
        };
        valid
            .validate(&descs)
            .expect("fixed and varlen union buffers should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 1,
                args: vec![ArgValue::Buffer(vec![0; 3])],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("invalid varlen union size must be rejected");
        assert!(err.to_string().contains("expected one of [2, 4]"));
    }

    #[test]
    fn validates_varlen_union_buffers_with_variable_fields() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                flex_packet [
                    raw array[int8]
                    word buffer[4:4]
                ] [varlen]
                syscall take_ptr@1 -> int(arg ptr[in, flex_packet])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Buffer(vec![0; 3])],
            }],
        };
        valid
            .validate(&descs)
            .expect("variable-sized varlen union buffer should validate");

        let also_valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Buffer(vec![0; 4])],
            }],
        };
        also_valid
            .validate(&descs)
            .expect("fixed-sized varlen union alternative should still validate");
    }

    #[test]
    fn validates_vma_values_and_derived_lengths() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall map@1 -> int(addr vma[2:3], len len[addr], opt vma[opt], optlen len[opt])
            "#,
        )
        .expect("test target should parse");
        let prog = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Vma {
                        addr: DATA_OFFSET + 512 * PAGE_SIZE,
                        size: 2 * PAGE_SIZE,
                    },
                    ArgValue::Const(2 * PAGE_SIZE),
                    ArgValue::Null,
                    ArgValue::Const(0),
                ],
            }],
        };

        prog.validate(&descs)
            .expect("vma values and optional null lengths should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Vma {
                        addr: DATA_OFFSET + 3,
                        size: PAGE_SIZE,
                    },
                    ArgValue::Const(PAGE_SIZE),
                    ArgValue::Null,
                    ArgValue::Const(0),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("unaligned vma must be rejected");
        assert!(err.to_string().contains("not page-aligned"));
    }

    #[test]
    fn validates_string_buffers_and_derived_lengths() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                path_values = "/dev/null"
                syscall write_like@1 -> int(path ptr[in, string[path_values]], path_len len[path], word ptr[in, stringnoz["abc", 8]], word_len len[word])
            "#,
        )
        .expect("test target should parse");
        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Buffer(b"/dev/null\0".to_vec()),
                    ArgValue::Const(10),
                    ArgValue::Buffer(vec![b'a', b'b', b'c', 0, 0, 0, 0, 0]),
                    ArgValue::Const(8),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("materialized string buffers and lengths should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Buffer(b"/dev/null".to_vec()),
                    ArgValue::Const(9),
                    ArgValue::Buffer(vec![b'a', b'b', b'c', 0, 0, 0, 0, 0]),
                    ArgValue::Const(8),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("missing NUL terminator must be rejected");
        assert!(err.to_string().contains("must end with a NUL byte"));
    }

    #[test]
    fn validates_string_literals_with_embedded_nul_bytes() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall write_nul@1 -> int(arg ptr[in, string["ab\u0000cd"]], arg_len len[arg])
            "#,
        )
        .expect("embedded-NUL string target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![ArgValue::Buffer(b"ab\0cd\0".to_vec()), ArgValue::Const(6)],
            }],
        };

        valid
            .validate(&descs)
            .expect("embedded-NUL string buffers should validate");
    }

    #[test]
    fn validates_packed_aligned_structs_with_nontrailing_var_fields() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type packed_mid_aligned {
                    prefix int32
                    payload array[int64]
                    payload_words len[payload, intptr]
                    tail ptr[in, array[int8, 4]]
                } [packed, align[8]]
                syscall use_mid@1 -> int(arg ptr[in, packed_mid_aligned], arglen len[arg, intptr])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Composite {
                        data: encode_scalar_bytes(4, 0x1122_3344)
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .chain(vec![0; 4])
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 20,
                            value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(32),
                ],
            }],
        };

        valid
            .validate(&descs)
            .expect("packed aligned mid-var struct should validate");
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
        let socket = syscall_idx(&descs, "socket");
        let close = syscall_idx(&descs, "close");
        let prog = Program {
            calls: vec![
                Call {
                    syscall_idx: socket,
                    args: vec![ArgValue::Const(2), ArgValue::Const(1), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: close,
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

    #[test]
    fn validates_parent_derived_inline_lengths() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type msg[PAYLOAD] {
                    size bytesize[parent, int32]
                    kind const[7, int32]
                    payload PAYLOAD
                } [packed]
                syscall write_msg@1 -> int(fd const[1, int32], data ptr[in, msg[int32]], len len[data, int32])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![12, 0, 0, 0, 7, 0, 0, 0, 0x34, 0x12, 0, 0]),
                    ArgValue::Const(12),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("parent-derived struct size field should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![8, 0, 0, 0, 7, 0, 0, 0, 0x34, 0x12, 0, 0]),
                    ArgValue::Const(12),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong parent-derived struct size field must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 8, expected 12"));
    }

    #[test]
    fn validates_offsetof_inline_fields() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type nlattr[PAYLOAD] {
                    nla_len offsetof[end, int16]
                    nla_type const[0xaa, int16]
                    payload PAYLOAD
                    end void
                } [packed]
                syscall send_attr@1 -> int(fd const[1, int32], data ptr[in, nlattr[int32]], len len[data, int32])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![8, 0, 0xaa, 0x00, 0x34, 0x12, 0x00, 0x00]),
                    ArgValue::Const(8),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("offsetof-derived inline field should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![6, 0, 0xaa, 0x00, 0x34, 0x12, 0x00, 0x00]),
                    ArgValue::Const(8),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong offsetof-derived inline field must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 6, expected 8"));
    }

    #[test]
    fn validates_named_path_lengths_across_arg_type_and_parent_roots() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type path_inner {
                    bytes array[int8, 6]
                } [packed]
                type path_outer {
                    inner path_inner
                    inner_len bytesize[path_outer:inner, int32]
                    inner_len2 bytesize[inner, int32]
                } [packed]
                type parent_meta {
                    payload_len bytesize[parent:parent:payload, int32]
                } [packed]
                helper_outer {
                    payload array[int32, 4]
                    meta parent_meta
                    data_len bytesize[syscall:data, int32]
                } [packed]
                syscall send_paths@1 -> int(fd const[1, int32], data ptr[in, path_outer], ctx ptr[in, helper_outer], inner_len len[data:inner, int32])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![
                        1, 2, 3, 4, 5, 6, // inner.bytes
                        6, 0, 0, 0, // inner_len
                        6, 0, 0, 0, // inner_len2
                    ]),
                    ArgValue::Buffer(vec![
                        1, 0, 0, 0, // payload[0]
                        2, 0, 0, 0, // payload[1]
                        3, 0, 0, 0, // payload[2]
                        4, 0, 0, 0, // payload[3]
                        16, 0, 0, 0, // meta.payload_len
                        14, 0, 0, 0, // data_len
                    ]),
                    ArgValue::Const(6),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("named-path derived lengths should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![
                        1, 2, 3, 4, 5, 6, //
                        6, 0, 0, 0, //
                        5, 0, 0, 0, // wrong current-root bytesize
                    ]),
                    ArgValue::Buffer(vec![
                        1, 0, 0, 0, //
                        2, 0, 0, 0, //
                        3, 0, 0, 0, //
                        4, 0, 0, 0, //
                        16, 0, 0, 0, //
                        13, 0, 0, 0, // wrong syscall-root bytesize
                    ]),
                    ArgValue::Const(6),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong named-path derived lengths must be rejected");
        let text = err.to_string();
        assert!(
            text.contains("derived inline field has value 5, expected 6")
                || text.contains("derived inline field has value 13, expected 14"),
            "unexpected validation error: {text}"
        );
    }

    #[test]
    fn validates_trailing_varlen_struct_arrays() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type qid {
                    path int32
                    version int32
                } [packed]
                type walk_msg {
                    nwqid len[wqid, int16]
                    wqid array[qid, 1:3]
                } [packed]
                syscall write_walk@1 -> int(fd const[1, int32], data ptr[in, walk_msg], size len[data, int32])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![
                        2, 0, // nwqid
                        1, 0, 0, 0, 2, 0, 0, 0, // qid[0]
                        3, 0, 0, 0, 4, 0, 0, 0, // qid[1]
                    ]),
                    ArgValue::Const(18),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("trailing fixed-element array payload should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Buffer(vec![
                        3, 0, // claims 3 elements
                        1, 0, 0, 0, 2, 0, 0, 0, // qid[0]
                        3, 0, 0, 0, 4, 0, 0, 0, // qid[1]
                    ]),
                    ArgValue::Const(18),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong trailing array element count must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 3, expected 2"));
    }

    #[test]
    fn validates_pointer_to_varlen_struct_array_lengths() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type iovec {
                    base ptr[in, array[int8, 4:8]]
                    len len[base, intptr]
                } [size[16]]
                type cmsghdr_like {
                    cmsg_len bytesize[parent, intptr]
                    cmsg_level const[0, int32]
                    cmsg_type const[0, int32]
                    data array[int8, 0:16]
                } [varlen, align[8]]
                type send_msghdr {
                    msg_name ptr[in, buffer[16:16], opt]
                    msg_namelen len[msg_name, int32]
                    msg_iov ptr[in, array[iovec, 1:2]]
                    msg_iovlen len[msg_iov, intptr]
                    msg_control ptr[in, array[cmsghdr_like, 1:2], opt]
                    msg_controllen bytesize[msg_control, intptr]
                    msg_flags const[0, int32]
                } [size[56]]
                syscall sendmsg@1 -> int(fd const[1, int32], msg ptr[in, send_msghdr], flags const[0, int32])
            "#,
        )
        .expect("test target should parse");

        let control_data = vec![
            24, 0, 0, 0, 0, 0, 0, 0, // cmsg_len = 24
            0, 0, 0, 0, // cmsg_level
            0, 0, 0, 0, // cmsg_type
            1, 2, 3, 0, 0, 0, 0, 0, // padded data
            16, 0, 0, 0, 0, 0, 0, 0, // cmsg_len = 16
            0, 0, 0, 0, // cmsg_level
            0, 0, 0, 0, // cmsg_type
        ];
        let control = ArgValue::Array {
            data: control_data,
            pointers: Vec::new(),
            element_sizes: vec![24, 16],
            struct_layouts: Vec::new(),
        };
        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 24]
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 40))
                            .chain(encode_scalar_bytes(4, 0))
                            .chain(vec![0; 4])
                            .collect(),
                        pointers: vec![
                            InlinePointerValue {
                                offset: 16,
                                value: Box::new(ArgValue::Composite {
                                    data: vec![0; 8]
                                        .into_iter()
                                        .chain(encode_scalar_bytes(8, 5))
                                        .collect(),
                                    pointers: vec![InlinePointerValue {
                                        offset: 0,
                                        value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5])),
                                    }],
                                    struct_layouts: Vec::new(),
                                }),
                            },
                            InlinePointerValue {
                                offset: 32,
                                value: Box::new(control.clone()),
                            },
                        ],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(0),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("pointer to varlen struct array should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 24]
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 32))
                            .chain(encode_scalar_bytes(4, 0))
                            .chain(vec![0; 4])
                            .collect(),
                        pointers: vec![
                            InlinePointerValue {
                                offset: 16,
                                value: Box::new(ArgValue::Composite {
                                    data: vec![0; 8]
                                        .into_iter()
                                        .chain(encode_scalar_bytes(8, 5))
                                        .collect(),
                                    pointers: vec![InlinePointerValue {
                                        offset: 0,
                                        value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5])),
                                    }],
                                    struct_layouts: Vec::new(),
                                }),
                            },
                            InlinePointerValue {
                                offset: 32,
                                value: Box::new(control),
                            },
                        ],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(0),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong varlen control length must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 32, expected 40"));
    }

    #[test]
    fn computes_native_and_packed_struct_layouts() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type natural_hdr {
                    a int32
                    b intptr
                    c int16
                }
                type packed_hdr {
                    a int32
                    b intptr
                    c int16
                } [packed, align[8]]
                syscall use_hdrs@1 -> int(n ptr[in, natural_hdr], p ptr[in, packed_hdr])
            "#,
        )
        .expect("test target should parse");

        let natural = match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => inner.as_ref(),
            other => panic!("unexpected natural hdr arg: {:?}", other),
        };
        let packed = match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => inner.as_ref(),
            other => panic!("unexpected packed hdr arg: {:?}", other),
        };

        match natural {
            ArgType::Struct {
                fields,
                size,
                packed,
                align,
                ..
            } => {
                assert!(!packed);
                assert_eq!(*align, None);
                assert_eq!(*size, 24);
                assert_eq!(
                    compute_struct_field_offset(fields, 0, false, *packed, None),
                    Some(0)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 1, false, *packed, None),
                    Some(8)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 2, false, *packed, None),
                    Some(16)
                );
            }
            other => panic!("unexpected natural hdr type: {:?}", other),
        }

        match packed {
            ArgType::Struct {
                fields,
                size,
                packed,
                align,
                ..
            } => {
                assert!(*packed);
                assert_eq!(*align, Some(8));
                assert_eq!(*size, 16);
                assert_eq!(
                    compute_struct_field_offset(fields, 0, false, *packed, None),
                    Some(0)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 1, false, *packed, None),
                    Some(4)
                );
                assert_eq!(
                    compute_struct_field_offset(fields, 2, false, *packed, None),
                    Some(12)
                );
            }
            other => panic!("unexpected packed hdr type: {:?}", other),
        }
    }

    #[test]
    fn validates_packed_struct_with_nontrailing_var_field() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type packed_mid {
                    prefix int32
                    payload array[int64]
                    payload_words len[payload, intptr]
                    tail ptr[in, array[int8, 4]]
                } [packed]
                syscall use_mid@1 -> int(arg ptr[in, packed_mid], arglen len[arg, intptr])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Composite {
                        data: encode_scalar_bytes(4, 0x1122_3344)
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(encode_scalar_bytes(8, 2))
                            .chain(encode_scalar_bytes(8, 2))
                            .chain(vec![0; 8])
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 28,
                            value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(36),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("packed struct with mid var field should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Composite {
                        data: encode_scalar_bytes(4, 0x1122_3344)
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(encode_scalar_bytes(8, 2))
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 28,
                            value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(36),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong derived count after var field must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 1, expected 2"));
    }

    #[test]
    fn validates_inline_pointer_struct_lengths() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type iovec {
                    base ptr[in, array[int8, 4:8]]
                    len len[base, intptr]
                } [size[16]]
                syscall send_iov@1 -> int(fd const[1, int32], iov ptr[in, iovec], total len[iov:base, intptr])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 8]
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 6))
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 0,
                            value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5, 6])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(6),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("inline pointer struct should validate");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 8]
                            .into_iter()
                            .chain(encode_scalar_bytes(8, 5))
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 0,
                            value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5, 6])),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(6),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("wrong inline pointer length must be rejected");
        assert!(err
            .to_string()
            .contains("derived inline field has value 5, expected 6"));
    }

    #[test]
    fn validates_optional_inline_pointer_lengths_as_zero() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type iovec {
                    base ptr[in, array[int8, 4:8]]
                    len len[base, intptr]
                } [size[16]]
                type send_msghdr {
                    msg_name ptr[in, buffer[16:16], opt]
                    msg_namelen len[msg_name, int32]
                    msg_iov ptr[in, array[iovec, 1:2]]
                    msg_iovlen len[msg_iov, intptr]
                    msg_control ptr[in, array[int8, 0:32], opt]
                    msg_controllen bytesize[msg_control, intptr]
                    msg_flags const[0, int32]
                } [size[56]]
                syscall sendmsg@1 -> int(fd const[1, int32], msg ptr[in, send_msghdr], flags const[0, int32])
            "#,
        )
        .expect("test target should parse");

        let valid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 8]
                            .into_iter()
                            .chain(encode_scalar_bytes(4, 0))
                            .chain(vec![0; 4])
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 0))
                            .chain(encode_scalar_bytes(4, 0))
                            .chain(vec![0; 4])
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(ArgValue::Composite {
                                data: vec![0; 8]
                                    .into_iter()
                                    .chain(encode_scalar_bytes(8, 5))
                                    .collect(),
                                pointers: vec![InlinePointerValue {
                                    offset: 0,
                                    value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5])),
                                }],
                                struct_layouts: Vec::new(),
                            }),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(0),
                ],
            }],
        };
        valid
            .validate(&descs)
            .expect("null optional inline pointers should derive zero lengths");

        let invalid = Program {
            calls: vec![Call {
                syscall_idx: 0,
                args: vec![
                    ArgValue::Const(1),
                    ArgValue::Composite {
                        data: vec![0; 8]
                            .into_iter()
                            .chain(encode_scalar_bytes(4, 8))
                            .chain(vec![0; 4])
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 1))
                            .chain(vec![0; 8])
                            .chain(encode_scalar_bytes(8, 4))
                            .chain(encode_scalar_bytes(4, 0))
                            .chain(vec![0; 4])
                            .collect(),
                        pointers: vec![InlinePointerValue {
                            offset: 16,
                            value: Box::new(ArgValue::Composite {
                                data: vec![0; 8]
                                    .into_iter()
                                    .chain(encode_scalar_bytes(8, 5))
                                    .collect(),
                                pointers: vec![InlinePointerValue {
                                    offset: 0,
                                    value: Box::new(ArgValue::Buffer(vec![1, 2, 3, 4, 5])),
                                }],
                                struct_layouts: Vec::new(),
                            }),
                        }],
                        struct_layouts: Vec::new(),
                    },
                    ArgValue::Const(0),
                ],
            }],
        };
        let err = invalid
            .validate(&descs)
            .expect_err("null optional pointer lengths must validate as zero");
        assert!(err
            .to_string()
            .contains("derived inline field has value 8, expected 0"));
    }
}
