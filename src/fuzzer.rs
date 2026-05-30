use crate::program::*;
use rand::Rng;
use std::collections::{HashMap, HashSet};

const MAX_CALLS: usize = 10;
const MIN_CALLS: usize = 1;

#[derive(Default)]
struct InlineObject {
    data: Vec<u8>,
    pointers: Vec<InlinePointerValue>,
    struct_layouts: Vec<InlineStructLayout>,
}

impl InlineObject {
    fn into_arg_value(self) -> ArgValue {
        if self.pointers.is_empty() && self.struct_layouts.is_empty() {
            ArgValue::Buffer(self.data)
        } else {
            ArgValue::Composite {
                data: self.data,
                pointers: self.pointers,
                struct_layouts: self.struct_layouts,
            }
        }
    }
}

fn shift_inline_struct_layout(mut layout: InlineStructLayout, delta: usize) -> InlineStructLayout {
    layout.base_offset += delta;
    for (start, end) in &mut layout.field_ranges {
        *start += delta;
        *end += delta;
    }
    layout
}

fn bitfield_value_limit(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn choose_scalar_const_value(
    size: usize,
    values: &[u64],
    range: Option<(u64, u64)>,
    allow_any: bool,
    bitfield_bits: Option<u8>,
    rng: &mut impl Rng,
) -> u64 {
    let bit_limit = bitfield_bits.map(bitfield_value_limit);
    let cap_value = |value: u64| bit_limit.map_or(value, |limit| value.min(limit));

    if !values.is_empty() {
        let filtered = values
            .iter()
            .copied()
            .filter(|value| bit_limit.is_none_or(|limit| *value <= limit))
            .collect::<Vec<_>>();
        if !filtered.is_empty() {
            return filtered[rng.gen_range(0..filtered.len())];
        }
        return cap_value(values[rng.gen_range(0..values.len())]);
    }

    if let Some((min, max)) = range {
        let upper = bit_limit.map_or(max, |limit| max.min(limit));
        let lower = min.min(upper);
        if lower <= upper {
            return rng.gen_range(lower..=upper);
        }
        return lower;
    }

    if allow_any {
        return cap_value(random_value_for_size(size, rng));
    }

    0
}

fn encode_generated_scalar_bytes(
    size: usize,
    value: u64,
    endian: ScalarEndian,
    bitfield_bits: Option<u8>,
) -> Vec<u8> {
    if let Some(bits) = bitfield_bits {
        let mut data = vec![0; size];
        if let Some(info) = standalone_bitfield_field_info(size, endian, bits) {
            let _ = encode_bitfield_storage_value(&mut data, info, value);
        }
        data
    } else {
        encode_scalar_bytes_endian(size, value, endian)
    }
}

fn array_inline_arg_value(elements: Vec<InlineObject>) -> ArgValue {
    let mut data = Vec::new();
    let mut pointers = Vec::new();
    let mut element_sizes = Vec::with_capacity(elements.len());
    let mut struct_layouts = Vec::new();
    for element in elements {
        let base = data.len();
        element_sizes.push(element.data.len());
        data.extend_from_slice(&element.data);
        pointers.extend(element.pointers.into_iter().map(|mut pointer| {
            pointer.offset += base;
            pointer
        }));
        struct_layouts.extend(
            element
                .struct_layouts
                .into_iter()
                .map(|layout| shift_inline_struct_layout(layout, base)),
        );
    }
    ArgValue::Array {
        data,
        pointers,
        element_sizes,
        struct_layouts,
    }
}

fn generate_proc_relative_value(values_per_proc: u64, rng: &mut impl Rng) -> u64 {
    if values_per_proc == 0 {
        0
    } else {
        rng.gen_range(0..values_per_proc)
    }
}

fn materialize_inline_proc_value(values_start: u64, relative: u64) -> u64 {
    values_start.wrapping_add(relative)
}

/// Generate a random program from scratch.
pub fn generate(descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, &[]);
    generate_with_choice_table(descs, &choice_table, rng)
}

/// Generate a random program from scratch, optionally biased by corpus history.
pub fn generate_with_corpus(
    descs: &[SyscallDesc],
    corpus: &[Program],
    rng: &mut impl Rng,
) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, corpus);
    generate_with_choice_table(descs, &choice_table, rng)
}

pub fn generate_with_choice_table(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    rng: &mut impl Rng,
) -> Program {
    generate_with_choice_table_and_edge_bias(descs, choice_table, &HashMap::new(), rng)
}

pub fn generate_with_choice_table_and_edge_bias(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> Program {
    let num_calls = rng.gen_range(MIN_CALLS..=MAX_CALLS);
    let mut calls = Vec::new();
    let mut available_resources: HashMap<String, Vec<ResultRef>> = HashMap::new();

    for _ in 0..num_calls {
        let previous_syscall_idx = calls.last().map(|call: &Call| call.syscall_idx);
        let syscall_idx = choose_syscall_for_generation(
            descs,
            choice_table,
            previous_syscall_idx,
            &available_resources,
            timeout_edge_failures,
            rng,
        );

        let desc = &descs[syscall_idx];
        let args = generate_args(desc, &available_resources, rng);

        let call_idx = calls.len();
        for (result_idx, output) in resource_outputs(desc).into_iter().enumerate() {
            register_available_resource(
                &mut available_resources,
                &output.resource,
                ResultRef {
                    call_idx,
                    result_idx,
                },
            );
        }

        calls.push(Call { syscall_idx, args });
    }

    let prog = Program { calls };
    let validation = validate_program(&prog, descs);
    debug_assert!(
        validation.is_ok(),
        "generated invalid program: {:?}\nerror: {}",
        prog,
        validation.unwrap_err()
    );
    prog
}

fn choose_syscall_for_generation(
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    previous_syscall_idx: Option<usize>,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> usize {
    let enabled_syscalls = choice_table.enabled_syscalls();
    let preferred_enabled = prefer_low_penalty_candidates(
        descs,
        previous_syscall_idx,
        enabled_syscalls,
        timeout_edge_failures,
    );
    let ready_consumers =
        resource_consumers_for_available_inputs(descs, enabled_syscalls, available_resources);
    if !ready_consumers.is_empty() && rng.gen_bool(0.6) {
        let preferred_ready = prefer_low_penalty_candidates(
            descs,
            previous_syscall_idx,
            &ready_consumers,
            timeout_edge_failures,
        );
        return choice_table.choose_subset(&preferred_ready, previous_syscall_idx, rng);
    }

    let candidate = choice_table.choose_subset(&preferred_enabled, previous_syscall_idx, rng);
    let fallback_producers = resource_producers_for_missing_inputs(
        descs,
        enabled_syscalls,
        &descs[candidate],
        available_resources,
    );
    if !fallback_producers.is_empty() && rng.gen_bool(0.7) {
        let preferred_fallback = prefer_low_penalty_candidates(
            descs,
            previous_syscall_idx,
            &fallback_producers,
            timeout_edge_failures,
        );
        choice_table.choose_subset(&preferred_fallback, previous_syscall_idx, rng)
    } else {
        candidate
    }
}

/// Generate arguments for a syscall.
fn generate_args(
    desc: &SyscallDesc,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    rng: &mut impl Rng,
) -> Vec<ArgValue> {
    let mut args = Vec::with_capacity(desc.args.len());
    for arg_type in &desc.args {
        let arg_value = generate_arg(desc, &args, arg_type, available_resources, rng);
        args.push(arg_value);
    }
    repair_generated_top_level_derived_args(desc, &mut args);
    args
}

fn repair_generated_top_level_derived_args(desc: &SyscallDesc, args: &mut [ArgValue]) {
    let updates = desc
        .args
        .iter()
        .enumerate()
        .filter_map(|(arg_idx, arg_type)| {
            let replacement = match arg_type {
                ArgType::Len {
                    target,
                    kind,
                    scale,
                    ..
                } => Some(ArgValue::Const(scale_length_value(
                    derive_target_length(desc, args, target, *kind)?,
                    *scale,
                ) as u64)),
                ArgType::Ptr {
                    inner,
                    dir,
                    optional: _,
                } if *dir != PtrDir::Out => match inner.as_ref() {
                    ArgType::Len {
                        target,
                        size,
                        kind,
                        endian,
                        scale,
                        bitfield_bits,
                    } if bitfield_bits.is_none() => {
                        Some(ArgValue::Buffer(encode_scalar_bytes_endian(
                            *size,
                            scale_length_value(
                                derive_target_length(desc, args, target, *kind)?,
                                *scale,
                            ) as u64,
                            *endian,
                        )))
                    }
                    _ => None,
                },
                _ => None,
            }?;
            Some((arg_idx, replacement))
        })
        .collect::<Vec<_>>();

    for (arg_idx, replacement) in updates {
        args[arg_idx] = replacement;
    }
}

/// Generate a single argument value.
fn generate_arg(
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    arg_type: &ArgType,
    available_resources: &HashMap<String, Vec<ResultRef>>,
    rng: &mut impl Rng,
) -> ArgValue {
    match arg_type {
        ArgType::Const {
            size,
            values,
            range,
            allow_any,
            ..
        } => {
            if !values.is_empty() {
                // Pick from valid values, occasionally mutate
                if rng.gen_bool(0.9) {
                    ArgValue::Const(values[rng.gen_range(0..values.len())])
                } else {
                    ArgValue::Const(random_value_for_size(*size, rng))
                }
            } else if let Some((min, max)) = range {
                if min <= max {
                    ArgValue::Const(rng.gen_range(*min..=*max))
                } else {
                    ArgValue::Const(*min)
                }
            } else if *allow_any {
                ArgValue::Const(random_value_for_size(*size, rng))
            } else {
                ArgValue::Const(0)
            }
        }
        ArgType::Proc {
            values_per_proc, ..
        } => ArgValue::Const(generate_proc_relative_value(*values_per_proc, rng)),
        ArgType::Len {
            target,
            kind,
            scale,
            ..
        } => {
            let value = derive_target_length(desc, generated_args, target, *kind).unwrap_or(0);
            ArgValue::Const(scale_length_value(value, *scale) as u64)
        }
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            if let Some(available) = available_resources
                .get(&resource.kind)
                .filter(|values| !values.is_empty())
            {
                if rng.gen_bool(0.8) {
                    return ArgValue::ResultRef(
                        available[rng.gen_range(0..available.len())].clone(),
                    );
                }
            }
            if !resource.values.is_empty() {
                ArgValue::Const(resource.values[rng.gen_range(0..resource.values.len())])
            } else {
                ArgValue::Const(0)
            }
        }
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            if *optional && rng.gen_bool(0.35) {
                return ArgValue::Null;
            }
            match dir {
                PtrDir::Out => ArgValue::OutPtr,
                PtrDir::In | PtrDir::InOut => {
                    generate_pointer_arg_value(desc, generated_args, inner, dir, rng)
                }
            }
        }
        ArgType::Void => ArgValue::Buffer(Vec::new()),
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } if arg_type_fixed_size(inner).is_none() => {
            generate_array_arg_value(inner, *min_len, *max_len, desc, generated_args, rng)
                .unwrap_or_else(|| ArgValue::Array {
                    data: Vec::new(),
                    pointers: Vec::new(),
                    element_sizes: Vec::new(),
                    struct_layouts: Vec::new(),
                })
        }
        ArgType::Array { .. } => generate_inline_arg_value(arg_type, desc, generated_args, rng)
            .unwrap_or_else(|| ArgValue::Buffer(Vec::new())),
        ArgType::Struct { size, .. } => {
            generate_inline_arg_value(arg_type, desc, generated_args, rng)
                .unwrap_or_else(|| ArgValue::Buffer(vec![0; *size]))
        }
        ArgType::Union {
            fields,
            size,
            varlen,
            ..
        } => generate_inline_arg_value(arg_type, desc, generated_args, rng).unwrap_or_else(|| {
            ArgValue::Buffer(vec![0; union_fallback_size(fields, *size, *varlen)])
        }),
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename,
        } => ArgValue::Buffer(generate_string_bytes(
            values, *noz, *fixed_len, *filename, rng,
        )),
        ArgType::Vma {
            min_pages,
            max_pages,
            optional,
        } => {
            if *optional && rng.gen_bool(0.35) {
                ArgValue::Null
            } else {
                generate_vma(*min_pages, *max_pages, rng)
            }
        }
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } => {
            let size = rng.gen_range(*min_size..=*max_size);
            let mut data = vec![0u8; size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            ArgValue::Buffer(data)
        }
        ArgType::Filename => ArgValue::Filename(random_filename(rng)),
    }
}

fn generate_pointer_arg_value(
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    inner: &ArgType,
    dir: &PtrDir,
    rng: &mut impl Rng,
) -> ArgValue {
    match inner {
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } => {
            let size = rng.gen_range(*min_size..=*max_size);
            let mut data = vec![0u8; size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            ArgValue::Buffer(data)
        }
        ArgType::Len {
            target,
            size,
            kind,
            endian,
            scale,
            bitfield_bits,
        } => {
            if bitfield_bits.is_some() {
                return ArgValue::Buffer(vec![0; *size]);
            }
            let value = derive_target_length(desc, generated_args, target, *kind).unwrap_or(0);
            ArgValue::Buffer(encode_scalar_bytes_endian(
                *size,
                scale_length_value(value, *scale) as u64,
                *endian,
            ))
        }
        ArgType::Proc {
            size,
            values_start,
            values_per_proc,
            endian,
        } => ArgValue::Buffer(encode_scalar_bytes_endian(
            *size,
            materialize_inline_proc_value(
                *values_start,
                generate_proc_relative_value(*values_per_proc, rng),
            ),
            *endian,
        )),
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename,
        } => ArgValue::Buffer(generate_string_bytes(
            values, *noz, *fixed_len, *filename, rng,
        )),
        ArgType::Array {
            inner: array_inner,
            min_len,
            max_len,
        } if arg_type_fixed_size(array_inner).is_none() => {
            generate_array_arg_value(array_inner, *min_len, *max_len, desc, generated_args, rng)
                .unwrap_or_else(|| ArgValue::Array {
                    data: Vec::new(),
                    pointers: Vec::new(),
                    element_sizes: Vec::new(),
                    struct_layouts: Vec::new(),
                })
        }
        ArgType::Array { .. } => generate_inline_arg_value(inner, desc, generated_args, rng)
            .unwrap_or_else(|| ArgValue::Buffer(Vec::new())),
        ArgType::Struct { size, .. } => generate_inline_arg_value(inner, desc, generated_args, rng)
            .unwrap_or_else(|| ArgValue::Buffer(vec![0; *size])),
        ArgType::Union {
            fields,
            size,
            varlen,
            ..
        } => generate_inline_arg_value(inner, desc, generated_args, rng).unwrap_or_else(|| {
            ArgValue::Buffer(vec![0; union_fallback_size(fields, *size, *varlen)])
        }),
        _ => {
            if let Some(size) = arg_type_fixed_size(inner) {
                let mut data = vec![0u8; size];
                if *dir != PtrDir::Out {
                    rng.fill(&mut data[..]);
                }
                ArgValue::Buffer(data)
            } else {
                ArgValue::OutPtr
            }
        }
    }
}

fn generate_inline_arg_value(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<ArgValue> {
    let object = generate_inline_object(arg_type, desc, generated_args, rng)?;
    Some(object.into_arg_value())
}

fn generate_array_arg_value(
    inner: &ArgType,
    min_len: usize,
    max_len: usize,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<ArgValue> {
    let len = if min_len == max_len {
        min_len
    } else {
        rng.gen_range(min_len..=max_len)
    };
    let mut elements = Vec::with_capacity(len);
    for _ in 0..len {
        elements.push(generate_inline_object(inner, desc, generated_args, rng)?);
    }
    Some(array_inline_arg_value(elements))
}

fn generate_reserved_inline_arg_value(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<ArgValue> {
    let mut object = generate_reserved_inline_object_raw(arg_type, desc, generated_args, rng)?;
    patch_inline_len_fields(
        arg_type,
        Some(desc),
        Some(generated_args),
        &[],
        &mut object.data,
        object.pointers.as_slice(),
        Some(object.struct_layouts.as_slice()),
        0,
    )?;
    Some(object.into_arg_value())
}

fn generate_reserved_array_arg_value(
    inner: &ArgType,
    min_len: usize,
    max_len: usize,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<ArgValue> {
    let len = if min_len == max_len {
        min_len
    } else {
        rng.gen_range(min_len..=max_len)
    };
    let mut elements = Vec::with_capacity(len);
    for _ in 0..len {
        let mut object = generate_reserved_inline_object_raw(inner, desc, generated_args, rng)?;
        patch_inline_len_fields(
            inner,
            Some(desc),
            Some(generated_args),
            &[],
            &mut object.data,
            object.pointers.as_slice(),
            Some(object.struct_layouts.as_slice()),
            0,
        )?;
        elements.push(object);
    }
    Some(array_inline_arg_value(elements))
}

fn generate_inline_bytes(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<Vec<u8>> {
    Some(generate_inline_object(arg_type, desc, generated_args, rng)?.data)
}

fn generate_inline_object(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<InlineObject> {
    let mut object = generate_inline_object_raw(arg_type, desc, generated_args, rng)?;
    patch_inline_len_fields(
        arg_type,
        Some(desc),
        Some(generated_args),
        &[],
        &mut object.data,
        object.pointers.as_slice(),
        Some(object.struct_layouts.as_slice()),
        0,
    )?;
    Some(object)
}

fn generate_inline_object_raw(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<InlineObject> {
    match arg_type {
        ArgType::Const {
            size,
            values,
            range,
            endian,
            allow_any,
            bitfield_bits,
        } => {
            let value =
                choose_scalar_const_value(*size, values, *range, *allow_any, *bitfield_bits, rng);
            Some(InlineObject {
                data: encode_generated_scalar_bytes(*size, value, *endian, *bitfield_bits),
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            })
        }
        ArgType::Proc {
            size,
            values_start,
            values_per_proc,
            endian,
        } => Some(InlineObject {
            data: encode_scalar_bytes_endian(
                *size,
                materialize_inline_proc_value(
                    *values_start,
                    generate_proc_relative_value(*values_per_proc, rng),
                ),
                *endian,
            ),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => Some(InlineObject {
            data: encode_scalar_bytes(resource.size, resource.default_value()),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            let len = if min_len == max_len {
                *min_len
            } else {
                rng.gen_range(*min_len..=*max_len)
            };
            let mut out = InlineObject::default();
            for _ in 0..len {
                let child = generate_inline_object_raw(inner, desc, generated_args, rng)?;
                let base = out.data.len();
                out.data.extend_from_slice(&child.data);
                out.pointers
                    .extend(child.pointers.into_iter().map(|mut pointer| {
                        pointer.offset += base;
                        pointer
                    }));
                out.struct_layouts.extend(
                    child
                        .struct_layouts
                        .into_iter()
                        .map(|layout| shift_inline_struct_layout(layout, base)),
                );
            }
            Some(out)
        }
        ArgType::Void => Some(InlineObject::default()),
        ArgType::Struct {
            fields,
            size,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            if overlay_start.is_some() {
                return None;
            }
            let mut out = InlineObject::default();
            let mut field_ranges = Vec::with_capacity(fields.len());
            let bitfield_info = compute_bitfield_field_info(fields)?;
            let mut idx = 0usize;
            while idx < fields.len() {
                if let Some(info) = bitfield_info[idx] {
                    let base = if *packed && *varlen {
                        out.data.len()
                    } else {
                        let field_offset = compute_struct_field_offset(
                            fields,
                            idx,
                            *varlen,
                            *packed,
                            *overlay_start,
                        )?;
                        out.data.resize(field_offset, 0);
                        field_offset
                    };
                    let mut storage = vec![0; info.unit_size];
                    let mut group_idx = idx;
                    loop {
                        let group_info = bitfield_info[group_idx]?;
                        match &fields[group_idx] {
                            ArgType::Const {
                                size,
                                values,
                                range,
                                endian: _,
                                allow_any,
                                bitfield_bits,
                            } => {
                                let value = choose_scalar_const_value(
                                    *size,
                                    values,
                                    *range,
                                    *allow_any,
                                    *bitfield_bits,
                                    rng,
                                );
                                encode_bitfield_storage_value(&mut storage, group_info, value)?;
                            }
                            ArgType::Len { .. } => {}
                            _ => return None,
                        }
                        let field_end = if group_info.is_last_in_group {
                            base.checked_add(group_info.unit_size)?
                        } else {
                            base
                        };
                        field_ranges.push((base, field_end));
                        if group_info.is_last_in_group {
                            break;
                        }
                        group_idx += 1;
                    }
                    out.data.extend_from_slice(&storage);
                    idx = group_idx + 1;
                    continue;
                }

                let field = &fields[idx];
                let child = generate_inline_object_raw(field, desc, generated_args, rng)?;
                let base = if *packed && *varlen {
                    out.data.len()
                } else {
                    let field_offset =
                        compute_struct_field_offset(fields, idx, *varlen, *packed, *overlay_start)?;
                    out.data.resize(field_offset, 0);
                    field_offset
                };
                let end = base.checked_add(child.data.len())?;
                field_ranges.push((base, end));
                out.data.extend_from_slice(&child.data);
                out.pointers
                    .extend(child.pointers.into_iter().map(|mut pointer| {
                        pointer.offset += base;
                        pointer
                    }));
                out.struct_layouts.extend(
                    child
                        .struct_layouts
                        .into_iter()
                        .map(|layout| shift_inline_struct_layout(layout, base)),
                );
                idx += 1;
            }
            if !*varlen {
                out.data.resize(*size, 0);
            } else {
                let struct_align = struct_type_alignment(fields, *packed, *align).ok()?;
                let final_size = if struct_align <= 1 {
                    out.data.len()
                } else {
                    out.data
                        .len()
                        .checked_add(struct_align - 1)
                        .map(|rounded| rounded & !(struct_align - 1))?
                };
                out.data.resize(final_size, 0);
            }
            let needs_struct_layout = compute_struct_field_ranges(
                fields,
                *varlen,
                *packed,
                *align,
                *overlay_start,
                out.data.len(),
            )
            .map_or(true, |computed| computed != field_ranges);
            if needs_struct_layout {
                out.struct_layouts.push(InlineStructLayout {
                    base_offset: 0,
                    field_ranges,
                });
            }
            Some(out)
        }
        ArgType::Union {
            fields,
            size,
            varlen,
            packed,
            align,
            ..
        } => {
            let candidate_fields = fields
                .iter()
                .filter(|field| arg_type_generation_limitation(field).is_none())
                .collect::<Vec<_>>();
            if candidate_fields.is_empty() {
                return None;
            }
            let field = candidate_fields.get(rng.gen_range(0..candidate_fields.len()))?;
            let mut out = generate_inline_object_raw(field, desc, generated_args, rng)?;
            if !*varlen {
                out.data.resize(*size, 0);
            } else {
                let union_align = union_type_alignment(fields, *packed, *align).ok()?;
                let final_size = if union_align <= 1 {
                    out.data.len()
                } else {
                    out.data
                        .len()
                        .checked_add(union_align - 1)
                        .map(|rounded| rounded & !(union_align - 1))?
                };
                out.data.resize(final_size, 0);
            }
            Some(out)
        }
        ArgType::String {
            values,
            noz,
            fixed_len,
            filename,
        } => Some(InlineObject {
            data: generate_string_bytes(values, *noz, *fixed_len, *filename, rng),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Buffer {
            min_size,
            max_size,
            dir,
        } => {
            let size = if min_size == max_size {
                *max_size
            } else {
                rng.gen_range(*min_size..=*max_size)
            };
            let mut data = vec![0u8; size];
            if *dir != BufferDir::Out {
                rng.fill(&mut data[..]);
            }
            Some(InlineObject {
                data,
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            })
        }
        ArgType::Len {
            size,
            endian,
            bitfield_bits,
            ..
        } => Some(InlineObject {
            data: encode_generated_scalar_bytes(*size, 0, *endian, *bitfield_bits),
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            let mut object = InlineObject {
                data: vec![0; 8],
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            };
            if *optional && rng.gen_bool(0.35) {
                return Some(object);
            }
            let value = match dir {
                PtrDir::Out => {
                    generate_reserved_pointer_arg_value(inner, desc, generated_args, rng)
                }
                PtrDir::In | PtrDir::InOut => {
                    generate_pointer_arg_value(desc, generated_args, inner, dir, rng)
                }
            };
            object.pointers.push(InlinePointerValue {
                offset: 0,
                value: Box::new(value),
            });
            Some(object)
        }
        ArgType::Vma {
            min_pages,
            max_pages,
            optional,
        } => Some(InlineObject {
            data: match generate_vma(*min_pages, *max_pages, rng) {
                ArgValue::Vma { addr, .. } => encode_scalar_bytes(8, addr),
                ArgValue::Null if *optional => encode_scalar_bytes(8, 0),
                _ => encode_scalar_bytes(8, 0),
            },
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Filename => {
            let mut data = random_filename(rng).into_bytes();
            data.push(0);
            Some(InlineObject {
                data,
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            })
        }
    }
}

fn generate_reserved_pointer_arg_value(
    inner: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> ArgValue {
    match inner {
        ArgType::Const { size, .. } | ArgType::Proc { size, .. } | ArgType::Len { size, .. } => {
            ArgValue::Buffer(vec![0; *size])
        }
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => {
            ArgValue::Buffer(vec![0; resource.size])
        }
        ArgType::String { fixed_len, .. } => ArgValue::Buffer(vec![0; fixed_len.unwrap_or(0)]),
        ArgType::Buffer {
            min_size, max_size, ..
        } => {
            let size = if min_size == max_size {
                *max_size
            } else {
                rng.gen_range(*min_size..=*max_size)
            };
            ArgValue::Buffer(vec![0; size])
        }
        ArgType::Filename => ArgValue::Buffer(vec![0]),
        ArgType::Void => ArgValue::Buffer(Vec::new()),
        ArgType::Vma { .. } => ArgValue::Buffer(vec![0; 8]),
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } if arg_type_fixed_size(inner).is_none() => {
            generate_reserved_array_arg_value(inner, *min_len, *max_len, desc, generated_args, rng)
                .unwrap_or_else(|| ArgValue::Array {
                    data: Vec::new(),
                    pointers: Vec::new(),
                    element_sizes: Vec::new(),
                    struct_layouts: Vec::new(),
                })
        }
        ArgType::Array { .. } | ArgType::Struct { .. } | ArgType::Union { .. } => {
            generate_reserved_inline_arg_value(inner, desc, generated_args, rng).unwrap_or_else(
                || ArgValue::Buffer(vec![0; arg_type_fixed_size(inner).unwrap_or(0)]),
            )
        }
        ArgType::Ptr {
            inner: nested_inner,
            dir,
            optional,
        } => {
            if *optional && rng.gen_bool(0.35) {
                ArgValue::Null
            } else {
                match dir {
                    PtrDir::Out => {
                        generate_reserved_pointer_arg_value(nested_inner, desc, generated_args, rng)
                    }
                    PtrDir::In | PtrDir::InOut => {
                        generate_pointer_arg_value(desc, generated_args, nested_inner, dir, rng)
                    }
                }
            }
        }
    }
}

fn generate_reserved_inline_object_raw(
    arg_type: &ArgType,
    desc: &SyscallDesc,
    generated_args: &[ArgValue],
    rng: &mut impl Rng,
) -> Option<InlineObject> {
    match arg_type {
        ArgType::Const { size, .. } | ArgType::Proc { size, .. } | ArgType::Len { size, .. } => {
            Some(InlineObject {
                data: vec![0; *size],
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            })
        }
        ArgType::Resource(resource) | ArgType::OptionalResource(resource) => Some(InlineObject {
            data: vec![0; resource.size],
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::String { fixed_len, .. } => Some(InlineObject {
            data: vec![0; fixed_len.unwrap_or(0)],
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Buffer {
            min_size, max_size, ..
        } => {
            let size = if min_size == max_size {
                *max_size
            } else {
                rng.gen_range(*min_size..=*max_size)
            };
            Some(InlineObject {
                data: vec![0; size],
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            })
        }
        ArgType::Filename => Some(InlineObject {
            data: vec![0],
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Void => Some(InlineObject::default()),
        ArgType::Vma { .. } => Some(InlineObject {
            data: vec![0; 8],
            pointers: Vec::new(),
            struct_layouts: Vec::new(),
        }),
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            let len = if min_len == max_len {
                *min_len
            } else {
                rng.gen_range(*min_len..=*max_len)
            };
            let mut out = InlineObject::default();
            for _ in 0..len {
                let child = generate_reserved_inline_object_raw(inner, desc, generated_args, rng)?;
                let base = out.data.len();
                out.data.extend_from_slice(&child.data);
                out.pointers
                    .extend(child.pointers.into_iter().map(|mut pointer| {
                        pointer.offset += base;
                        pointer
                    }));
                out.struct_layouts.extend(
                    child
                        .struct_layouts
                        .into_iter()
                        .map(|layout| shift_inline_struct_layout(layout, base)),
                );
            }
            Some(out)
        }
        ArgType::Struct {
            fields,
            size,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            if overlay_start.is_some() {
                return None;
            }
            let mut out = InlineObject::default();
            let mut field_ranges = Vec::with_capacity(fields.len());
            let bitfield_info = compute_bitfield_field_info(fields)?;
            let mut idx = 0usize;
            while idx < fields.len() {
                if let Some(info) = bitfield_info[idx] {
                    let base = if *packed && *varlen {
                        out.data.len()
                    } else {
                        let field_offset = compute_struct_field_offset(
                            fields,
                            idx,
                            *varlen,
                            *packed,
                            *overlay_start,
                        )?;
                        out.data.resize(field_offset, 0);
                        field_offset
                    };
                    let mut group_idx = idx;
                    loop {
                        let group_info = bitfield_info[group_idx]?;
                        let field_end = if group_info.is_last_in_group {
                            base.checked_add(group_info.unit_size)?
                        } else {
                            base
                        };
                        field_ranges.push((base, field_end));
                        if group_info.is_last_in_group {
                            break;
                        }
                        group_idx += 1;
                    }
                    out.data.resize(base.checked_add(info.unit_size)?, 0);
                    idx = group_idx + 1;
                    continue;
                }

                let field = &fields[idx];
                let child = generate_reserved_inline_object_raw(field, desc, generated_args, rng)?;
                let base = if *packed && *varlen {
                    out.data.len()
                } else {
                    let field_offset =
                        compute_struct_field_offset(fields, idx, *varlen, *packed, *overlay_start)?;
                    out.data.resize(field_offset, 0);
                    field_offset
                };
                let end = base.checked_add(child.data.len())?;
                field_ranges.push((base, end));
                out.data.extend_from_slice(&child.data);
                out.pointers
                    .extend(child.pointers.into_iter().map(|mut pointer| {
                        pointer.offset += base;
                        pointer
                    }));
                out.struct_layouts.extend(
                    child
                        .struct_layouts
                        .into_iter()
                        .map(|layout| shift_inline_struct_layout(layout, base)),
                );
                idx += 1;
            }
            if !*varlen {
                out.data.resize(*size, 0);
            } else {
                let struct_align = struct_type_alignment(fields, *packed, *align).ok()?;
                let final_size = if struct_align <= 1 {
                    out.data.len()
                } else {
                    out.data
                        .len()
                        .checked_add(struct_align - 1)
                        .map(|rounded| rounded & !(struct_align - 1))?
                };
                out.data.resize(final_size, 0);
            }
            let needs_struct_layout = compute_struct_field_ranges(
                fields,
                *varlen,
                *packed,
                *align,
                *overlay_start,
                out.data.len(),
            )
            .map_or(true, |computed| computed != field_ranges);
            if needs_struct_layout {
                out.struct_layouts.push(InlineStructLayout {
                    base_offset: 0,
                    field_ranges,
                });
            }
            Some(out)
        }
        ArgType::Union {
            fields,
            size,
            varlen,
            packed,
            align,
            ..
        } => {
            let candidate_fields = fields
                .iter()
                .filter(|field| arg_type_generation_limitation(field).is_none())
                .collect::<Vec<_>>();
            if candidate_fields.is_empty() {
                return None;
            }
            let field = candidate_fields.get(rng.gen_range(0..candidate_fields.len()))?;
            let mut out = generate_reserved_inline_object_raw(field, desc, generated_args, rng)?;
            if !*varlen {
                out.data.resize(*size, 0);
            } else {
                let union_align = union_type_alignment(fields, *packed, *align).ok()?;
                let final_size = if union_align <= 1 {
                    out.data.len()
                } else {
                    out.data
                        .len()
                        .checked_add(union_align - 1)
                        .map(|rounded| rounded & !(union_align - 1))?
                };
                out.data.resize(final_size, 0);
            }
            Some(out)
        }
        ArgType::Ptr {
            inner,
            dir,
            optional,
        } => {
            let mut object = InlineObject {
                data: vec![0; 8],
                pointers: Vec::new(),
                struct_layouts: Vec::new(),
            };
            if *optional && rng.gen_bool(0.35) {
                return Some(object);
            }
            let value = match dir {
                PtrDir::Out => {
                    generate_reserved_pointer_arg_value(inner, desc, generated_args, rng)
                }
                PtrDir::In | PtrDir::InOut => {
                    generate_pointer_arg_value(desc, generated_args, inner, dir, rng)
                }
            };
            object.pointers.push(InlinePointerValue {
                offset: 0,
                value: Box::new(value),
            });
            Some(object)
        }
    }
}

fn patch_inline_len_fields(
    arg_type: &ArgType,
    desc: Option<&SyscallDesc>,
    generated_args: Option<&[ArgValue]>,
    frames: &[LengthTargetFrame<'_>],
    data: &mut [u8],
    pointers: &[InlinePointerValue],
    struct_layouts: Option<&[InlineStructLayout]>,
    base_offset: usize,
) -> Option<()> {
    match arg_type {
        ArgType::Const { .. }
        | ArgType::Proc { .. }
        | ArgType::Resource(_)
        | ArgType::OptionalResource(_)
        | ArgType::Void
        | ArgType::String { .. }
        | ArgType::Buffer { .. }
        | ArgType::Vma { .. }
        | ArgType::Filename => Some(()),
        ArgType::Len {
            target,
            size,
            kind,
            endian,
            scale,
            bitfield_bits,
        } => {
            let value = derive_inline_target_length(desc, generated_args, frames, target, *kind)
                .unwrap_or(0);
            let scaled = scale_length_value(value, *scale) as u64;
            if let Some(bits) = bitfield_bits {
                let info = standalone_bitfield_field_info(*size, *endian, *bits)?;
                encode_bitfield_storage_value(data, info, scaled)?;
                return Some(());
            }
            let encoded = encode_scalar_bytes_endian(*size, scaled, *endian);
            data.get_mut(..encoded.len())?.copy_from_slice(&encoded);
            Some(())
        }
        ArgType::Array { inner, .. } => {
            let elem_size = arg_type_fixed_size(inner)?;
            if elem_size == 0 {
                return Some(());
            }
            for (element_idx, chunk) in data.chunks_exact_mut(elem_size).enumerate() {
                patch_inline_len_fields(
                    inner,
                    desc,
                    generated_args,
                    frames,
                    chunk,
                    pointers,
                    struct_layouts,
                    base_offset + (element_idx * elem_size),
                )?;
            }
            Some(())
        }
        ArgType::Struct {
            type_name,
            fields,
            field_names,
            varlen,
            packed,
            align,
            overlay_start,
            ..
        } => {
            let ranges = if let Some(field_ranges) =
                lookup_inline_struct_layout(struct_layouts, base_offset, fields.len())
            {
                field_ranges
                    .iter()
                    .map(|(start, end)| {
                        Some((
                            start.checked_sub(base_offset)?,
                            end.checked_sub(base_offset)?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?
            } else {
                compute_struct_field_ranges(
                    fields,
                    *varlen,
                    *packed,
                    *align,
                    *overlay_start,
                    data.len(),
                )?
            };
            let bitfield_info = compute_bitfield_field_info(fields)?;
            let mut idx = 0usize;
            while idx < fields.len() {
                if let Some(info) = bitfield_info[idx] {
                    let mut group_end = idx;
                    while !bitfield_info[group_end]?.is_last_in_group {
                        group_end += 1;
                    }
                    let unit_offset = ranges[idx].0;
                    let unit_end = if ranges[group_end].1 > unit_offset {
                        ranges[group_end].1
                    } else {
                        unit_offset.checked_add(info.unit_size)?
                    };
                    for field_idx in idx..=group_end {
                        let ArgType::Len {
                            target,
                            kind,
                            scale,
                            ..
                        } = &fields[field_idx]
                        else {
                            continue;
                        };
                        let snapshot = data.to_vec();
                        let mut next_frames = frames.to_vec();
                        next_frames.push(LengthTargetFrame {
                            type_name: type_name.as_deref(),
                            fields,
                            field_names,
                            size: snapshot.len(),
                            is_union: false,
                            varlen: *varlen,
                            packed: *packed,
                            align: *align,
                            overlay_start: *overlay_start,
                            data: Some(snapshot.as_slice()),
                            pointers: Some(pointers),
                            struct_layouts,
                            base_offset,
                        });
                        let value = derive_inline_target_length(
                            desc,
                            generated_args,
                            &next_frames,
                            target,
                            *kind,
                        )
                        .unwrap_or(0);
                        let scaled = scale_length_value(value, *scale) as u64;
                        encode_bitfield_storage_value(
                            data.get_mut(unit_offset..unit_end)?,
                            bitfield_info[field_idx]?,
                            scaled,
                        )?;
                    }
                    idx = group_end + 1;
                    continue;
                }

                let field = &fields[idx];
                let (offset, end) = ranges[idx];
                let snapshot = data.to_vec();
                let mut next_frames = frames.to_vec();
                next_frames.push(LengthTargetFrame {
                    type_name: type_name.as_deref(),
                    fields,
                    field_names,
                    size: snapshot.len(),
                    is_union: false,
                    varlen: *varlen,
                    packed: *packed,
                    align: *align,
                    overlay_start: *overlay_start,
                    data: Some(snapshot.as_slice()),
                    pointers: Some(pointers),
                    struct_layouts,
                    base_offset,
                });
                patch_inline_len_fields(
                    field,
                    desc,
                    generated_args,
                    &next_frames,
                    data.get_mut(offset..end)?,
                    pointers,
                    struct_layouts,
                    base_offset + offset,
                )?;
                idx += 1;
            }
            Some(())
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
        } => {
            for field in fields {
                let Some(field_size) = arg_type_fixed_size(field) else {
                    continue;
                };
                if *varlen && field_size != data.len() {
                    continue;
                }
                if field_size > data.len() {
                    continue;
                }
                let snapshot = data.to_vec();
                let mut next_frames = frames.to_vec();
                next_frames.push(LengthTargetFrame {
                    type_name: type_name.as_deref(),
                    fields,
                    field_names,
                    size: if *varlen { snapshot.len() } else { *size },
                    is_union: true,
                    varlen: *varlen,
                    packed: *packed,
                    align: *align,
                    overlay_start: None,
                    data: Some(snapshot.as_slice()),
                    pointers: Some(pointers),
                    struct_layouts,
                    base_offset,
                });
                if patch_inline_len_fields(
                    field,
                    desc,
                    generated_args,
                    &next_frames,
                    data.get_mut(..field_size)?,
                    pointers,
                    struct_layouts,
                    base_offset,
                )
                .is_some()
                {
                    break;
                }
            }
            Some(())
        }
        ArgType::Ptr { .. } => Some(()),
    }
}

fn union_fallback_size(fields: &[ArgType], size: usize, varlen: bool) -> usize {
    if !varlen {
        return size;
    }
    fields.first().and_then(arg_type_fixed_size).unwrap_or(size)
}

fn generate_string_bytes(
    values: &[Vec<u8>],
    noz: bool,
    fixed_len: Option<usize>,
    filename: bool,
    rng: &mut impl Rng,
) -> Vec<u8> {
    let source = if filename {
        choose_filename_source(fixed_len, rng).into_bytes()
    } else if !values.is_empty() {
        choose_string_source(values, fixed_len, noz, rng)
    } else {
        random_string_source(fixed_len, noz, rng)
    };
    materialize_string_bytes(source, noz, fixed_len)
}

fn choose_filename_source(fixed_len: Option<usize>, rng: &mut impl Rng) -> String {
    let candidates = [
        "./a",
        "./b",
        "./c",
        "./file0",
        "./file1",
        "./dir0/file0",
        "/tmp/syz0",
        "/tmp/syz1",
    ];
    let fits = |candidate: &&str| {
        let encoded_len = candidate.len() + 1;
        fixed_len.is_none_or(|limit| encoded_len <= limit)
    };
    let matching = candidates.iter().copied().filter(fits).collect::<Vec<_>>();
    if matching.is_empty() {
        "./a".to_string()
    } else {
        matching[rng.gen_range(0..matching.len())].to_string()
    }
}

fn choose_string_source(
    values: &[Vec<u8>],
    fixed_len: Option<usize>,
    noz: bool,
    rng: &mut impl Rng,
) -> Vec<u8> {
    let matching = values
        .iter()
        .filter(|value| string_source_fits(value, noz, fixed_len))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        values[rng.gen_range(0..values.len())].clone()
    } else {
        matching[rng.gen_range(0..matching.len())].clone()
    }
}

fn random_string_source(fixed_len: Option<usize>, noz: bool, rng: &mut impl Rng) -> Vec<u8> {
    let max_len = fixed_len
        .map(|len| len.saturating_sub(usize::from(!noz)))
        .unwrap_or(16)
        .max(1);
    let len = rng.gen_range(1..=max_len);
    (0..len)
        .map(|_| b'a' + rng.gen_range(0..26) as u8)
        .collect()
}

fn string_source_fits(value: &[u8], noz: bool, fixed_len: Option<usize>) -> bool {
    fixed_len.is_none_or(|limit| value.len() + usize::from(!noz) <= limit)
}

fn materialize_string_bytes(mut source: Vec<u8>, noz: bool, fixed_len: Option<usize>) -> Vec<u8> {
    if let Some(limit) = fixed_len {
        let content_limit = if noz { limit } else { limit.saturating_sub(1) };
        if source.len() > content_limit {
            source.truncate(content_limit);
        }
    }
    if !noz {
        source.push(0);
    }
    if let Some(limit) = fixed_len {
        source.resize(limit, 0);
    }
    source
}

fn generate_vma(min_pages: usize, max_pages: usize, rng: &mut impl Rng) -> ArgValue {
    let pages = if min_pages >= max_pages {
        min_pages as u64
    } else {
        rng.gen_range(min_pages as u64..=max_pages as u64)
    };
    let usable_pages = VMA_NUM_PAGES.saturating_sub(VMA_RESERVED_START_PAGE).max(1);
    let clamped_pages = pages.min(usable_pages).max(1);
    let max_start_page = VMA_NUM_PAGES.saturating_sub(clamped_pages);
    let start_page = if max_start_page <= VMA_RESERVED_START_PAGE {
        VMA_RESERVED_START_PAGE.min(max_start_page)
    } else {
        rng.gen_range(VMA_RESERVED_START_PAGE..=max_start_page)
    };
    ArgValue::Vma {
        addr: DATA_OFFSET + start_page * PAGE_SIZE,
        size: clamped_pages * PAGE_SIZE,
    }
}

// ============================================================
// Mutation operations
// ============================================================

/// Mutate a program by applying a random mutation.
pub fn mutate(prog: &Program, descs: &[SyscallDesc], rng: &mut impl Rng) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, &[]);
    mutate_with_choice_table(prog, descs, &choice_table, rng)
}

/// Mutate a program by applying a random mutation, optionally biased by corpus history.
pub fn mutate_with_corpus(
    prog: &Program,
    descs: &[SyscallDesc],
    corpus: &[Program],
    rng: &mut impl Rng,
) -> Program {
    let choice_table = SyscallChoiceTable::build(descs, corpus);
    mutate_with_choice_table(prog, descs, &choice_table, rng)
}

pub fn mutate_with_choice_table(
    prog: &Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    rng: &mut impl Rng,
) -> Program {
    mutate_with_choice_table_and_edge_bias(prog, descs, choice_table, &HashMap::new(), rng)
}

pub fn mutate_with_choice_table_and_edge_bias(
    prog: &Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) -> Program {
    let mut new_prog = prog.clone();
    let mutation_type = rng.gen_range(0..6);
    match mutation_type {
        0 => mutate_insert_call(
            &mut new_prog,
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        ),
        1 => mutate_remove_call(&mut new_prog, rng),
        2 => mutate_args(&mut new_prog, descs, rng),
        3 => mutate_integer(&mut new_prog, descs, rng),
        4 => mutate_buffer(&mut new_prog, descs, rng),
        5 => splice(
            &mut new_prog,
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        ),
        _ => {}
    }
    // Ensure program is not empty
    if new_prog.calls.is_empty() {
        new_prog = generate_with_choice_table_and_edge_bias(
            descs,
            choice_table,
            timeout_edge_failures,
            rng,
        );
    }
    // Ensure program is not too long
    if new_prog.calls.len() > MAX_CALLS {
        new_prog.calls.truncate(MAX_CALLS);
    }
    repair_result_refs(&mut new_prog, descs);
    debug_assert!(validate_program(&new_prog, descs).is_ok());
    new_prog
}

/// Insert a random call at a random position.
fn mutate_insert_call(
    prog: &mut Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) {
    if prog.calls.len() >= MAX_CALLS {
        return;
    }
    if choice_table.enabled_syscalls().is_empty() {
        return;
    }
    let pos = rng.gen_range(0..=prog.calls.len());
    shift_result_refs_for_insert(prog, pos);
    let available_resources = available_resources_before(&prog.calls, descs, pos);
    let previous_syscall_idx = pos
        .checked_sub(1)
        .and_then(|idx| prog.calls.get(idx))
        .map(|call| call.syscall_idx);
    let syscall_idx = choose_syscall_for_generation(
        descs,
        choice_table,
        previous_syscall_idx,
        &available_resources,
        timeout_edge_failures,
        rng,
    );
    let desc = &descs[syscall_idx];
    let args = generate_args(desc, &available_resources, rng);
    prog.calls.insert(pos, Call { syscall_idx, args });
}

/// Remove a random call.
fn mutate_remove_call(prog: &mut Program, rng: &mut impl Rng) {
    if prog.calls.len() <= 1 {
        return;
    }
    let pos = rng.gen_range(0..prog.calls.len());
    prog.calls.remove(pos);
    shift_result_refs_for_removal(prog, pos);
}

/// Replace arguments of a random call with fresh ones.
fn mutate_args(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..prog.calls.len());
    let available_resources = available_resources_before(&prog.calls, descs, idx);

    let desc = &descs[prog.calls[idx].syscall_idx];
    prog.calls[idx].args = generate_args(desc, &available_resources, rng);
}

/// Mutate an integer argument.
fn mutate_integer(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    let desc = &descs[call.syscall_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
    if matches!(desc.args.get(arg_idx), Some(ArgType::Len { .. })) {
        return;
    }
    if let ArgValue::Const(ref mut val) = call.args[arg_idx] {
        let op = rng.gen_range(0..5);
        match op {
            0 => *val = val.wrapping_add(rng.gen_range(1..=16)),
            1 => *val = val.wrapping_sub(rng.gen_range(1..=16)),
            2 => *val ^= 1u64 << rng.gen_range(0..64),
            3 => *val = rng.gen(),
            4 => {
                *val = [
                    0,
                    1,
                    0xFFFF_FFFF,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0x80000000,
                    0x7FFFFFFF,
                ][rng.gen_range(0..6)]
            }
            _ => {}
        }
        if let Some(ArgType::Proc {
            values_per_proc, ..
        }) = desc.args.get(arg_idx)
        {
            *val = if *values_per_proc == 0 {
                0
            } else if *val == PROC_DEFAULT_VALUE {
                0
            } else {
                *val % *values_per_proc
            };
        }
    } else if let Some(ArgType::Vma {
        min_pages,
        max_pages,
        optional,
    }) = desc.args.get(arg_idx)
    {
        if *optional && rng.gen_bool(0.2) {
            call.args[arg_idx] = ArgValue::Null;
        } else {
            call.args[arg_idx] = generate_vma(*min_pages, *max_pages, rng);
        }
    }
}

/// Mutate buffer content.
fn mutate_buffer(prog: &mut Program, descs: &[SyscallDesc], rng: &mut impl Rng) {
    if prog.calls.is_empty() {
        return;
    }
    let call_idx = rng.gen_range(0..prog.calls.len());
    let call = &mut prog.calls[call_idx];
    let desc = &descs[call.syscall_idx];
    if call.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..call.args.len());
    if matches!(
        desc.args.get(arg_idx),
        Some(ArgType::Ptr {
            inner,
            ..
        }) if matches!(inner.as_ref(), ArgType::Len { .. })
    ) {
        return;
    }
    if let ArgValue::Buffer(ref mut data) = call.args[arg_idx] {
        if data.is_empty() {
            return;
        }
        let op = rng.gen_range(0..3);
        match op {
            0 => {
                // Flip a random byte
                let pos = rng.gen_range(0..data.len());
                data[pos] ^= 1u8 << rng.gen_range(0..8);
            }
            1 => {
                // Overwrite with random bytes
                let pos = rng.gen_range(0..data.len());
                let len = rng.gen_range(1..=std::cmp::min(8, data.len() - pos));
                for i in pos..pos + len {
                    data[i] = rng.gen();
                }
            }
            2 => {
                // Set a byte to a special value
                let pos = rng.gen_range(0..data.len());
                data[pos] = [0, 0xFF, 0x7F, 0x80, 0x41][rng.gen_range(0..5)];
            }
            _ => {}
        }
    }
}

/// Splice: take calls from a fresh program and merge.
fn splice(
    prog: &mut Program,
    descs: &[SyscallDesc],
    choice_table: &SyscallChoiceTable,
    timeout_edge_failures: &HashMap<String, u32>,
    rng: &mut impl Rng,
) {
    let other =
        generate_with_choice_table_and_edge_bias(descs, choice_table, timeout_edge_failures, rng);
    if other.calls.is_empty() || prog.calls.is_empty() {
        return;
    }
    let split_self = rng.gen_range(0..prog.calls.len());
    let split_other = rng.gen_range(0..other.calls.len());
    let mut new_calls = prog.calls[..split_self].to_vec();
    new_calls.extend_from_slice(&other.calls[split_other..]);
    prog.calls = new_calls;
    repair_result_refs(prog, descs);
}

/// Describe a program in human-readable form.
pub fn describe_program(prog: &Program, descs: &[SyscallDesc]) -> String {
    let mut s = String::new();
    for (i, call) in prog.calls.iter().enumerate() {
        let desc = &descs[call.syscall_idx];
        s.push_str(&format!("{}. {}(", i, desc.name));
        for (j, (arg, arg_type)) in call.args.iter().zip(desc.args.iter()).enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            match arg {
                ArgValue::Const(v) => s.push_str(&format!("0x{:x}", v)),
                ArgValue::ResultRef(result_ref) => s.push_str(&format!(
                    "result_from_call_{}_{}",
                    result_ref.call_idx, result_ref.result_idx
                )),
                ArgValue::Buffer(d) => s.push_str(&format!("buf[{}]", d.len())),
                ArgValue::Composite { data, pointers, .. } => {
                    s.push_str(&format!("obj[{};+{}ptr]", data.len(), pointers.len()))
                }
                ArgValue::Array {
                    data,
                    pointers,
                    element_sizes,
                    ..
                } => s.push_str(&format!(
                    "arr[{};+{}ptr;{}elts]",
                    data.len(),
                    pointers.len(),
                    element_sizes.len()
                )),
                ArgValue::Filename(f) => s.push_str(&format!("\"{}\"", f)),
                ArgValue::Vma { addr, size } => {
                    if matches!(arg_type, ArgType::Vma { .. }) {
                        s.push_str(&format!("&(0x{:x}/0x{:x})", addr, size));
                    } else {
                        s.push_str(&format!("0x{:x}", addr));
                    }
                }
                ArgValue::OutPtr => s.push_str("&out"),
                ArgValue::Null => s.push_str("NULL"),
            }
        }
        s.push_str(")\n");
    }
    s
}

fn random_value_for_size(size: usize, rng: &mut impl Rng) -> u64 {
    let bit_width = size.saturating_mul(8);
    if bit_width >= 64 {
        rng.gen()
    } else {
        rng.gen::<u64>() & ((1u64 << bit_width) - 1)
    }
}

fn resource_producers_for_missing_inputs(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    desc: &SyscallDesc,
    available_resources: &HashMap<String, Vec<ResultRef>>,
) -> Vec<usize> {
    let mut producers = Vec::new();
    let mut seen = HashSet::new();

    for resource in input_resources(desc) {
        let is_available = available_resources
            .get(&resource.kind)
            .is_some_and(|values| !values.is_empty());
        if is_available {
            continue;
        }
        for syscall_idx in resource_constructor_syscalls(descs, &resource) {
            if enabled_syscalls.contains(&syscall_idx) && seen.insert(syscall_idx) {
                producers.push(syscall_idx);
            }
        }
    }

    producers
}

fn resource_consumers_for_available_inputs(
    descs: &[SyscallDesc],
    enabled_syscalls: &[usize],
    available_resources: &HashMap<String, Vec<ResultRef>>,
) -> Vec<usize> {
    let mut consumers = Vec::new();

    for &syscall_idx in enabled_syscalls {
        let inputs = input_resources(&descs[syscall_idx]);
        if inputs.is_empty() {
            continue;
        }

        let all_available = inputs.iter().all(|resource| {
            available_resources
                .get(&resource.kind)
                .is_some_and(|values| !values.is_empty())
        });
        if !all_available {
            continue;
        }

        let uses_current_resources = inputs.iter().any(|resource| {
            available_resources
                .get(&resource.kind)
                .is_some_and(|values| !values.is_empty())
        });
        if uses_current_resources {
            consumers.push(syscall_idx);
        }
    }

    consumers
}

fn timeout_edge_penalty(
    descs: &[SyscallDesc],
    previous_syscall_idx: Option<usize>,
    candidate_idx: usize,
    timeout_edge_failures: &HashMap<String, u32>,
) -> u32 {
    let Some(previous_syscall_idx) = previous_syscall_idx else {
        return 0;
    };
    timeout_prone_edge_key(descs, previous_syscall_idx, candidate_idx)
        .and_then(|edge| timeout_edge_failures.get(&edge).copied())
        .unwrap_or(0)
}

fn prefer_low_penalty_candidates(
    descs: &[SyscallDesc],
    previous_syscall_idx: Option<usize>,
    candidates: &[usize],
    timeout_edge_failures: &HashMap<String, u32>,
) -> Vec<usize> {
    if candidates.len() <= 1 || timeout_edge_failures.is_empty() {
        return candidates.to_vec();
    }

    let mut best_penalty = u32::MAX;
    let mut filtered = Vec::new();
    for &candidate in candidates {
        let penalty = timeout_edge_penalty(
            descs,
            previous_syscall_idx,
            candidate,
            timeout_edge_failures,
        );
        if penalty < best_penalty {
            best_penalty = penalty;
            filtered.clear();
            filtered.push(candidate);
        } else if penalty == best_penalty {
            filtered.push(candidate);
        }
    }

    if filtered.is_empty() {
        candidates.to_vec()
    } else {
        filtered
    }
}

fn available_resources_before(
    calls: &[Call],
    descs: &[SyscallDesc],
    upto: usize,
) -> HashMap<String, Vec<ResultRef>> {
    let mut resources = HashMap::new();
    for (index, call) in calls[..upto].iter().enumerate() {
        for (result_idx, output) in resource_outputs(&descs[call.syscall_idx])
            .into_iter()
            .enumerate()
        {
            register_available_resource(
                &mut resources,
                &output.resource,
                ResultRef {
                    call_idx: index,
                    result_idx,
                },
            );
        }
    }
    resources
}

fn shift_result_refs_for_insert(prog: &mut Program, pos: usize) {
    for call in &mut prog.calls {
        for arg in &mut call.args {
            if let ArgValue::ResultRef(result_ref) = arg {
                if result_ref.call_idx >= pos {
                    result_ref.call_idx += 1;
                }
            }
        }
    }
}

fn shift_result_refs_for_removal(prog: &mut Program, pos: usize) {
    for call in &mut prog.calls {
        for arg in &mut call.args {
            if let ArgValue::ResultRef(result_ref) = arg {
                if result_ref.call_idx == pos {
                    result_ref.call_idx = usize::MAX;
                    result_ref.result_idx = usize::MAX;
                } else if result_ref.call_idx > pos {
                    result_ref.call_idx -= 1;
                }
            }
        }
    }
}

fn repair_result_refs(prog: &mut Program, descs: &[SyscallDesc]) {
    let mut available_resources: HashMap<String, Vec<ResultRef>> = HashMap::new();
    for call_idx in 0..prog.calls.len() {
        let desc = &descs[prog.calls[call_idx].syscall_idx];
        for (arg_type, arg_value) in desc.args.iter().zip(prog.calls[call_idx].args.iter_mut()) {
            if let ArgType::Resource(resource) | ArgType::OptionalResource(resource) = arg_type {
                if let ArgValue::ResultRef(ref_idx) = arg_value {
                    let available = available_resources.get(&resource.kind);
                    let has_match = available.is_some_and(|indices| indices.contains(ref_idx));
                    if !has_match {
                        if let Some(last_idx) =
                            available.and_then(|indices| indices.last()).cloned()
                        {
                            *ref_idx = last_idx;
                        } else {
                            *arg_value = ArgValue::Const(resource.default_value());
                        }
                    }
                }
            }
        }
        for (result_idx, output) in resource_outputs(desc).into_iter().enumerate() {
            register_available_resource(
                &mut available_resources,
                &output.resource,
                ResultRef {
                    call_idx,
                    result_idx,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn syscall_idx(descs: &[SyscallDesc], name: &str) -> usize {
        descs
            .iter()
            .position(|desc| desc.name == name)
            .unwrap_or_else(|| panic!("missing syscall {name}"))
    }

    #[test]
    fn generates_program_from_parsed_descriptions() {
        let descs = get_syscall_descs();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
        let prog = generate(&descs, &mut rng);
        assert!(!prog.calls.is_empty());
        assert!(prog.calls.len() <= MAX_CALLS);
        for call in &prog.calls {
            assert!(call.syscall_idx < descs.len());
        }
        prog.validate(&descs)
            .expect("generated programs must validate");
    }

    #[test]
    fn repair_result_refs_after_removal_retargets_to_previous_resource() {
        let descs = get_syscall_descs();
        let eventfd2 = syscall_idx(&descs, "eventfd2");
        let close = syscall_idx(&descs, "close");
        let mut prog = Program {
            calls: vec![
                Call {
                    syscall_idx: eventfd2,
                    args: vec![ArgValue::Const(0), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: eventfd2,
                    args: vec![ArgValue::Const(1), ArgValue::Const(0)],
                },
                Call {
                    syscall_idx: close,
                    args: vec![ArgValue::ResultRef(ResultRef {
                        call_idx: 1,
                        result_idx: 0,
                    })],
                },
            ],
        };

        prog.calls.remove(1);
        shift_result_refs_for_removal(&mut prog, 1);
        repair_result_refs(&mut prog, &descs);

        match prog.calls[1].args[0] {
            ArgValue::ResultRef(ref result_ref) => {
                assert_eq!(result_ref.call_idx, 0);
                assert_eq!(result_ref.result_idx, 0);
            }
            ref other => panic!("unexpected arg after repair: {:?}", other),
        }
    }

    #[test]
    fn generate_inline_bytes_materializes_union_sizes() {
        let fixed_union = ArgType::Union {
            type_name: None,
            fields: vec![
                ArgType::Buffer {
                    min_size: 2,
                    max_size: 2,
                    dir: BufferDir::Plain,
                },
                ArgType::Buffer {
                    min_size: 4,
                    max_size: 4,
                    dir: BufferDir::Plain,
                },
            ],
            field_names: vec!["a".into(), "b".into()],
            size: 8,
            varlen: false,
            packed: false,
            align: None,
        };
        let varlen_union = ArgType::Union {
            type_name: None,
            fields: vec![
                ArgType::Buffer {
                    min_size: 2,
                    max_size: 2,
                    dir: BufferDir::Plain,
                },
                ArgType::Buffer {
                    min_size: 4,
                    max_size: 4,
                    dir: BufferDir::Plain,
                },
            ],
            field_names: vec!["a".into(), "b".into()],
            size: 4,
            varlen: true,
            packed: false,
            align: None,
        };
        let desc = SyscallDesc {
            name: "inline".into(),
            id: 0,
            arg_names: Vec::new(),
            args: Vec::new(),
            ret: ReturnType::Int,
            attrs: SyscallAttrs::default(),
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_ffff);

        for _ in 0..16 {
            assert_eq!(
                generate_inline_bytes(&fixed_union, &desc, &[], &mut rng)
                    .unwrap()
                    .len(),
                8
            );
            let len = generate_inline_bytes(&varlen_union, &desc, &[], &mut rng)
                .unwrap()
                .len();
            assert!(matches!(len, 2 | 4));
        }
    }

    #[test]
    fn generates_vma_lengths_from_selected_mapping_size() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                syscall map@1 -> int(addr vma[2:3], len len[addr])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xbeef_1234);

        for _ in 0..16 {
            let args = generate_args(desc, &HashMap::new(), &mut rng);
            let (addr, size) = match &args[0] {
                ArgValue::Vma { addr, size } => (*addr, *size),
                other => panic!("unexpected vma arg: {:?}", other),
            };
            assert!(addr >= DATA_OFFSET);
            assert_eq!(addr % PAGE_SIZE, 0);
            assert!(matches!(size / PAGE_SIZE, 2 | 3));
            assert_eq!(args[1], ArgValue::Const(size));
        }
    }

    #[test]
    fn generates_string_lengths_from_materialized_pointer_strings() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                path_values = "/dev/null", "/dev/zero"
                syscall write_like@1 -> int(path ptr[in, string[path_values]], path_len len[path], word ptr[in, stringnoz["abc", 8]], word_len len[word])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xc0de_1234);

        for _ in 0..16 {
            let args = generate_args(desc, &HashMap::new(), &mut rng);
            let path_len = match &args[0] {
                ArgValue::Buffer(data) => {
                    assert!(data.ends_with(&[0]));
                    data.len() as u64
                }
                other => panic!("unexpected path arg: {:?}", other),
            };
            assert_eq!(args[1], ArgValue::Const(path_len));

            match &args[2] {
                ArgValue::Buffer(data) => {
                    assert_eq!(data.len(), 8);
                    assert_eq!(&data[..3], b"abc");
                }
                other => panic!("unexpected stringnoz arg: {:?}", other),
            }
            assert_eq!(args[3], ArgValue::Const(8));
        }
    }

    #[test]
    fn generates_lengths_for_template_instantiated_payloads() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                payloads = "syz", "hello"
                type wrap[PAYLOAD] {
                    payload PAYLOAD
                }
                type alias_wrap[PAYLOAD] wrap[PAYLOAD]
                syscall write_wrap@1 -> int(fd const[1, int32], data ptr[in, alias_wrap[stringnoz[payloads, 8]]], size len[data])
            "#,
        )
        .expect("template target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4444_2222);

        for _ in 0..16 {
            let args = generate_args(desc, &HashMap::new(), &mut rng);
            match &args[1] {
                ArgValue::Buffer(data) => {
                    assert_eq!(data.len(), 8);
                    assert!(data.starts_with(b"syz") || data.starts_with(b"hello"));
                }
                other => panic!("unexpected templated payload arg: {:?}", other),
            }
            assert_eq!(args[2], ArgValue::Const(8));
        }
    }

    #[test]
    fn generates_inline_proc_fields_with_proc0_materialization() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type ipv4_addr_initdev {
                    a0 const[0xac, int8]
                    a1 const[0x1e, int8]
                    a2 int8[0:1]
                    a3 proc[1, 1, int8]
                }
                syscall use_addr@1 -> int(addr ptr[in, ipv4_addr_initdev])
            "#,
        )
        .expect("proc-bearing target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5150_c001);

        for _ in 0..8 {
            let args = generate_args(desc, &HashMap::new(), &mut rng);
            match &args[0] {
                ArgValue::Buffer(data) => {
                    assert_eq!(data.len(), 4);
                    assert_eq!(data[0], 0xac);
                    assert_eq!(data[1], 0x1e);
                    assert!(matches!(data[2], 0 | 1));
                    assert_eq!(data[3], 1);
                }
                other => panic!("unexpected inline proc argument: {:?}", other),
            }
        }
    }

    #[test]
    fn mutated_programs_remain_valid() {
        let descs = get_syscall_descs();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfacefeed);
        let mut prog = generate(&descs, &mut rng);

        for _ in 0..64 {
            prog = mutate(&prog, &descs, &mut rng);
            prog.validate(&descs)
                .expect("mutated programs must remain structurally valid");
        }
    }

    #[test]
    fn generates_unbounded_8_byte_constants() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xabad1dea);
        let desc = SyscallDesc {
            name: "const_only".into(),
            id: 1,
            arg_names: vec!["value".into()],
            args: vec![ArgType::Const {
                size: 8,
                values: vec![],
                range: None,
                endian: ScalarEndian::Native,
                allow_any: true,
                bitfield_bits: None,
            }],
            ret: ReturnType::Int,
            attrs: SyscallAttrs::default(),
        };
        let arg = generate_arg(
            &desc,
            &[],
            &ArgType::Const {
                size: 8,
                values: vec![],
                range: None,
                endian: ScalarEndian::Native,
                allow_any: true,
                bitfield_bits: None,
            },
            &HashMap::new(),
            &mut rng,
        );

        assert!(matches!(arg, ArgValue::Const(_)));
    }

    #[test]
    fn generates_length_arguments_from_materialized_pointer_sizes() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                type sockaddr_storage buffer[16:16]
                bind(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x600d_f00d);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) | ArgType::OptionalResource(resource) => resource,
                other => panic!("unexpected bind fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        assert!(matches!(args[1], ArgValue::Buffer(ref data) if data.len() == 16));
        assert!(matches!(args[2], ArgValue::Const(16)));
    }

    #[test]
    fn generates_forward_syscall_lengths_after_target_args() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type fd_set buffer[128:128]
                syscall select_like@1 -> int(n len[inp, int32], inp ptr[inout, fd_set], outp ptr[inout, len[inp, int32]])
            "#,
        )
        .expect("forward len target target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x514c_4543);

        for _ in 0..8 {
            let args = generate_args(desc, &HashMap::new(), &mut rng);
            assert!(matches!(args[1], ArgValue::Buffer(ref data) if data.len() == 128));
            assert_eq!(args[0], ArgValue::Const(128));
            assert!(matches!(args[2], ArgValue::Buffer(ref data) if data.len() == 4));
            match &args[2] {
                ArgValue::Buffer(data) => {
                    assert_eq!(decode_scalar_bytes_endian(data, ScalarEndian::Native), 128);
                }
                other => panic!("unexpected outp arg: {:?}", other),
            }
        }
    }

    #[test]
    fn generates_structured_sockaddr_bytes_and_matching_length() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd]
                resource sock_in[sock]
                const AF_INET = 2
                type sock_port int16be[20000:20004]
                type ipv4_addr const[0x7f000001, int32be]
                sockaddr_in {
                    family const[AF_INET, int16]
                    port sock_port
                    addr ipv4_addr
                } [size[16]]
                bind$inet(fd sock_in, addr ptr[in, sockaddr_in], addrlen len[addr])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1a7e_5eed);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) | ArgType::OptionalResource(resource) => resource,
                other => panic!("unexpected bind fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        match &args[1] {
            ArgValue::Buffer(data) => {
                assert_eq!(data.len(), 16);
                assert_eq!(&data[..2], &[2, 0]);
                assert_eq!(&data[4..8], &[127, 0, 0, 1]);
            }
            other => panic!("unexpected bind addr arg: {:?}", other),
        }
        assert!(matches!(args[2], ArgValue::Const(16)));
    }

    #[test]
    fn generates_buffer_lengths_for_len_and_bytesize() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                syscall send@1(fd fd, buf buffer[in], count len[buf, int32], size bytesize[buf, int32])
            "#,
        )
        .expect("test target should parse");
        let desc = &descs[0];
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x600d_beef);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &desc.args[0] {
                ArgType::Resource(resource) | ArgType::OptionalResource(resource) => resource,
                other => panic!("unexpected send fd arg: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let args = generate_args(desc, &available_resources, &mut rng);
        let buf_len = match &args[1] {
            ArgValue::Buffer(data) => data.len() as u64,
            other => panic!("unexpected send buf arg: {:?}", other),
        };
        assert!(matches!(args[2], ArgValue::Const(v) if v == buf_len));
        assert!(matches!(args[3], ArgValue::Const(v) if v == buf_len));
    }

    #[test]
    fn missing_sock_input_prefers_sock_constructor() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                syscall listen@2 -> int(sock, const[4; 1])
                syscall close@3 -> int(fd)
            "#,
        )
        .expect("test target should parse");

        let availability = transitively_enabled_syscalls(&descs);
        let producers = resource_producers_for_missing_inputs(
            &descs,
            &availability.enabled,
            &descs[1],
            &HashMap::new(),
        );
        assert_eq!(producers, vec![0]);
    }

    #[test]
    fn generation_skips_transitively_disabled_syscalls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall close@2 -> int(fd)
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_5678);

        for _ in 0..16 {
            let prog = generate(&descs, &mut rng);
            assert!(!prog.calls.is_empty());
            assert!(prog.calls.iter().all(|call| call.syscall_idx == 0));
        }
    }

    #[test]
    fn generation_skips_no_generate_syscalls() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1
                syscall getpid@1 -> int()
                syscall eventfd2@2 -> fd(const[4; 0], const[4; 0]) (no_generate)
                syscall close@3 -> int(fd)
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5678_1234);

        for _ in 0..16 {
            let prog = generate(&descs, &mut rng);
            assert!(!prog.calls.is_empty());
            assert!(prog.calls.iter().all(|call| call.syscall_idx == 0));
        }
    }

    #[test]
    fn available_sock_resources_surface_sock_consumers() {
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
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &descs[0].ret {
                ReturnType::Resource(resource) => resource,
                other => panic!("unexpected socket return: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );

        let consumers = resource_consumers_for_available_inputs(
            &descs,
            &availability.enabled,
            &available_resources,
        );
        assert!(consumers.contains(&1)); // listen(sock)
        assert!(consumers.contains(&2)); // close(fd) via sock -> fd compatibility
        assert!(!consumers.contains(&0)); // socket does not consume resources
        assert!(!consumers.contains(&3)); // getpid does not consume resources
    }

    #[test]
    fn timeout_edge_penalty_filters_followup_candidates() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                type sockaddr_storage buffer[16:16]
                syscall socket$inet@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                sendto$inet(fd sock, buf buffer[in], len bytesize[buf, int32], flags const[4; 0], addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
                bind$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
                connect$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let penalties = HashMap::from([("sendto$inet->bind$inet".to_string(), 1)]);

        assert_eq!(
            prefer_low_penalty_candidates(&descs, Some(1), &[2, 3], &penalties),
            vec![3]
        );
    }

    #[test]
    fn generation_bias_avoids_penalized_timeout_edge_when_alternative_exists() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                resource fd[4] = -1, 0
                resource sock[fd] = -1, 0
                type sockaddr_storage buffer[16:16]
                syscall socket$inet@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
                sendto$inet(fd sock, buf buffer[in], len bytesize[buf, int32], flags const[4; 0], addr ptr[in, sockaddr_storage, opt], addrlen len[addr, int32])
                bind$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
                connect$inet(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
            "#,
        )
        .expect("test target should parse");
        let choice_table = SyscallChoiceTable::build(&descs, &[]);
        let mut available_resources = HashMap::new();
        register_available_resource(
            &mut available_resources,
            match &descs[0].ret {
                ReturnType::Resource(resource) => resource,
                other => panic!("unexpected socket return: {:?}", other),
            },
            ResultRef {
                call_idx: 0,
                result_idx: 0,
            },
        );
        let penalties = HashMap::from([("sendto$inet->bind$inet".to_string(), 1)]);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeed_cafe);

        for _ in 0..16 {
            let choice = choose_syscall_for_generation(
                &descs,
                &choice_table,
                Some(1),
                &available_resources,
                &penalties,
                &mut rng,
            );
            assert_ne!(choice, 2);
        }
    }

    #[test]
    fn weighted_choice_prefers_resource_followup_calls() {
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
        let choice_table = SyscallChoiceTable::build(&descs, &[]);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5151_8282);

        for _ in 0..32 {
            let choice = choice_table.choose_subset(&[1, 2, 3], Some(0), &mut rng);
            assert_ne!(choice, 3);
        }
    }

    #[test]
    fn weighted_choice_uses_dynamic_corpus_bias() {
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
        let choice_table = SyscallChoiceTable::build(&descs, &corpus);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4141_9292);

        for _ in 0..32 {
            let choice = choice_table.choose_subset(&[1, 2], Some(0), &mut rng);
            assert_eq!(choice, 1);
        }
    }

    #[test]
    fn generates_parent_derived_inline_lengths_for_struct_templates() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                payload_words = "syz", "hello"
                type msg[PAYLOAD] {
                    size bytesize[parent, int32]
                    kind const[7, int32]
                    payload PAYLOAD
                } [packed]
                syscall write_msg@1 -> int(fd const[1, int32], data ptr[in, msg[stringnoz[payload_words, 8]]], len len[data, int32])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x0ddc_0ffe);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated data arg: {:?}", other),
            };
            assert_eq!(data.len(), 16);
            assert_eq!(decode_scalar_bytes(&data[..4]), 16);
            assert_eq!(decode_scalar_bytes(&data[4..8]), 7);
            assert_eq!(prog.calls[0].args[2], ArgValue::Const(16));
        }
    }

    #[test]
    fn generates_offsetof_inline_fields_for_structs() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x55aa_0ff5);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated data arg: {:?}", other),
            };
            assert_eq!(data.len(), 8);
            assert_eq!(decode_scalar_bytes(&data[..2]), 8);
            assert_eq!(decode_scalar_bytes(&data[2..4]), 0xaa);
            assert_eq!(prog.calls[0].args[2], ArgValue::Const(8));
        }
    }

    #[test]
    fn generates_named_path_lengths_across_arg_type_and_parent_roots() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x77aa_5511);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated data arg: {:?}", other),
            };
            assert_eq!(data.len(), 14);
            assert_eq!(decode_scalar_bytes(&data[6..10]), 6);
            assert_eq!(decode_scalar_bytes(&data[10..14]), 6);

            let ctx = match &prog.calls[0].args[2] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated ctx arg: {:?}", other),
            };
            assert_eq!(ctx.len(), 24);
            assert_eq!(decode_scalar_bytes(&ctx[16..20]), 16);
            assert_eq!(decode_scalar_bytes(&ctx[20..24]), 14);

            assert_eq!(prog.calls[0].args[3], ArgValue::Const(6));
        }
    }

    #[test]
    fn generates_trailing_byte_arrays_with_inline_sizes() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type blob_msg {
                    count bytesize[data, int32]
                    data array[int8, 4:8]
                } [packed]
                syscall write_blob@1 -> int(fd const[1, int32], data ptr[in, blob_msg], size len[data, int32])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1bad_b002);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated blob arg: {:?}", other),
            };
            assert!((8..=12).contains(&data.len()));
            let payload_len = data.len() - 4;
            assert!((4..=8).contains(&payload_len));
            assert_eq!(decode_scalar_bytes(&data[..4]) as usize, payload_len);
            assert_eq!(prog.calls[0].args[2], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_fixed_element_array_counts_inside_varlen_structs() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x77aa_cc11);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                other => panic!("unexpected generated walk arg: {:?}", other),
            };
            assert!(data.len() >= 10);
            assert_eq!((data.len() - 2) % 8, 0);
            let element_count = (data.len() - 2) / 8;
            assert!((1..=3).contains(&element_count));
            assert_eq!(decode_scalar_bytes(&data[..2]) as usize, element_count);
            assert_eq!(prog.calls[0].args[2], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_inline_pointer_structs_with_matching_lengths() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_1ace);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            match &prog.calls[0].args[1] {
                ArgValue::Composite { data, pointers, .. } => {
                    assert_eq!(data.len(), 16);
                    assert_eq!(pointers.len(), 1);
                    assert_eq!(pointers[0].offset, 0);
                    let payload = match pointers[0].value.as_ref() {
                        ArgValue::Buffer(data) => data,
                        other => panic!("unexpected inline pointer payload: {:?}", other),
                    };
                    assert!((4..=8).contains(&payload.len()));
                    assert_eq!(decode_scalar_bytes(&data[8..16]) as usize, payload.len());
                    assert_eq!(prog.calls[0].args[2], ArgValue::Const(payload.len() as u64));
                }
                other => panic!("unexpected generated iovec arg: {:?}", other),
            }
        }
    }

    #[test]
    fn generates_msghdr_with_nested_iovec_and_optional_lengths() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_baad);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let ArgValue::Composite { data, pointers, .. } = &prog.calls[0].args[1] else {
                panic!(
                    "unexpected generated msghdr arg: {:?}",
                    prog.calls[0].args[1]
                );
            };
            assert_eq!(data.len(), 56);
            assert_eq!(decode_scalar_bytes(&data[48..52]), 0);

            let name_ptr = pointers.iter().find(|pointer| pointer.offset == 0);
            let name_len = decode_scalar_bytes(&data[8..12]) as usize;
            match name_ptr.map(|pointer| pointer.value.as_ref()) {
                Some(ArgValue::Buffer(name)) => {
                    assert_eq!(name.len(), 16);
                    assert_eq!(name_len, 16);
                }
                Some(other) => panic!("unexpected msg_name payload: {:?}", other),
                None => assert_eq!(name_len, 0),
            }

            let iov_ptr = pointers
                .iter()
                .find(|pointer| pointer.offset == 16)
                .expect("msg_iov pointer should always be present");
            let ArgValue::Composite {
                data: iov_data,
                pointers: iov_pointers,
                ..
            } = iov_ptr.value.as_ref()
            else {
                panic!("unexpected msg_iov payload: {:?}", iov_ptr.value);
            };
            let iov_len = decode_scalar_bytes(&data[24..32]) as usize;
            assert!((1..=2).contains(&iov_len));
            assert_eq!(iov_data.len(), iov_len * 16);
            assert_eq!(iov_pointers.len(), iov_len);
            for (idx, pointer) in iov_pointers.iter().enumerate() {
                assert_eq!(pointer.offset, idx * 16);
                let ArgValue::Buffer(payload) = pointer.value.as_ref() else {
                    panic!("unexpected iovec base payload: {:?}", pointer.value);
                };
                assert!((4..=8).contains(&payload.len()));
                let len_offset = idx * 16 + 8;
                assert_eq!(
                    decode_scalar_bytes(&iov_data[len_offset..len_offset + 8]) as usize,
                    payload.len()
                );
            }

            let control_ptr = pointers.iter().find(|pointer| pointer.offset == 32);
            let control_len = decode_scalar_bytes(&data[40..48]) as usize;
            match control_ptr.map(|pointer| pointer.value.as_ref()) {
                Some(ArgValue::Array {
                    data: control,
                    element_sizes,
                    ..
                }) => {
                    assert!((1..=2).contains(&element_sizes.len()));
                    assert_eq!(control_len, control.len());
                    let mut offset = 0usize;
                    for &element_size in element_sizes {
                        assert!(element_size >= 16);
                        assert_eq!(element_size % 8, 0);
                        let end = offset + element_size;
                        let element = &control[offset..end];
                        assert_eq!(decode_scalar_bytes(&element[..8]) as usize, element_size);
                        assert_eq!(decode_scalar_bytes(&element[8..12]), 0);
                        assert_eq!(decode_scalar_bytes(&element[12..16]), 0);
                        offset = end;
                    }
                    assert_eq!(offset, control.len());
                }
                Some(other) => panic!("unexpected msg_control payload: {:?}", other),
                None => assert_eq!(control_len, 0),
            }
        }
    }

    #[test]
    fn generates_sendmmsg_with_batched_msghdrs() {
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
                type send_mmsghdr {
                    msg_hdr send_msghdr
                    msg_len const[0, int32]
                } [size[64]]
                syscall sendmmsg@1 -> int(fd const[1, int32], msgvec ptr[in, array[send_mmsghdr, 1:2]], vlen len[msgvec, int32], flags const[0, int32])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_bad5);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let ArgValue::Composite { data, pointers, .. } = &prog.calls[0].args[1] else {
                panic!(
                    "unexpected generated msgvec arg: {:?}",
                    prog.calls[0].args[1]
                );
            };
            let vlen = match prog.calls[0].args[2] {
                ArgValue::Const(value) => value as usize,
                ref other => panic!("unexpected generated vlen arg: {:?}", other),
            };
            assert!((1..=2).contains(&vlen));
            assert_eq!(data.len(), vlen * 64);

            for element_idx in 0..vlen {
                let base = element_idx * 64;
                let element = &data[base..base + 64];
                assert_eq!(decode_scalar_bytes(&element[56..60]), 0);
                let name_ptr = pointers.iter().find(|pointer| pointer.offset == base);
                let name_len = decode_scalar_bytes(&element[8..12]) as usize;
                match name_ptr.map(|pointer| pointer.value.as_ref()) {
                    Some(ArgValue::Buffer(name)) => {
                        assert_eq!(name.len(), 16);
                        assert_eq!(name_len, 16);
                    }
                    Some(other) => panic!("unexpected batched msg_name payload: {:?}", other),
                    None => assert_eq!(name_len, 0),
                }

                let iov_ptr = pointers
                    .iter()
                    .find(|pointer| pointer.offset == base + 16)
                    .expect("each mmsghdr element should have msg_iov");
                let ArgValue::Composite {
                    data: iov_data,
                    pointers: iov_pointers,
                    ..
                } = iov_ptr.value.as_ref()
                else {
                    panic!("unexpected batched msg_iov payload: {:?}", iov_ptr.value);
                };
                let iov_len = decode_scalar_bytes(&element[24..32]) as usize;
                assert!((1..=2).contains(&iov_len));
                assert_eq!(iov_data.len(), iov_len * 16);
                assert_eq!(iov_pointers.len(), iov_len);
                for (iov_idx, pointer) in iov_pointers.iter().enumerate() {
                    assert_eq!(pointer.offset, iov_idx * 16);
                    let ArgValue::Buffer(payload) = pointer.value.as_ref() else {
                        panic!("unexpected batched iovec payload: {:?}", pointer.value);
                    };
                    let len_offset = iov_idx * 16 + 8;
                    assert_eq!(
                        decode_scalar_bytes(&iov_data[len_offset..len_offset + 8]) as usize,
                        payload.len()
                    );
                }

                let control_ptr = pointers.iter().find(|pointer| pointer.offset == base + 32);
                let control_len = decode_scalar_bytes(&element[40..48]) as usize;
                match control_ptr.map(|pointer| pointer.value.as_ref()) {
                    Some(ArgValue::Array {
                        data: control,
                        element_sizes,
                        ..
                    }) => {
                        assert!((1..=2).contains(&element_sizes.len()));
                        assert_eq!(control.len(), control_len);
                        let mut offset = 0usize;
                        for &element_size in element_sizes {
                            assert!(element_size >= 16);
                            assert_eq!(element_size % 8, 0);
                            let end = offset + element_size;
                            let cmsg = &control[offset..end];
                            assert_eq!(decode_scalar_bytes(&cmsg[..8]) as usize, element_size);
                            offset = end;
                        }
                        assert_eq!(offset, control.len());
                    }
                    Some(other) => panic!("unexpected batched msg_control payload: {:?}", other),
                    None => assert_eq!(control_len, 0),
                }
            }
        }
    }

    #[test]
    fn generates_recv_msghdr_with_reserved_output_buffers() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type iovec_out {
                    base ptr[out, array[int8, 4:8]]
                    len len[base, intptr]
                } [size[16]]
                type recv_msghdr {
                    msg_name ptr[out, buffer[16:16], opt]
                    msg_namelen len[msg_name, int32]
                    msg_iov ptr[in, array[iovec_out, 1:2]]
                    msg_iovlen len[msg_iov, intptr]
                    msg_control ptr[out, array[int8, 0:32], opt]
                    msg_controllen bytesize[msg_control, intptr]
                    msg_flags const[0, int32]
                } [size[56]]
                syscall recvmsg@1 -> int(fd const[1, int32], msg ptr[inout, recv_msghdr], flags const[0, int32])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_feed);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let ArgValue::Composite { data, pointers, .. } = &prog.calls[0].args[1] else {
                panic!(
                    "unexpected generated recv_msghdr arg: {:?}",
                    prog.calls[0].args[1]
                );
            };
            assert_eq!(data.len(), 56);
            assert_eq!(decode_scalar_bytes(&data[48..52]), 0);

            let name_ptr = pointers.iter().find(|pointer| pointer.offset == 0);
            let name_len = decode_scalar_bytes(&data[8..12]) as usize;
            match name_ptr.map(|pointer| pointer.value.as_ref()) {
                Some(ArgValue::Buffer(name)) => {
                    assert_eq!(name.len(), 16);
                    assert_eq!(name_len, 16);
                    assert!(name.iter().all(|byte| *byte == 0));
                }
                Some(other) => panic!("unexpected recv msg_name payload: {:?}", other),
                None => assert_eq!(name_len, 0),
            }

            let iov_ptr = pointers
                .iter()
                .find(|pointer| pointer.offset == 16)
                .expect("recv msg_iov pointer should always be present");
            let ArgValue::Composite {
                data: iov_data,
                pointers: iov_pointers,
                ..
            } = iov_ptr.value.as_ref()
            else {
                panic!("unexpected recv msg_iov payload: {:?}", iov_ptr.value);
            };
            let iov_len = decode_scalar_bytes(&data[24..32]) as usize;
            assert!((1..=2).contains(&iov_len));
            assert_eq!(iov_data.len(), iov_len * 16);
            assert_eq!(iov_pointers.len(), iov_len);
            for (idx, pointer) in iov_pointers.iter().enumerate() {
                let ArgValue::Buffer(payload) = pointer.value.as_ref() else {
                    panic!("unexpected recv iovec base payload: {:?}", pointer.value);
                };
                assert!((4..=8).contains(&payload.len()));
                assert!(payload.iter().all(|byte| *byte == 0));
                let len_offset = idx * 16 + 8;
                assert_eq!(
                    decode_scalar_bytes(&iov_data[len_offset..len_offset + 8]) as usize,
                    payload.len()
                );
            }

            let control_ptr = pointers.iter().find(|pointer| pointer.offset == 32);
            let control_len = decode_scalar_bytes(&data[40..48]) as usize;
            match control_ptr.map(|pointer| pointer.value.as_ref()) {
                Some(ArgValue::Buffer(control)) => {
                    assert!(control.len() <= 32);
                    assert_eq!(control_len, control.len());
                    assert!(control.iter().all(|byte| *byte == 0));
                }
                Some(other) => panic!("unexpected recv msg_control payload: {:?}", other),
                None => assert_eq!(control_len, 0),
            }
        }
    }

    #[test]
    fn generates_aligned_varlen_struct_lengths_from_parent_size() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type cmsghdr_like {
                    cmsg_len len[parent, intptr]
                    cmsg_level int32
                    cmsg_type int32
                    data array[int8, 1:8]
                } [align[8]]
                syscall write_cmsg@1 -> int(fd const[1, int32], data ptr[in, cmsghdr_like], size len[data, intptr])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xc5c5_5eed);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            let data = match &prog.calls[0].args[1] {
                ArgValue::Buffer(data) => data,
                ArgValue::Composite {
                    data,
                    pointers,
                    struct_layouts,
                } => {
                    assert!(pointers.is_empty());
                    assert_eq!(struct_layouts.len(), 1);
                    data
                }
                other => panic!("unexpected generated cmsghdr_like arg: {:?}", other),
            };
            assert!(data.len() >= 24);
            assert_eq!(data.len() % 8, 0);
            assert_eq!(decode_scalar_bytes(&data[..8]) as usize, data.len());
            assert_eq!(prog.calls[0].args[2], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_packed_structs_with_nontrailing_var_fields() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51de_4b11);

        for _ in 0..8 {
            let prog = generate(&descs, &mut rng);
            prog.validate(&descs)
                .expect("generated program with packed mid-var struct should validate");

            let ArgValue::Composite { data, pointers, .. } = &prog.calls[0].args[0] else {
                panic!(
                    "unexpected generated packed_mid arg: {:?}",
                    prog.calls[0].args[0]
                );
            };
            assert!(data.len() >= 20);
            assert_eq!(data.len() % 4, 0);

            let payload_words =
                decode_scalar_bytes(&data[data.len() - 16..data.len() - 8]) as usize;
            let payload_bytes = data.len() - 20;
            assert_eq!(payload_words * 8, payload_bytes);

            let Some(tail_ptr) = pointers
                .iter()
                .find(|pointer| pointer.offset == data.len() - 8)
            else {
                panic!("expected tail pointer at packed suffix");
            };
            let ArgValue::Buffer(tail_data) = tail_ptr.value.as_ref() else {
                panic!("unexpected tail pointer payload: {:?}", tail_ptr.value);
            };
            assert_eq!(tail_data.len(), 4);
            assert_eq!(prog.calls[0].args[1], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_packed_aligned_structs_with_nontrailing_var_fields() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51de_4b18);

        for _ in 0..8 {
            let prog = Program {
                calls: vec![Call {
                    syscall_idx: 0,
                    args: generate_args(&descs[0], &HashMap::new(), &mut rng),
                }],
            };
            if let Err(err) = prog.validate(&descs) {
                panic!(
                    "generated program with packed aligned mid-var struct should validate: {:?}\nprogram: {:?}",
                    err, prog
                );
            }

            let ArgValue::Composite { data, pointers, .. } = &prog.calls[0].args[0] else {
                panic!(
                    "unexpected generated packed_mid_aligned arg: {:?}",
                    prog.calls[0].args[0]
                );
            };
            assert!(data.len() >= 24);
            assert_eq!(data.len() % 8, 0);

            let payload_words =
                decode_scalar_bytes(&data[data.len() - 20..data.len() - 12]) as usize;
            let payload_bytes = data.len() - 24;
            assert_eq!(payload_words * 8, payload_bytes);

            let Some(tail_ptr) = pointers
                .iter()
                .find(|pointer| pointer.offset == data.len() - 12)
            else {
                panic!("expected tail pointer at aligned suffix offset");
            };
            match tail_ptr.value.as_ref() {
                ArgValue::Buffer(buf) => assert_eq!(buf.len(), 4),
                other => panic!("unexpected tail pointer value: {:?}", other),
            }
            assert_eq!(prog.calls[0].args[1], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_packed_structs_with_multiple_variable_fields() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type multi {
                    sep0 const[':', int8]
                    name stringnoz["aa", "bbb"]
                    sep1 const[':', int8]
                    kind stringnoz["x", "yy"]
                    sep2 const[':', int8]
                    payload array[int8, 1:4]
                } [packed]
                syscall use_multi@1 -> int(arg ptr[in, multi], arglen len[arg, intptr])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51de_4b21);

        for _ in 0..8 {
            let prog = Program {
                calls: vec![Call {
                    syscall_idx: 0,
                    args: generate_args(&descs[0], &HashMap::new(), &mut rng),
                }],
            };
            prog.validate(&descs)
                .expect("generated program with multiple variable packed fields should validate");

            let ArgValue::Composite {
                data,
                pointers,
                struct_layouts,
            } = &prog.calls[0].args[0]
            else {
                panic!(
                    "unexpected generated multi arg: {:?}",
                    prog.calls[0].args[0]
                );
            };
            assert!(pointers.is_empty());
            assert_eq!(struct_layouts.len(), 1);
            assert!(data.len() >= 7);

            let ranges = &struct_layouts[0].field_ranges;
            assert_eq!(data[ranges[0].0], b':');
            assert_eq!(data[ranges[2].0], b':');
            assert_eq!(data[ranges[4].0], b':');
            assert!((2..=3).contains(&ranges[1].1.saturating_sub(ranges[1].0)));
            assert!((1..=2).contains(&ranges[3].1.saturating_sub(ranges[3].0)));
            assert!((1..=4).contains(&ranges[5].1.saturating_sub(ranges[5].0)));
            assert_eq!(prog.calls[0].args[1], ArgValue::Const(data.len() as u64));
        }
    }

    #[test]
    fn generates_packed_bitfield_lengths_and_constants() {
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51de_4b31);

        for _ in 0..8 {
            let prog = Program {
                calls: vec![Call {
                    syscall_idx: 0,
                    args: generate_args(&descs[0], &HashMap::new(), &mut rng),
                }],
            };
            prog.validate(&descs)
                .expect("generated program with bitfield-backed header should validate");

            let ArgValue::Buffer(data) = &prog.calls[0].args[0] else {
                panic!(
                    "unexpected generated ipv4_like arg: {:?}",
                    prog.calls[0].args[0]
                );
            };
            assert_eq!(data.len(), 4);
            assert_eq!(data[0], 0x41);
            assert_eq!(prog.calls[0].args[1], ArgValue::Const(4));
        }
    }

    #[test]
    fn generates_big_endian_bitfield_groups() {
        let descs = crate::description::parse_syscall_descs(
            r#"
                type mpls_like {
                    label const[1, int32be:20]
                    tc const[0, int32be:3]
                    s const[1, int32be:1]
                    ttl const[0x12, int32be:8]
                }
                syscall use_mpls_like@1 -> int(arg ptr[in, mpls_like])
            "#,
        )
        .expect("test target should parse");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51de_4b32);

        for _ in 0..8 {
            let prog = Program {
                calls: vec![Call {
                    syscall_idx: 0,
                    args: generate_args(&descs[0], &HashMap::new(), &mut rng),
                }],
            };
            prog.validate(&descs)
                .expect("generated program with big-endian bitfields should validate");

            let ArgValue::Buffer(data) = &prog.calls[0].args[0] else {
                panic!(
                    "unexpected generated mpls_like arg: {:?}",
                    prog.calls[0].args[0]
                );
            };
            assert_eq!(data.as_slice(), &[0x00, 0x00, 0x11, 0x12]);
        }
    }
}
