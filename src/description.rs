use crate::program::{
    ArgType, BufferDir, LengthKind, PtrDir, ResourceDesc, ReturnType, ScalarEndian, SyscallAttrs,
    SyscallDesc,
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

const TARGET_ARCH: &str = "amd64";

pub fn parse_syscall_descs(input: &str) -> Result<Vec<SyscallDesc>, String> {
    let mut state = ParseState::default();
    parse_input(input, "<inline>", None, &mut state, &mut HashSet::new())?;
    Ok(state.descs)
}

pub fn parse_syscall_descs_from_path(path: impl AsRef<Path>) -> Result<Vec<SyscallDesc>, String> {
    let mut state = ParseState::default();
    parse_path(path.as_ref(), &mut state, &mut HashSet::new())?;
    Ok(state.descs)
}

#[derive(Default)]
struct ParseState {
    consts: HashMap<String, u64>,
    const_sets: HashMap<String, ValueSet>,
    flag_sets: HashMap<String, ValueSet>,
    types: HashMap<String, ArgType>,
    resources: HashMap<String, ResourceDesc>,
    descs: Vec<SyscallDesc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueSet {
    size: usize,
    values: Vec<u64>,
}

fn parse_path(
    path: &Path,
    state: &mut ParseState,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), String> {
    let resolved = fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to resolve description path {}: {}",
            path.display(),
            err
        )
    })?;
    if !visited.insert(resolved.clone()) {
        return Ok(());
    }

    let metadata = fs::metadata(&resolved).map_err(|err| {
        format!(
            "failed to stat description path {}: {}",
            resolved.display(),
            err
        )
    })?;
    if metadata.is_dir() {
        let mut entries = fs::read_dir(&resolved)
            .map_err(|err| {
                format!(
                    "failed to read description directory {}: {}",
                    resolved.display(),
                    err
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                format!(
                    "failed to iterate description directory {}: {}",
                    resolved.display(),
                    err
                )
            })?;
        entries.sort_by_key(|entry| path_sort_key(&entry.path()));

        for entry in entries {
            let entry_path = entry.path();
            let file_type = entry.file_type().map_err(|err| {
                format!(
                    "failed to read file type for {}: {}",
                    entry_path.display(),
                    err
                )
            })?;
            if file_type.is_dir()
                || entry_path.extension() == Some(OsStr::new("txt"))
                || entry_path.extension() == Some(OsStr::new("const"))
            {
                parse_path(&entry_path, state, visited)?;
            }
        }
        return Ok(());
    }

    if resolved.extension() == Some(OsStr::new("txt")) {
        if let Some(const_sibling) = sibling_const_path(&resolved) {
            if const_sibling.exists() {
                parse_path(&const_sibling, state, visited)?;
            }
        }
    }

    let input = fs::read_to_string(&resolved).map_err(|err| {
        format!(
            "failed to read description file {}: {}",
            resolved.display(),
            err
        )
    })?;
    if resolved.extension() == Some(OsStr::new("const")) {
        parse_const_file(&input, &resolved.display().to_string(), &mut state.consts)
    } else {
        parse_input(
            &input,
            &resolved.display().to_string(),
            resolved.parent(),
            state,
            visited,
        )
    }
}

fn parse_input(
    input: &str,
    source: &str,
    base_dir: Option<&Path>,
    state: &mut ParseState,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), String> {
    let lines = input.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut pending_syscalls = Vec::new();
    while index < lines.len() {
        let line_no = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include ") {
            if is_header_include(rest) {
                continue;
            }
            let include_path = parse_include_path(line_no, rest)?;
            let include_path = if include_path.is_absolute() {
                include_path
            } else if let Some(base_dir) = base_dir {
                base_dir.join(include_path)
            } else {
                return Err(format!(
                    "{}: line {}: relative include requires file-based parsing",
                    source, line_no
                ));
            };
            parse_path(&include_path, state, visited)
                .map_err(|err| format!("{}: line {}: {}", source, line_no, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("const ") {
            parse_const(line_no, rest, &mut state.consts)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("constset ") {
            parse_value_set(line_no, rest, &state.consts, &mut state.const_sets)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("flagset ") {
            parse_value_set(line_no, rest, &state.consts, &mut state.flag_sets)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if line.starts_with("define ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("type ") {
            let known_types = state.types.clone();
            parse_type_alias(
                line_no,
                rest,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &known_types,
                &state.resources,
                &mut state.types,
            )
            .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("resource ") {
            parse_resource(line_no, rest, &state.consts, &mut state.resources)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if line.ends_with('{') {
            let known_types = state.types.clone();
            parse_struct_block(
                line_no,
                line,
                &lines,
                &mut index,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &known_types,
                &state.resources,
                &mut state.types,
            )
            .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("syscall ") {
            pending_syscalls.push((line_no, rest.to_string()));
            continue;
        }
        if looks_like_bare_syscall(line) {
            pending_syscalls.push((line_no, line.to_string()));
            continue;
        }
        if line.contains('=') {
            parse_implicit_value_set(
                line_no,
                line,
                &state.consts,
                &mut state.const_sets,
                &mut state.flag_sets,
            )
            .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }

        return Err(format!(
            "{}: line {}: unsupported statement: {}",
            source, line_no, line
        ));
    }

    for (line_no, syscall) in pending_syscalls {
        state.descs.push(
            parse_syscall(
                line_no,
                &syscall,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.types,
                &state.resources,
            )
            .map_err(|err| format!("{}: {}", source, err))?,
        );
    }

    Ok(())
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn path_sort_key(path: &Path) -> (String, u8, String) {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let (normalized, priority) = if file_name.ends_with(".txt.const") {
        (file_name.trim_end_matches(".const").to_string(), 0u8)
    } else if file_name.ends_with(".txt") {
        (file_name.to_string(), 1u8)
    } else if path.extension() == Some(OsStr::new("const")) {
        (file_name.to_string(), 2u8)
    } else if path.is_dir() {
        (file_name.to_string(), 3u8)
    } else {
        (file_name.to_string(), 4u8)
    };
    (normalized, priority, path.display().to_string())
}

fn sibling_const_path(path: &Path) -> Option<PathBuf> {
    if path.extension() != Some(OsStr::new("txt")) {
        return None;
    }
    let file_name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!("{}.const", file_name)))
}

fn parse_const_file(
    input: &str,
    source: &str,
    consts: &mut HashMap<String, u64>,
) -> Result<(), String> {
    for (line_no, raw_line) in input.lines().enumerate() {
        let line_no = line_no + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("arches =") {
            continue;
        }

        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{}: line {}: expected NAME = VALUE", source, line_no))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(format!(
                "{}: line {}: constant name is empty",
                source, line_no
            ));
        }

        let (value_expr, arch_filter) = match value.split_once(',') {
            Some((value_expr, arch_filter)) => (value_expr.trim(), Some(arch_filter.trim())),
            None => (value.trim(), None),
        };
        if let Some(arch_filter) = arch_filter {
            if !arch_filter_allows_target(arch_filter, TARGET_ARCH) {
                continue;
            }
        }

        let parsed = parse_expr(value_expr, consts, line_no)
            .map_err(|err| format!("{}: {}", source, err))?;
        consts.insert(name.to_string(), parsed);
    }
    Ok(())
}

fn arch_filter_allows_target(filter: &str, target_arch: &str) -> bool {
    filter
        .split(':')
        .map(str::trim)
        .any(|arch| !arch.is_empty() && arch == target_arch)
}

fn parse_include_path(line_no: usize, rest: &str) -> Result<PathBuf, String> {
    let path = rest.trim();
    if path.is_empty() {
        return Err(format!("line {}: include path is empty", line_no));
    }
    let path = path
        .strip_prefix('"')
        .and_then(|path| path.strip_suffix('"'))
        .unwrap_or(path);
    if path.is_empty() {
        return Err(format!("line {}: include path is empty", line_no));
    }
    Ok(PathBuf::from(path))
}

fn is_header_include(rest: &str) -> bool {
    let path = rest.trim().trim_matches('"');
    path.starts_with('<') && path.ends_with('>')
}

fn looks_like_bare_syscall(line: &str) -> bool {
    let Some(open) = line.find('(') else {
        return false;
    };
    let head = line[..open].trim();
    if head.is_empty() || head.contains(char::is_whitespace) {
        return false;
    }
    head.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
}

fn parse_const(
    line_no: usize,
    rest: &str,
    consts: &mut HashMap<String, u64>,
) -> Result<(), String> {
    let (name, expr) = rest
        .split_once('=')
        .ok_or_else(|| format!("line {}: expected const NAME = VALUE", line_no))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("line {}: constant name is empty", line_no));
    }
    let value = parse_expr(expr.trim(), consts, line_no)?;
    consts.insert(name.to_string(), value);
    Ok(())
}

fn parse_resource(
    line_no: usize,
    rest: &str,
    consts: &HashMap<String, u64>,
    resources: &mut HashMap<String, ResourceDesc>,
) -> Result<(), String> {
    let (left, right) = match rest.split_once('=') {
        Some((left, right)) => (left, Some(right.trim())),
        None => (rest, None),
    };
    let left = left.trim();
    let open = left
        .find('[')
        .ok_or_else(|| format!("line {}: resource is missing '['", line_no))?;
    let close = left
        .rfind(']')
        .ok_or_else(|| format!("line {}: resource is missing ']'", line_no))?;
    if close < open {
        return Err(format!("line {}: malformed resource declaration", line_no));
    }
    let kind = left[..open].trim();
    if kind.is_empty() {
        return Err(format!("line {}: resource kind is empty", line_no));
    }
    let base = left[open + 1..close].trim();
    let (size, lineage) = match resources.get(base) {
        Some(parent) => {
            let mut lineage = parent.lineage.clone();
            lineage.push(kind.to_string());
            (parent.size, lineage)
        }
        None => {
            let size = parse_integer(base, line_no)? as usize;
            (size, vec![kind.to_string()])
        }
    };
    let values = match right {
        Some(right) => split_top_level(right, ',')
            .into_iter()
            .map(|value| parse_expr(value.trim(), consts, line_no))
            .collect::<Result<Vec<_>, _>>()?,
        None => resources
            .get(base)
            .map(|resource| resource.values.clone())
            .unwrap_or_default(),
    };
    resources.insert(
        kind.to_string(),
        ResourceDesc {
            kind: kind.to_string(),
            size,
            values,
            lineage,
        },
    );
    Ok(())
}

fn parse_implicit_value_set(
    line_no: usize,
    line: &str,
    consts: &HashMap<String, u64>,
    const_sets: &mut HashMap<String, ValueSet>,
    flag_sets: &mut HashMap<String, ValueSet>,
) -> Result<(), String> {
    let (name, values) = line
        .split_once('=')
        .ok_or_else(|| format!("line {}: expected NAME = VALUE", line_no))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("line {}: value set name is empty", line_no));
    }
    let values = split_top_level(values.trim(), ',')
        .into_iter()
        .map(|value| parse_expr(value.trim(), consts, line_no))
        .collect::<Result<Vec<_>, _>>()?;
    let set = ValueSet { size: 4, values };
    const_sets.insert(name.to_string(), set.clone());
    flag_sets.insert(name.to_string(), set);
    Ok(())
}

fn parse_type_alias(
    line_no: usize,
    rest: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
) -> Result<(), String> {
    let arg_names = HashMap::new();
    let (name, type_text) = rest
        .split_once(char::is_whitespace)
        .ok_or_else(|| format!("line {}: type declaration is missing a body", line_no))?;
    let name = name.trim();
    let type_text = type_text.trim();
    if name.is_empty() || type_text.is_empty() {
        return Err(format!("line {}: malformed type declaration", line_no));
    }
    if let Ok(arg_type) = parse_arg(
        type_text, consts, const_sets, flag_sets, &arg_names, types, resources, line_no,
    ) {
        out_types.insert(name.to_string(), arg_type);
    }
    Ok(())
}

fn parse_struct_block(
    line_no: usize,
    header: &str,
    lines: &[&str],
    index: &mut usize,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
) -> Result<(), String> {
    let arg_names = HashMap::new();
    let name = header.strip_suffix('{').unwrap_or(header).trim();
    if name.is_empty() {
        return Err(format!("line {}: struct name is empty", line_no));
    }

    let mut fields = Vec::new();
    let mut declared_size = None;
    while *index < lines.len() {
        let field_line_no = *index + 1;
        let line = strip_comment(lines[*index]).trim();
        *index += 1;
        if line.is_empty() {
            continue;
        }
        if let Some(attrs) = line.strip_prefix('}') {
            declared_size = parse_struct_attrs(attrs, consts, field_line_no)?;
            break;
        }
        let mut parts = line.split_whitespace();
        let _field_name = parts
            .next()
            .ok_or_else(|| format!("line {}: struct field is empty", field_line_no))?;
        let type_text = parts.collect::<Vec<_>>().join(" ");
        if type_text.is_empty() {
            return Err(format!(
                "line {}: struct field is missing a type",
                field_line_no
            ));
        }
        let arg_type = parse_arg(
            &type_text,
            consts,
            const_sets,
            flag_sets,
            &arg_names,
            types,
            resources,
            field_line_no,
        )?;
        fields.push(arg_type);
    }
    if fields.is_empty() {
        return Err(format!("line {}: struct '{}' has no fields", line_no, name));
    }

    let field_size = fields.iter().try_fold(0usize, |acc, field| {
        let size = crate::program::arg_type_fixed_size(field).ok_or_else(|| {
            format!(
                "line {}: struct '{}' fields must be fixed-size",
                line_no, name
            )
        })?;
        acc.checked_add(size)
            .ok_or_else(|| format!("line {}: struct '{}' size overflow", line_no, name))
    })?;
    let size = declared_size.unwrap_or(field_size);
    if size < field_size {
        return Err(format!(
            "line {}: struct '{}' declared size {} is smaller than field size {}",
            line_no, name, size, field_size
        ));
    }

    out_types.insert(name.to_string(), ArgType::Struct { fields, size });
    Ok(())
}

fn parse_struct_attrs(
    text: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<Option<usize>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let mut groups = Vec::new();
    let mut depth = 0usize;
    let mut start = None;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '[' => {
                if depth == 0 {
                    start = Some(idx + 1);
                }
                depth += 1;
            }
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(start) = start.take() {
                        groups.push(trimmed[start..idx].trim());
                    }
                }
            }
            _ => {}
        }
    }
    if groups.is_empty() {
        groups.push(trimmed);
    }

    let mut size = None;
    for group in groups {
        for attr in split_top_level(group, ',') {
            let attr = attr.trim();
            let Some(inner) = bracketed(attr, "size") else {
                continue;
            };
            size = Some(parse_expr(inner.trim(), consts, line_no)? as usize);
        }
    }
    Ok(size)
}

fn parse_value_set(
    line_no: usize,
    rest: &str,
    consts: &HashMap<String, u64>,
    sets: &mut HashMap<String, ValueSet>,
) -> Result<(), String> {
    let (left, right) = rest
        .split_once('=')
        .ok_or_else(|| format!("line {}: expected NAME[SIZE] = VALUE", line_no))?;
    let left = left.trim();
    let open = left
        .find('[')
        .ok_or_else(|| format!("line {}: value set is missing '['", line_no))?;
    let close = left
        .rfind(']')
        .ok_or_else(|| format!("line {}: value set is missing ']'", line_no))?;
    if close < open {
        return Err(format!("line {}: malformed value set declaration", line_no));
    }

    let name = left[..open].trim();
    if name.is_empty() {
        return Err(format!("line {}: value set name is empty", line_no));
    }
    let size = parse_integer(left[open + 1..close].trim(), line_no)? as usize;
    let values = split_top_level(right.trim(), ',')
        .into_iter()
        .map(|value| parse_expr(value.trim(), consts, line_no))
        .collect::<Result<Vec<_>, _>>()?;
    sets.insert(name.to_string(), ValueSet { size, values });
    Ok(())
}

fn parse_syscall(
    line_no: usize,
    rest: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
) -> Result<SyscallDesc, String> {
    if let Some((left, right)) = rest.split_once("->") {
        let (name, id) = parse_name_and_id_or_lookup(line_no, left.trim())?;
        let open = right
            .find('(')
            .ok_or_else(|| format!("line {}: syscall is missing argument list", line_no))?;
        let close = find_matching_paren(right, open)
            .ok_or_else(|| format!("line {}: syscall is missing closing ')'", line_no))?;
        if close < open {
            return Err(format!("line {}: malformed argument list", line_no));
        }

        let ret = parse_return_type(right[..open].trim(), resources, line_no)?;
        let args = parse_syscall_args(
            &right[open + 1..close],
            consts,
            const_sets,
            flag_sets,
            types,
            resources,
            line_no,
        )?;
        let attrs = parse_syscall_attrs(right[close + 1..].trim(), line_no)?;
        return Ok(SyscallDesc {
            name: name.to_string(),
            id,
            args,
            ret,
            attrs,
        });
    }

    let open = rest
        .find('(')
        .ok_or_else(|| format!("line {}: syscall is missing argument list", line_no))?;
    let close = find_matching_paren(rest, open)
        .ok_or_else(|| format!("line {}: syscall is missing closing ')'", line_no))?;
    let (name, id) = parse_name_and_id_or_lookup(line_no, rest[..open].trim())?;
    let args = parse_syscall_args(
        &rest[open + 1..close],
        consts,
        const_sets,
        flag_sets,
        types,
        resources,
        line_no,
    )?;

    let mut tail = rest[close + 1..].trim();
    let ret = if tail.is_empty() {
        ReturnType::Int
    } else {
        if tail.starts_with('(') {
            ReturnType::Int
        } else {
            let ret_end = tail.find('(').unwrap_or(tail.len());
            let ret_name = tail[..ret_end].trim();
            tail = tail[ret_end..].trim();
            if ret_name.is_empty() {
                ReturnType::Int
            } else {
                parse_return_type(ret_name, resources, line_no)?
            }
        }
    };
    let attrs = parse_syscall_attrs(tail, line_no)?;

    Ok(SyscallDesc {
        name: name.to_string(),
        id,
        args,
        ret,
        attrs,
    })
}

fn parse_syscall_attrs(mut tail: &str, line_no: usize) -> Result<SyscallAttrs, String> {
    let mut attrs = SyscallAttrs::default();
    while !tail.is_empty() {
        if !tail.starts_with('(') {
            return Err(format!(
                "line {}: unsupported syscall suffix '{}'",
                line_no, tail
            ));
        }
        let close = find_matching_paren(tail, 0)
            .ok_or_else(|| format!("line {}: malformed syscall attributes", line_no))?;
        let inner = tail[1..close].trim();
        for attr in split_top_level(inner, ',') {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            match attr {
                "automatic_helper" => attrs.automatic_helper = true,
                "no_generate" => attrs.no_generate = true,
                "disabled" => attrs.disabled = true,
                other => {
                    return Err(format!(
                        "line {}: unsupported syscall attribute '{}'",
                        line_no, other
                    ))
                }
            }
        }
        tail = tail[close + 1..].trim();
    }
    Ok(attrs)
}

fn parse_name_and_id_or_lookup(line_no: usize, text: &str) -> Result<(&str, u64), String> {
    if let Some((name, id)) = text.rsplit_once('@') {
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("line {}: syscall name is empty", line_no));
        }
        let id = parse_integer(id.trim(), line_no)?;
        return Ok((name, id));
    }
    if !is_valid_syscall_name(text) {
        return Err(format!(
            "line {}: syscall must use NAME@ID syntax or a known bare syscall name",
            line_no
        ));
    }
    let lookup_name = text.split('$').next().unwrap_or(text);
    let Some(id) = builtin_linux_amd64_syscall_id(lookup_name) else {
        return Err(format!(
            "line {}: unknown bare syscall '{}' for linux/amd64 ID lookup",
            line_no, text
        ));
    };
    Ok((text, id))
}

fn is_valid_syscall_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}

fn builtin_linux_amd64_syscall_id(name: &str) -> Option<u64> {
    Some(match name {
        "openat" => 4304,
        "accept" => 0,
        "accept4" => 11,
        "bind" => 90,
        "close" => 248,
        "connect" => 256,
        "getpeername" => 526,
        "read" => 5186,
        "getsockname" => 563,
        "getsockopt" => 577,
        "recvfrom" => 5511,
        "recvmmsg" => 5527,
        "recvmsg" => 5530,
        "sendmmsg" => 5673,
        "sendmsg" => 5682,
        "sendto" => 6688,
        "setsockopt" => 6751,
        "shutdown" => 7173,
        "write" => 7616,
        "pipe2" => 4854,
        "dup3" => 301,
        "socket" => 7181,
        "socketpair" => 7261,
        "listen" => 4062,
        "eventfd2" => 322,
        "mmap" => 4170,
        "munmap" => 4287,
        "mprotect" => 4243,
        "mkdirat" => 4152,
        "unlinkat" => 7588,
        "fstat" => 484,
        "getcwd" => 509,
        "getpid" => 543,
        "getuid" => 862,
        "ioctl" => 960,
        _ => return None,
    })
}

fn parse_return_type(
    text: &str,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<ReturnType, String> {
    match text {
        "void" => Ok(ReturnType::None),
        "int" => Ok(ReturnType::Int),
        _ => resources
            .get(text)
            .cloned()
            .map(ReturnType::Resource)
            .ok_or_else(|| format!("line {}: unsupported return type '{}'", line_no, text)),
    }
}

fn parse_arg(
    text: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<ArgType, String> {
    let text = text.trim();
    if let Some(resource) = resources.get(text) {
        return Ok(ArgType::Resource(resource.clone()));
    }
    if let Some(arg_type) = types.get(text) {
        return Ok(arg_type.clone());
    }
    if let Some((size, endian)) = scalar_integer_spec(text) {
        return Ok(ArgType::Const {
            size,
            values: Vec::new(),
            range: None,
            endian,
        });
    }
    if let Some(arg_type) = parse_scalar_range_arg(text, consts, line_no)? {
        return Ok(arg_type);
    }
    if text == "filename" {
        return Ok(ArgType::Filename);
    }
    if let Some(inner) = bracketed(text, "const") {
        return parse_const_arg(inner, consts, const_sets, "const", line_no);
    }
    if let Some(inner) = bracketed(text, "flags") {
        return parse_const_arg(inner, consts, flag_sets, "flags", line_no);
    }
    if let Some(inner) = bracketed(text, "buffer") {
        return parse_buffer(inner, line_no);
    }
    if let Some(inner) = bracketed(text, "array") {
        return parse_array(
            inner, consts, const_sets, flag_sets, arg_names, types, resources, line_no,
        );
    }
    if let Some(inner) = bracketed(text, "ptr") {
        return parse_ptr(
            inner, consts, const_sets, flag_sets, arg_names, types, resources, line_no,
        );
    }
    if let Some(inner) = bracketed(text, "len") {
        return parse_len(inner, arg_names, line_no, LengthKind::Auto);
    }
    if let Some(inner) = bracketed(text, "bytesize") {
        return parse_len(inner, arg_names, line_no, LengthKind::Bytes);
    }
    if let Some(type_text) = strip_named_arg_prefix(text) {
        return parse_arg(
            type_text, consts, const_sets, flag_sets, arg_names, types, resources, line_no,
        );
    }

    Err(format!("line {}: unsupported argument '{}'", line_no, text))
}

fn parse_const_arg(
    inner: &str,
    consts: &HashMap<String, u64>,
    sets: &HashMap<String, ValueSet>,
    arg_kind: &str,
    line_no: usize,
) -> Result<ArgType, String> {
    let parts = split_top_level(inner, ';');
    if parts.len() == 2 {
        let left = parts[0].trim();
        let right = parts[1].trim();
        let size = parse_integer(left, line_no)? as usize;
        let values = split_top_level(right, ',')
            .into_iter()
            .map(|value| parse_expr(value.trim(), consts, line_no))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(ArgType::Const {
            size,
            values,
            range: None,
            endian: ScalarEndian::Native,
        });
    }
    if parts.len() > 2 {
        return Err(format!(
            "line {}: {} must use [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax",
            line_no, arg_kind
        ));
    }

    let parts = split_type_parts(inner);
    match parts.as_slice() {
        [single] => {
            let single = single.trim();
            if let Some(set) = sets.get(single) {
                return Ok(ArgType::Const {
                    size: set.size,
                    values: set.values.clone(),
                    range: None,
                    endian: ScalarEndian::Native,
                });
            }
            match parse_expr(single, consts, line_no) {
                Ok(value) => Ok(ArgType::Const {
                    size: 8,
                    values: vec![value],
                    range: None,
                    endian: ScalarEndian::Native,
                }),
                Err(_) => Err(format!(
                    "line {}: unknown {} set '{}' (expected [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax)",
                    line_no, arg_kind, single
                )),
            }
        }
        [left, right] => {
            let left = left.trim();
            let right = right.trim();
            let Some((size, endian)) = scalar_integer_spec(right) else {
                return Err(format!(
                    "line {}: {} must use [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax",
                    line_no, arg_kind
                ));
            };
            if let Some(set) = sets.get(left) {
                return Ok(ArgType::Const {
                    size,
                    values: set.values.clone(),
                    range: None,
                    endian,
                });
            }
            match parse_expr(left, consts, line_no) {
                Ok(value) => Ok(ArgType::Const {
                    size,
                    values: vec![value],
                    range: None,
                    endian,
                }),
                Err(_) => Err(format!(
                    "line {}: unknown {} set '{}' (expected [value, intN] or [set_name, intN] syntax)",
                    line_no, arg_kind, left
                )),
            }
        }
        _ => Err(format!(
            "line {}: {} must use [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax",
            line_no, arg_kind
        )),
    }
}

fn parse_buffer(inner: &str, line_no: usize) -> Result<ArgType, String> {
    if let Some((min, max)) = inner.split_once(':') {
        let min_size = parse_integer(min.trim(), line_no)? as usize;
        let max_size = parse_integer(max.trim(), line_no)? as usize;
        return Ok(ArgType::Buffer {
            min_size,
            max_size,
            dir: BufferDir::Plain,
        });
    }

    let dir = match inner.trim() {
        "in" => BufferDir::In,
        "out" => BufferDir::Out,
        "inout" => BufferDir::InOut,
        other => {
            return Err(format!(
                "line {}: buffer must use [min:max] or [in|out|inout] syntax, got '{}'",
                line_no, other
            ))
        }
    };
    Ok(ArgType::Buffer {
        min_size: 1,
        max_size: 256,
        dir,
    })
}

fn parse_array(
    inner: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if parts.len() != 2 {
        return Err(format!(
            "line {}: array must use [inner; len] or [inner, len] syntax",
            line_no
        ));
    }
    let inner = parse_arg(
        parts[0].trim(),
        consts,
        const_sets,
        flag_sets,
        arg_names,
        types,
        resources,
        line_no,
    )?;
    let len = parse_integer(parts[1].trim(), line_no)? as usize;
    Ok(ArgType::Array {
        inner: Box::new(inner),
        len,
    })
}

fn parse_ptr(
    inner: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if !(2..=3).contains(&parts.len()) {
        return Err(format!(
            "line {}: ptr must use [dir; inner] or [dir, inner, opt] syntax",
            line_no
        ));
    }
    let dir = match parts[0].trim() {
        "in" => PtrDir::In,
        "out" => PtrDir::Out,
        "inout" => PtrDir::InOut,
        other => {
            return Err(format!(
                "line {}: unsupported pointer direction '{}'",
                line_no, other
            ))
        }
    };
    let inner = parse_arg(
        parts[1].trim(),
        consts,
        const_sets,
        flag_sets,
        arg_names,
        types,
        resources,
        line_no,
    )?;
    let optional = match parts.get(2).map(|part| part.trim()) {
        None => false,
        Some("opt") => true,
        Some(other) => {
            return Err(format!(
                "line {}: unsupported pointer attribute '{}'",
                line_no, other
            ))
        }
    };
    Ok(ArgType::Ptr {
        inner: Box::new(inner),
        dir,
        optional,
    })
}

fn parse_len(
    inner: &str,
    arg_names: &HashMap<String, usize>,
    line_no: usize,
    kind: LengthKind,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!(
            "line {}: len must use [target] or [target, intN] syntax",
            line_no
        ));
    }
    let target_name = parts[0].trim();
    if target_name.is_empty() {
        return Err(format!("line {}: len target is empty", line_no));
    }
    let Some(&target) = arg_names.get(target_name) else {
        return Err(format!(
            "line {}: unknown len target '{}' (only earlier named arguments are supported)",
            line_no, target_name
        ));
    };
    let size = match parts.get(1).map(|part| part.trim()) {
        None | Some("") => 8,
        Some(type_name) => scalar_integer_spec(type_name).map(|(size, _)| size).ok_or_else(|| {
            format!(
                "line {}: unsupported len scalar type '{}' (expected int8/int16/int32/int64/intptr)",
                line_no, type_name
            )
        })?,
    };
    Ok(ArgType::Len { target, size, kind })
}

fn parse_expr(text: &str, consts: &HashMap<String, u64>, line_no: usize) -> Result<u64, String> {
    let parts = split_top_level(text, '|');
    let mut value = 0u64;
    for part in parts {
        value |= parse_atom(part.trim(), consts, line_no)?;
    }
    Ok(value)
}

fn parse_atom(text: &str, consts: &HashMap<String, u64>, line_no: usize) -> Result<u64, String> {
    if let Some(value) = consts.get(text) {
        return Ok(*value);
    }
    parse_integer(text, line_no)
}

fn parse_integer(text: &str, line_no: usize) -> Result<u64, String> {
    let normalized = text.replace('_', "");
    if normalized.is_empty() {
        return Err(format!("line {}: expected integer literal", line_no));
    }

    if let Some(rest) = normalized.strip_prefix('-') {
        let positive = parse_unsigned(rest, line_no)?;
        let signed = -(positive as i128);
        return Ok(signed as u64);
    }

    parse_unsigned(&normalized, line_no)
}

fn parse_unsigned(text: &str, line_no: usize) -> Result<u64, String> {
    if let Some(rest) = text.strip_prefix("0x") {
        return u64::from_str_radix(rest, 16)
            .map_err(|_| format!("line {}: invalid hex literal '{}'", line_no, text));
    }
    if let Some(rest) = text.strip_prefix("0o") {
        return u64::from_str_radix(rest, 8)
            .map_err(|_| format!("line {}: invalid octal literal '{}'", line_no, text));
    }
    text.parse::<u64>()
        .map_err(|_| format!("line {}: invalid integer literal '{}'", line_no, text))
}

fn scalar_integer_spec(text: &str) -> Option<(usize, ScalarEndian)> {
    match text {
        "int8" => Some((1, ScalarEndian::Native)),
        "int16" => Some((2, ScalarEndian::Native)),
        "int32" => Some((4, ScalarEndian::Native)),
        "int64" | "intptr" => Some((8, ScalarEndian::Native)),
        "int16be" => Some((2, ScalarEndian::Big)),
        "int32be" => Some((4, ScalarEndian::Big)),
        "int64be" => Some((8, ScalarEndian::Big)),
        _ => None,
    }
}

fn parse_scalar_range_arg(
    text: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<Option<ArgType>, String> {
    let Some(open) = text.find('[') else {
        return Ok(None);
    };
    if !text.ends_with(']') {
        return Ok(None);
    }
    let scalar_name = text[..open].trim();
    let Some((size, endian)) = scalar_integer_spec(scalar_name) else {
        return Ok(None);
    };
    let inner = &text[open + 1..text.len() - 1];
    let (min, max) = inner
        .split_once(':')
        .ok_or_else(|| format!("line {}: scalar range must use [min:max] syntax", line_no))?;
    let min = parse_expr(min.trim(), consts, line_no)?;
    let max = parse_expr(max.trim(), consts, line_no)?;
    Ok(Some(ArgType::Const {
        size,
        values: Vec::new(),
        range: Some((min, max)),
        endian,
    }))
}

fn bracketed<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(prefix)?;
    let rest = rest.strip_prefix('[')?;
    rest.strip_suffix(']')
}

fn parse_syscall_args(
    args_str: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    types: &HashMap<String, ArgType>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<Vec<ArgType>, String> {
    if args_str.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut arg_names = HashMap::new();
    let mut args = Vec::new();
    for raw_arg in split_top_level(args_str, ',') {
        let (arg_name, arg_text) = split_named_arg(raw_arg);
        let arg_type = parse_arg(
            arg_text, consts, const_sets, flag_sets, &arg_names, types, resources, line_no,
        )?;
        if let Some(name) = arg_name {
            arg_names.insert(name, args.len());
        }
        args.push(arg_type);
    }
    Ok(args)
}

fn find_matching_paren(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < open_idx) {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_type_parts(text: &str) -> Vec<&str> {
    let semi = split_top_level(text, ';');
    if semi.len() == 2 {
        return semi;
    }
    split_top_level(text, ',')
}

fn strip_named_arg_prefix(text: &str) -> Option<&str> {
    let mut saw_ident = false;

    for (idx, ch) in text.char_indices() {
        match ch {
            '[' | '(' => return None,
            ']' | ')' => return None,
            c if c.is_whitespace() => {
                let rest = text[idx..].trim();
                return if saw_ident && !rest.is_empty() {
                    Some(rest)
                } else {
                    None
                };
            }
            '_' | '$' => saw_ident = true,
            c if c.is_ascii_alphanumeric() => saw_ident = true,
            _ => return None,
        }
    }
    None
}

fn split_named_arg(text: &str) -> (Option<String>, &str) {
    let trimmed = text.trim();
    if let Some(rest) = strip_named_arg_prefix(trimmed) {
        let name_len = trimmed.len() - rest.len();
        let name = trimmed[..name_len].trim();
        if !name.is_empty() {
            return (Some(name.to_string()), rest);
        }
    }
    (None, trimmed)
}

fn split_top_level(text: &str, delim: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;

    for (idx, ch) in text.char_indices() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if ch == delim && depth == 0 {
            parts.push(text[start..idx].trim());
            start = idx + ch.len_utf8();
        }
    }

    parts.push(text[start..].trim());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_description_dir(label: &str) -> PathBuf {
        let unique = format!(
            "syzkaller-rust-{}-{}-{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_builtin_linux_target() {
        let descs = parse_syscall_descs(crate::program::BUILTIN_LINUX_AMD64_DESCRIPTIONS).unwrap();
        assert_eq!(descs.len(), 20);
        assert_eq!(descs[0].name, "openat");
        assert_eq!(descs[0].id, 4304);
        assert_eq!(descs[17].name, "getpid");
    }

    #[test]
    fn parses_negative_and_bitwise_constants() {
        let input = r#"
            resource fd[4] = -1, 0, 1
            const AT_FDCWD = -100
            const O_CREAT = 0o100
            const O_RDWR = 2
            syscall openat@1 -> fd(const[8; AT_FDCWD], flags[4; O_CREAT|O_RDWR])
        "#;
        let descs = parse_syscall_descs(input).unwrap();
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values[0], (-100i64) as u64),
            other => panic!("unexpected arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::Const { values, .. } => assert_eq!(values[0], 0o100 | 2),
            other => panic!("unexpected arg: {:?}", other),
        }
    }

    #[test]
    fn parses_named_const_and_flag_sets() {
        let input = r#"
            resource fd[4] = -1, 0, 1
            const O_RDONLY = 0
            const O_WRONLY = 1
            const O_RDWR = 2
            const O_CREAT = 0o100
            flagset open_flags[4] = O_RDONLY, O_WRONLY, O_CREAT|O_RDWR
            constset open_modes[4] = 0o644, 0o666
            syscall openat@1 -> fd(filename, flags[open_flags], const[open_modes])
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].args[1] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert_eq!(values, &vec![0, 1, 0o100 | 2]);
            }
            other => panic!("unexpected flags arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert_eq!(values, &vec![0o644, 0o666]);
            }
            other => panic!("unexpected const arg: {:?}", other),
        }
    }

    #[test]
    fn parses_scalar_integer_arg_types() {
        let input = r#"
            resource sock[4] = -1, 0
            syscall listen@2 -> int(sock, int32, intptr)
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].args[1] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert!(values.is_empty());
            }
            other => panic!("unexpected int32 arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 8);
                assert!(values.is_empty());
            }
            other => panic!("unexpected intptr arg: {:?}", other),
        }
    }

    #[test]
    fn parses_named_args_and_default_int_return() {
        let input = r#"
            resource sock[4] = -1, 0
            flagset socket_families[4] = 1, 2
            flagset socket_types[4] = 1, 2
            syscall socket@1(domain flags[socket_families], type flags[socket_types], proto int32) sock (automatic_helper)
            syscall listen@2(fd sock, backlog int32)
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].ret {
            ReturnType::Resource(resource) => assert_eq!(resource.kind, "sock"),
            other => panic!("unexpected socket return type: {:?}", other),
        }
        assert!(descs[0].attrs.automatic_helper);
        match &descs[0].args[2] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert!(values.is_empty());
            }
            other => panic!("unexpected proto arg: {:?}", other),
        }
        assert_eq!(descs[1].ret, ReturnType::Int);
        match &descs[1].args[0] {
            ArgType::Resource(resource) => assert_eq!(resource.kind, "sock"),
            other => panic!("unexpected listen fd arg: {:?}", other),
        }
    }

    #[test]
    fn parses_syscall_generation_attrs() {
        let input = r#"
            resource fd[4] = -1, 0
            syscall eventfd2@1 -> fd(const[4; 0], const[4; 0]) (automatic_helper, no_generate)
            close(fd fd) (disabled)
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        assert!(descs[0].attrs.automatic_helper);
        assert!(descs[0].attrs.no_generate);
        assert!(!descs[0].attrs.disabled);
        assert!(descs[1].attrs.disabled);
        assert!(!descs[1].attrs.no_generate);
    }

    #[test]
    fn parses_comma_style_ptr_and_array_types() {
        let input = r#"
            resource fd[4] = -1, 0
            syscall pipe2@1 -> int(ptr[out, array[fd, 2]], int32)
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Array { inner, len } => {
                        assert_eq!(*len, 2);
                        match inner.as_ref() {
                            ArgType::Resource(resource) => assert_eq!(resource.kind, "fd"),
                            other => panic!("unexpected array inner type: {:?}", other),
                        }
                    }
                    other => panic!("unexpected ptr inner type: {:?}", other),
                }
            }
            other => panic!("unexpected ptr arg: {:?}", other),
        }
    }

    #[test]
    fn parses_realistic_socket_subset_syntax() {
        let input = r#"
            include <linux/socket.h>
            resource fd[4] = -1, 0
            resource sock[fd]
            const AF_UNIX = 1
            const AF_INET = 2
            const SOCK_STREAM = 1
            const SOCK_DGRAM = 2
            type sock_port int16be[20000:20004]

            socket(domain flags[socket_domain], type flags[socket_type], proto int32) sock (automatic_helper)
            socketpair(domain flags[socket_domain], type flags[socket_type], proto int32, fds ptr[out, sock_pair])
            listen(fd sock, backlog int32)

            socket_domain = AF_UNIX, AF_INET
            socket_type = SOCK_STREAM, SOCK_DGRAM

            sock_pair {
                fd0 sock
                fd1 sock
            }
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        assert_eq!(descs.len(), 3);
        assert_eq!(descs[0].id, 7181);
        assert_eq!(descs[1].id, 7261);
        assert_eq!(descs[2].id, 4062);
        match &descs[0].args[0] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert_eq!(values, &vec![1, 2]);
            }
            other => panic!("unexpected socket domain arg: {:?}", other),
        }
        match &descs[1].args[3] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Struct { fields, size } => {
                        assert_eq!(*size, 8);
                        assert_eq!(fields.len(), 2);
                        for field in fields {
                            match field {
                                ArgType::Resource(resource) => assert_eq!(resource.kind, "sock"),
                                other => panic!("unexpected sock_pair inner type: {:?}", other),
                            }
                        }
                    }
                    other => panic!("unexpected socketpair ptr inner type: {:?}", other),
                }
            }
            other => panic!("unexpected socketpair fds arg: {:?}", other),
        }
        assert_eq!(descs[2].ret, ReturnType::Int);
    }

    #[test]
    fn rejects_unknown_named_sets() {
        let input = r#"
            resource fd[4] = -1, 0, 1
            syscall openat@1 -> fd(filename, flags[missing_flags], const[4; 0])
        "#;
        let err = parse_syscall_descs(input).unwrap_err();
        assert!(err.contains("unknown flags set 'missing_flags'"));
    }

    #[test]
    fn rejects_unknown_bare_syscall_names() {
        let input = "totally_not_real(fd sock)";
        let err = parse_syscall_descs(input).unwrap_err();
        assert!(err.contains("unknown bare syscall 'totally_not_real'"));
    }

    #[test]
    fn parses_len_and_optional_pointer_forms() {
        let input = r#"
            resource fd[4] = -1, 0
            resource sock[fd]
            type sockaddr_storage buffer[128:128]
            accept(fd sock, peer ptr[out, sockaddr_storage, opt], peerlen ptr[inout, len[peer, int32]]) sock
            bind(fd sock, addr ptr[in, sockaddr_storage], addrlen len[addr, int32])
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(*optional);
                match inner.as_ref() {
                    ArgType::Buffer {
                        min_size,
                        max_size,
                        dir,
                    } => {
                        assert_eq!((*min_size, *max_size), (128, 128));
                        assert_eq!(*dir, BufferDir::Plain);
                    }
                    other => panic!("unexpected accept peer inner type: {:?}", other),
                }
            }
            other => panic!("unexpected accept peer arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::InOut);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Len { target, size, kind } => {
                        assert_eq!((*target, *size, *kind), (1, 4, LengthKind::Auto));
                    }
                    other => panic!("unexpected accept peerlen inner type: {:?}", other),
                }
            }
            other => panic!("unexpected accept peerlen arg: {:?}", other),
        }
        match &descs[1].args[2] {
            ArgType::Len { target, size, kind } => {
                assert_eq!((*target, *size, *kind), (1, 4, LengthKind::Auto))
            }
            other => panic!("unexpected bind addrlen arg: {:?}", other),
        }
    }

    #[test]
    fn parses_typed_consts_structs_and_variant_syscall_names() {
        let input = r#"
            resource fd[4] = -1, 0
            resource sock[fd]
            resource sock_in[sock]
            const AF_INET = 2
            const SOCK_STREAM = 1
            flagset socket_types[4] = SOCK_STREAM
            type sock_port int16be[20000:20004]
            type ipv4_addr const[0x7f000001, int32be]

            sockaddr_in {
                family const[AF_INET, int16]
                port sock_port
                addr ipv4_addr
            } [size[16], align[8]]

            socket$inet(domain const[AF_INET], type flags[socket_types, int16], proto int32) sock_in
            bind$inet(fd sock_in, addr ptr[in, sockaddr_in], addrlen len[addr])
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].name, "socket$inet");
        assert_eq!(descs[0].id, 7181);
        match &descs[0].args[0] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
            } => {
                assert_eq!(*size, 8);
                assert_eq!(values, &vec![2]);
                assert_eq!(*range, None);
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected socket domain arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
            } => {
                assert_eq!(*size, 2);
                assert_eq!(values, &vec![1]);
                assert_eq!(*range, None);
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected socket type arg: {:?}", other),
        }
        match &descs[1].args[1] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::In);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Struct { fields, size } => {
                        assert_eq!(*size, 16);
                        assert_eq!(fields.len(), 3);
                        match &fields[0] {
                            ArgType::Const {
                                size,
                                values,
                                range,
                                endian,
                            } => {
                                assert_eq!(*size, 2);
                                assert_eq!(values, &vec![2]);
                                assert_eq!(*range, None);
                                assert_eq!(*endian, ScalarEndian::Native);
                            }
                            other => panic!("unexpected sockaddr family field: {:?}", other),
                        }
                        match &fields[1] {
                            ArgType::Const {
                                size,
                                values,
                                range,
                                endian,
                            } => {
                                assert_eq!(*size, 2);
                                assert!(values.is_empty());
                                assert_eq!(*range, Some((20000, 20004)));
                                assert_eq!(*endian, ScalarEndian::Big);
                            }
                            other => panic!("unexpected sockaddr port field: {:?}", other),
                        }
                        match &fields[2] {
                            ArgType::Const {
                                size,
                                values,
                                range,
                                endian,
                            } => {
                                assert_eq!(*size, 4);
                                assert_eq!(values, &vec![0x7f000001]);
                                assert_eq!(*range, None);
                                assert_eq!(*endian, ScalarEndian::Big);
                            }
                            other => panic!("unexpected sockaddr addr field: {:?}", other),
                        }
                    }
                    other => panic!("unexpected sockaddr_in type: {:?}", other),
                }
            }
            other => panic!("unexpected bind addr arg: {:?}", other),
        }
        match &descs[1].args[2] {
            ArgType::Len { target, size, kind } => {
                assert_eq!((*target, *size, *kind), (1, 8, LengthKind::Auto))
            }
            other => panic!("unexpected bind addrlen arg: {:?}", other),
        }
    }

    #[test]
    fn parses_buffer_direction_and_bytesize_forms() {
        let input = r#"
            resource fd[4] = -1, 0
            resource sock[fd]
            sendto$inet(fd sock, buf buffer[in], len len[buf, int32], f const[0], addr ptr[in, sockaddr_in, opt], addrlen len[addr])
            recvfrom$inet(fd sock, buf buffer[out], len bytesize[buf, int32], f const[0], addr ptr[out, sockaddr_in, opt], addrlen len[addr])
            sockaddr_in {
                family const[2, int16]
                port int16be[20000:20004]
                addr const[0x7f000001, int32be]
            } [size[16]]
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].args[1] {
            ArgType::Buffer {
                min_size,
                max_size,
                dir,
            } => {
                assert_eq!((*min_size, *max_size), (1, 256));
                assert_eq!(*dir, BufferDir::In);
            }
            other => panic!("unexpected sendto buf arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Len { target, size, kind } => {
                assert_eq!((*target, *size, *kind), (1, 4, LengthKind::Auto));
            }
            other => panic!("unexpected sendto len arg: {:?}", other),
        }
        match &descs[1].args[1] {
            ArgType::Buffer {
                min_size,
                max_size,
                dir,
            } => {
                assert_eq!((*min_size, *max_size), (1, 256));
                assert_eq!(*dir, BufferDir::Out);
            }
            other => panic!("unexpected recvfrom buf arg: {:?}", other),
        }
        match &descs[1].args[2] {
            ArgType::Len { target, size, kind } => {
                assert_eq!((*target, *size, *kind), (1, 4, LengthKind::Bytes));
            }
            other => panic!("unexpected recvfrom len arg: {:?}", other),
        }
    }

    #[test]
    fn parses_resource_declarations() {
        let input = r#"
            resource fd[4] = -1, 0, 1, 2
            resource sock[fd] = -1, 0
            syscall eventfd2@318 -> fd(const[4; 0], const[4; 0])
            syscall socket@7256 -> sock(const[4; 2], const[4; 1], const[4; 0])
            syscall close@246 -> int(fd)
        "#;
        let descs = parse_syscall_descs(input).unwrap();
        match &descs[0].ret {
            ReturnType::Resource(resource) => {
                assert_eq!(resource.kind, "fd");
                assert_eq!(resource.size, 4);
                assert_eq!(resource.default_value(), (-1i64) as u64);
            }
            other => panic!("unexpected return type: {:?}", other),
        }
        match &descs[1].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values[0], 2),
            other => panic!("unexpected arg type: {:?}", other),
        }
        match &descs[1].ret {
            ReturnType::Resource(resource) => {
                assert_eq!(resource.kind, "sock");
                assert_eq!(resource.lineage, vec!["fd", "sock"]);
            }
            other => panic!("unexpected socket return type: {:?}", other),
        }
        match &descs[2].args[0] {
            ArgType::Resource(resource) => assert_eq!(resource.lineage, vec!["fd"]),
            other => panic!("unexpected arg type: {:?}", other),
        }
    }

    #[test]
    fn parses_output_resource_arrays() {
        let input = r#"
            resource fd[4] = -1, 0, 1, 2
            syscall pipe2@4916 -> int(ptr[out; array[fd; 2]], const[4; 0])
        "#;
        let descs = parse_syscall_descs(input).unwrap();
        match &descs[0].args[0] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Array { inner, len } => {
                        assert_eq!(*len, 2);
                        match inner.as_ref() {
                            ArgType::Resource(resource) => assert_eq!(resource.kind, "fd"),
                            other => panic!("unexpected array inner type: {:?}", other),
                        }
                    }
                    other => panic!("unexpected pointer inner type: {:?}", other),
                }
            }
            other => panic!("unexpected arg type: {:?}", other),
        }
    }

    #[test]
    fn parses_relative_includes_from_file_paths() {
        let dir = temp_description_dir("include");
        let base = dir.join("base.txt");
        let common = dir.join("common.txt.const");

        fs::write(
            &common,
            "# Code generated by syz-sysgen. DO NOT EDIT.\narches = 386, amd64\nO_CLOEXEC = 0o2000000\n",
        )
        .unwrap();
        fs::write(
            &base,
            "include \"common.txt.const\"\nresource fd[4] = -1, 0\nflagset dup_flags[4] = 0, O_CLOEXEC\nsyscall dup3@297 -> fd(fd, fd, flags[dup_flags])\n",
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&base).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Resource(resource) => assert_eq!(resource.kind, "fd"),
            other => panic!("unexpected arg type: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![0, 0o2000000]),
            other => panic!("unexpected flags type: {:?}", other),
        }
    }

    #[test]
    fn path_loading_ignores_header_includes_in_realistic_socket_fragment() {
        let dir = temp_description_dir("socket-header-include");
        let base = dir.join("socket.txt");
        fs::write(
            dir.join("socket.txt.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "arches = amd64\n",
                "AF_UNIX = 1\n",
                "SOCK_STREAM = 1\n",
            ),
        )
        .unwrap();
        fs::write(
            &base,
            concat!(
                "include <linux/socket.h>\n",
                "resource fd[4] = -1, 0\n",
                "resource sock[fd]\n",
                "socketpair(domain flags[socket_domain], type flags[socket_type], proto int32, fds ptr[out, sock_pair])\n",
                "listen(fd sock, backlog int32)\n",
                "socket_domain = AF_UNIX\n",
                "socket_type = SOCK_STREAM\n",
                "sock_pair {\n",
                "    fd0 sock\n",
                "    fd1 sock\n",
                "}\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&base).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].name, "socketpair");
        assert_eq!(descs[0].id, 7261);
        assert_eq!(descs[1].id, 4062);
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![1]),
            other => panic!("unexpected socketpair domain arg: {:?}", other),
        }
        match &descs[0].args[3] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Struct { fields, size } => {
                        assert_eq!(*size, 8);
                        assert_eq!(fields.len(), 2);
                        for field in fields {
                            match field {
                                ArgType::Resource(resource) => assert_eq!(resource.kind, "sock"),
                                other => {
                                    panic!("unexpected socketpair output inner type: {:?}", other)
                                }
                            }
                        }
                    }
                    other => panic!("unexpected socketpair output type: {:?}", other),
                }
            }
            other => panic!("unexpected socketpair fds arg: {:?}", other),
        }
        match &descs[1].args[0] {
            ArgType::Resource(resource) => assert_eq!(resource.kind, "sock"),
            other => panic!("unexpected listen fd arg: {:?}", other),
        }
    }

    #[test]
    fn parses_const_files_with_arch_filters() {
        let dir = temp_description_dir("const-file");
        fs::write(
            dir.join("00-common.txt.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "arches = 386, amd64, arm64\n",
                "AF_UNIX = 1\n",
                "AMD64_ONLY = 7, amd64:386\n",
                "NOT_AMD64 = 99, arm64:riscv64\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("10-target.txt"),
            concat!(
                "resource sock[4] = -1, 0\n",
                "constset unix_domain[4] = AF_UNIX\n",
                "constset proto_values[4] = AMD64_ONLY\n",
                "syscall socket@1 -> sock(const[unix_domain], const[4; 1], const[proto_values])\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![1]),
            other => panic!("unexpected domain arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![7]),
            other => panic!("unexpected proto arg: {:?}", other),
        }
    }

    #[test]
    fn auto_loads_sibling_const_file_for_single_txt_target() {
        let dir = temp_description_dir("sibling-const");
        let base = dir.join("socket.txt");
        fs::write(
            dir.join("socket.txt.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "arches = 386, amd64\n",
                "AF_UNIX = 1\n",
                "SOCK_STREAM = 1\n",
            ),
        )
        .unwrap();
        fs::write(
            &base,
            concat!(
                "resource sock[4] = -1, 0\n",
                "constset unix_domain[4] = AF_UNIX\n",
                "constset stream_type[4] = SOCK_STREAM\n",
                "syscall socket@1 -> sock(const[unix_domain], const[stream_type], int32)\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&base).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![1]),
            other => panic!("unexpected domain arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert!(values.is_empty());
            }
            other => panic!("unexpected proto arg: {:?}", other),
        }
    }

    #[test]
    fn parses_directory_fragments_in_sorted_order() {
        let dir = temp_description_dir("directory");
        fs::write(dir.join("00-resources.txt"), "resource fd[4] = -1, 0\n").unwrap();
        fs::write(
            dir.join("10-syscalls.txt"),
            "syscall close@246 -> int(fd)\nsyscall getpid@537 -> int()\n",
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].name, "close");
        assert_eq!(descs[1].name, "getpid");
    }

    #[test]
    fn directory_loading_prefers_txt_const_before_matching_txt() {
        let dir = temp_description_dir("directory-const-order");
        fs::write(
            dir.join("socket.txt.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "arches = amd64\n",
                "AF_UNIX = 1\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("socket.txt"),
            concat!(
                "resource sock[4] = -1, 0\n",
                "constset unix_domain[4] = AF_UNIX\n",
                "syscall socket@1 -> sock(const[unix_domain], int32, int32)\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![1]),
            other => panic!("unexpected domain arg: {:?}", other),
        }
    }
}
