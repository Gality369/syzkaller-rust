use crate::program::{
    ArgType, BufferDir, LengthKind, LengthTarget, LengthTargetRoot, PtrDir, ResourceDesc,
    ReturnType, ScalarEndian, SyscallAttrs, SyscallDesc,
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const TARGET_ARCH: &str = "amd64";
const TARGET_PTR_SIZE: u64 = 8;
const KNOWN_CONST_FILE_ARCHES: &[&str] = &[
    "386", "amd64", "arm", "arm64", "mips64le", "ppc64le", "riscv64", "s390x", "loong64",
];

fn builtin_consts() -> HashMap<String, u64> {
    HashMap::from([
        ("PTR_SIZE".to_string(), TARGET_PTR_SIZE),
        ("PAGE_SIZE".to_string(), crate::program::PAGE_SIZE),
    ])
}

fn builtin_types() -> HashMap<String, ArgType> {
    HashMap::from([
        (
            "bool8".to_string(),
            ArgType::Const {
                size: 1,
                values: Vec::new(),
                range: Some((0, 1)),
                endian: ScalarEndian::Native,
                allow_any: false,
                bitfield_bits: None,
            },
        ),
        (
            "bool16".to_string(),
            ArgType::Const {
                size: 2,
                values: Vec::new(),
                range: Some((0, 1)),
                endian: ScalarEndian::Native,
                allow_any: false,
                bitfield_bits: None,
            },
        ),
        (
            "bool32".to_string(),
            ArgType::Const {
                size: 4,
                values: Vec::new(),
                range: Some((0, 1)),
                endian: ScalarEndian::Native,
                allow_any: false,
                bitfield_bits: None,
            },
        ),
        (
            "bool64".to_string(),
            ArgType::Const {
                size: 8,
                values: Vec::new(),
                range: Some((0, 1)),
                endian: ScalarEndian::Native,
                allow_any: false,
                bitfield_bits: None,
            },
        ),
        (
            "boolptr".to_string(),
            ArgType::Const {
                size: TARGET_PTR_SIZE as usize,
                values: Vec::new(),
                range: Some((0, 1)),
                endian: ScalarEndian::Native,
                allow_any: false,
                bitfield_bits: None,
            },
        ),
        (
            "fileoff".to_string(),
            ArgType::Const {
                size: 8,
                values: Vec::new(),
                range: None,
                endian: ScalarEndian::Native,
                allow_any: true,
                bitfield_bits: None,
            },
        ),
        (
            "compressed_image".to_string(),
            ArgType::Buffer {
                min_size: 0,
                max_size: usize::MAX,
                dir: BufferDir::Plain,
            },
        ),
    ])
}

pub fn parse_syscall_descs(input: &str) -> Result<Vec<SyscallDesc>, String> {
    let mut state = ParseState {
        consts: builtin_consts(),
        types: builtin_types(),
        templates: builtin_templates(),
        allow_unknown_bare_syscalls: false,
        ..Default::default()
    };
    parse_input(input, "<inline>", None, &mut state, &mut HashSet::new())?;
    Ok(state.descs)
}

pub fn parse_syscall_descs_from_path(path: impl AsRef<Path>) -> Result<Vec<SyscallDesc>, String> {
    let mut state = ParseState {
        consts: builtin_consts(),
        types: builtin_types(),
        templates: builtin_templates(),
        allow_unknown_bare_syscalls: true,
        ..Default::default()
    };
    parse_path(path.as_ref(), &mut state, &mut HashSet::new())?;
    Ok(state.descs)
}

#[derive(Default)]
struct ParseState {
    consts: HashMap<String, u64>,
    const_sets: HashMap<String, ValueSet>,
    flag_sets: HashMap<String, ValueSet>,
    string_sets: HashMap<String, Vec<Vec<u8>>>,
    types: HashMap<String, ArgType>,
    templates: HashMap<String, TypeTemplate>,
    resources: HashMap<String, ResourceDesc>,
    descs: Vec<SyscallDesc>,
    next_synthetic_syscall_id: u64,
    allow_unknown_bare_syscalls: bool,
}

struct PrescanFile {
    source: String,
    lines: Vec<String>,
    is_const: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetaDirective {
    Automatic,
    NoExtract,
    Arches(Vec<String>),
}

#[derive(Clone)]
enum PendingTypeDef {
    TypeAlias {
        line_no: usize,
        rest: String,
    },
    TypeStruct {
        line_no: usize,
        rest: String,
        block_lines: Vec<String>,
    },
    TypeUnion {
        line_no: usize,
        rest: String,
        block_lines: Vec<String>,
    },
    Struct {
        line_no: usize,
        line: String,
        block_lines: Vec<String>,
    },
    Union {
        line_no: usize,
        line: String,
        block_lines: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueSet {
    size: usize,
    values: Vec<u64>,
}

#[derive(Debug, Clone)]
struct TypeTemplate {
    name: String,
    params: Vec<String>,
    body: TemplateBody,
}

#[derive(Debug, Clone)]
enum TemplateBody {
    Alias(String),
    Struct {
        fields: Vec<TemplateField>,
        attrs: BlockAttrs,
    },
    Union {
        fields: Vec<TemplateField>,
        attrs: BlockAttrs,
    },
}

#[derive(Debug, Clone)]
struct TemplateField {
    name: String,
    type_text: String,
    attrs: FieldAttrs,
}

#[derive(Debug, Clone, Copy, Default)]
struct FieldAttrs {
    overlay: bool,
    dir: Option<PtrDir>,
}

#[derive(Debug, Clone, Copy)]
struct ScalarTypeSpec {
    size: usize,
    endian: ScalarEndian,
    bitfield_bits: Option<u8>,
}

fn builtin_templates() -> HashMap<String, TypeTemplate> {
    HashMap::from([
        (
            "fileoff".to_string(),
            TypeTemplate {
                name: "fileoff".to_string(),
                params: vec!["BASE".to_string()],
                body: TemplateBody::Alias("BASE".to_string()),
            },
        ),
        (
            "optional".to_string(),
            TypeTemplate {
                name: "optional".to_string(),
                params: vec!["T".to_string()],
                body: TemplateBody::Union {
                    fields: vec![
                        TemplateField {
                            name: "val".to_string(),
                            type_text: "T".to_string(),
                            attrs: FieldAttrs::default(),
                        },
                        TemplateField {
                            name: "void".to_string(),
                            type_text: "void".to_string(),
                            attrs: FieldAttrs::default(),
                        },
                    ],
                    attrs: BlockAttrs {
                        size: None,
                        varlen: true,
                        packed: false,
                        align: None,
                    },
                },
            },
        ),
        (
            "fmt".to_string(),
            TypeTemplate {
                name: "fmt".to_string(),
                params: vec!["BASE".to_string(), "T".to_string()],
                body: TemplateBody::Alias("T".to_string()),
            },
        ),
        (
            "text".to_string(),
            TypeTemplate {
                name: "text".to_string(),
                params: vec!["ARCH".to_string()],
                body: TemplateBody::Alias("buffer[in]".to_string()),
            },
        ),
    ])
}

#[derive(Debug, Clone, Default)]
struct ParseArgContext {
    allow_parent_len: bool,
    field_names: Option<HashMap<String, usize>>,
    current_type_name: Option<String>,
    recursive_pending_types: Option<HashSet<String>>,
}

impl ParseArgContext {
    fn with_field_names(mut self, field_names: &HashMap<String, usize>) -> Self {
        self.field_names = Some(field_names.clone());
        self
    }

    fn field_names(&self) -> Option<&HashMap<String, usize>> {
        self.field_names.as_ref()
    }

    fn with_current_type_name(mut self, current_type_name: Option<&str>) -> Self {
        self.current_type_name = current_type_name.map(str::to_string);
        self
    }

    fn current_type_name(&self) -> Option<&str> {
        self.current_type_name.as_deref()
    }

    fn with_recursive_pending_types(
        mut self,
        recursive_pending_types: Option<&HashSet<String>>,
    ) -> Self {
        self.recursive_pending_types = recursive_pending_types.cloned();
        self
    }

    fn recursive_pending_types(&self) -> Option<&HashSet<String>> {
        self.recursive_pending_types.as_ref()
    }
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
        if parse_trace_enabled() {
            eprintln!("parse_path: entering dir {}", resolved.display());
        }
        prescan_path_definitions(&resolved, state, &mut HashSet::new())?;

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

    if parse_trace_enabled() {
        eprintln!("parse_path: file {}", resolved.display());
    }

    if resolved.extension() == Some(OsStr::new("const")) && !const_file_matches_target(&resolved) {
        return Ok(());
    }

    let input = fs::read_to_string(&resolved).map_err(|err| {
        format!(
            "failed to read description file {}: {}",
            resolved.display(),
            err
        )
    })?;
    if resolved.extension() == Some(OsStr::new("const")) {
        return parse_const_file(&input, &resolved.display().to_string(), &mut state.consts);
    }

    let lines = input.lines().collect::<Vec<_>>();
    if !file_meta_allows_target(&lines, &resolved.display().to_string())? {
        return Ok(());
    }

    for const_sibling in sibling_const_paths(&resolved) {
        if const_sibling.exists() {
            parse_path(&const_sibling, state, visited)?;
        }
    }

    parse_input(
        &input,
        &resolved.display().to_string(),
        resolved.parent(),
        state,
        visited,
    )
}

fn prescan_path_definitions(
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
        let mut files = Vec::new();
        collect_prescan_files(&resolved, &mut files, &mut HashSet::new())?;
        if parse_trace_enabled() {
            eprintln!(
                "prescan_path_definitions: {} gathered {} files",
                resolved.display(),
                files.len()
            );
        }

        let pending_resources = files
            .iter()
            .flat_map(|file| {
                let lines = file.lines.iter().map(String::as_str).collect::<Vec<_>>();
                collect_local_resource_definitions(&lines)
                    .into_iter()
                    .map(move |(line_no, rest)| (file.source.clone(), line_no, rest))
            })
            .collect::<Vec<_>>();
        resolve_pending_resource_definitions(pending_resources, state)?;

        let mut pending_types = Vec::new();
        for file in &files {
            if file.is_const {
                let input = file.lines.join("\n");
                parse_const_file(&input, &file.source, &mut state.consts)?;
                continue;
            }
            let lines = file.lines.iter().map(String::as_str).collect::<Vec<_>>();
            prescan_local_value_definitions(&lines, &file.source, state)?;
            pending_types.extend(
                collect_pending_type_definitions(&lines)
                    .map_err(|err| format!("{}: {}", file.source, err))?,
            );
        }
        resolve_pending_type_definitions(pending_types, state, &resolved.display().to_string())?;
        return Ok(());
    }

    if resolved.extension() == Some(OsStr::new("txt")) {
        let input = fs::read_to_string(&resolved).map_err(|err| {
            format!(
                "failed to read description file {}: {}",
                resolved.display(),
                err
            )
        })?;
        let source = resolved.display().to_string();
        let lines = input.lines().collect::<Vec<_>>();
        if !file_meta_allows_target(&lines, &source)? {
            return Ok(());
        }
        for const_sibling in sibling_const_paths(&resolved) {
            if const_sibling.exists() {
                prescan_path_definitions(&const_sibling, state, visited)?;
            }
        }
        prescan_local_resource_definitions(&lines, &source, state)?;
        prescan_local_value_definitions(&lines, &source, state)?;
        return Ok(());
    }

    if resolved.extension() == Some(OsStr::new("const")) {
        if !const_file_matches_target(&resolved) {
            return Ok(());
        }
        let input = fs::read_to_string(&resolved).map_err(|err| {
            format!(
                "failed to read description file {}: {}",
                resolved.display(),
                err
            )
        })?;
        parse_const_file(&input, &resolved.display().to_string(), &mut state.consts)?;
    }

    Ok(())
}

fn collect_prescan_files(
    path: &Path,
    files: &mut Vec<PrescanFile>,
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
                collect_prescan_files(&entry_path, files, visited)?;
            }
        }
        return Ok(());
    }

    let input = fs::read_to_string(&resolved).map_err(|err| {
        format!(
            "failed to read description file {}: {}",
            resolved.display(),
            err
        )
    })?;
    if resolved.extension() == Some(OsStr::new("const")) && !const_file_matches_target(&resolved) {
        return Ok(());
    }
    if resolved.extension() == Some(OsStr::new("txt")) {
        let lines = input.lines().collect::<Vec<_>>();
        if !file_meta_allows_target(&lines, &resolved.display().to_string())? {
            return Ok(());
        }
        for const_sibling in sibling_const_paths(&resolved) {
            if const_sibling.exists() {
                collect_prescan_files(&const_sibling, files, visited)?;
            }
        }
    }
    files.push(PrescanFile {
        source: resolved.display().to_string(),
        lines: input.lines().map(str::to_string).collect(),
        is_const: resolved.extension() == Some(OsStr::new("const")),
    });
    Ok(())
}

fn parse_input(
    input: &str,
    source: &str,
    base_dir: Option<&Path>,
    state: &mut ParseState,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), String> {
    let lines = input.lines().collect::<Vec<_>>();
    if !file_meta_allows_target(&lines, source)? {
        return Ok(());
    }
    if let Some(base_dir) = base_dir {
        for (index, raw_line) in lines.iter().enumerate() {
            let line_no = index + 1;
            let line = strip_comment(raw_line).trim();
            let Some(rest) = line.strip_prefix("include ") else {
                continue;
            };
            if is_header_include(rest) {
                continue;
            }
            let include_path = parse_include_path(line_no, rest)?;
            let include_path = if include_path.is_absolute() {
                include_path
            } else {
                base_dir.join(include_path)
            };
            parse_path(&include_path, state, visited)
                .map_err(|err| format!("{}: line {}: {}", source, line_no, err))?;
        }
    }
    prescan_local_resource_definitions(&lines, source, state)?;
    prescan_local_value_definitions(&lines, source, state)?;
    let mut index = 0usize;
    let mut pending_types = Vec::new();
    let mut pending_syscalls = Vec::new();
    while index < lines.len() {
        let line_no = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("meta ") {
            parse_meta_directive(line_no, rest).map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("incdir ") {
            parse_incdir_path(line_no, rest).map_err(|err| format!("{}: {}", source, err))?;
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
        if let Some(rest) = line.strip_prefix("define ") {
            parse_define(line_no, rest, &mut state.consts)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("type ") {
            let rest = rest.trim();
            if rest.ends_with('{') {
                pending_types.push(PendingTypeDef::TypeStruct {
                    line_no,
                    rest: rest.to_string(),
                    block_lines: collect_block_lines(&lines, &mut index, line_no, "}")
                        .map_err(|err| format!("{}: {}", source, err))?,
                });
                continue;
            }
            if rest.ends_with('[') {
                pending_types.push(PendingTypeDef::TypeUnion {
                    line_no,
                    rest: rest.to_string(),
                    block_lines: collect_block_lines(&lines, &mut index, line_no, "]")
                        .map_err(|err| format!("{}: {}", source, err))?,
                });
                continue;
            }
            pending_types.push(PendingTypeDef::TypeAlias {
                line_no,
                rest: rest.to_string(),
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("resource ") {
            parse_resource(line_no, rest, &state.consts, &mut state.resources)
                .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }
        if line.ends_with('{') {
            pending_types.push(PendingTypeDef::Struct {
                line_no,
                line: line.to_string(),
                block_lines: collect_block_lines(&lines, &mut index, line_no, "}")
                    .map_err(|err| format!("{}: {}", source, err))?,
            });
            continue;
        }
        if line.ends_with('[') {
            pending_types.push(PendingTypeDef::Union {
                line_no,
                line: line.to_string(),
                block_lines: collect_block_lines(&lines, &mut index, line_no, "]")
                    .map_err(|err| format!("{}: {}", source, err))?,
            });
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
            let known_const_sets = state.const_sets.clone();
            let known_flag_sets = state.flag_sets.clone();
            let known_string_sets = state.string_sets.clone();
            parse_implicit_value_set(
                line_no,
                line,
                &state.consts,
                &known_const_sets,
                &known_flag_sets,
                &known_string_sets,
                &mut state.const_sets,
                &mut state.flag_sets,
                &mut state.string_sets,
            )
            .map_err(|err| format!("{}: {}", source, err))?;
            continue;
        }

        return Err(format!(
            "{}: line {}: unsupported statement: {}",
            source, line_no, line
        ));
    }

    resolve_pending_type_definitions(pending_types, state, source)?;

    for (line_no, syscall) in pending_syscalls {
        state.descs.push(
            parse_syscall(
                line_no,
                &syscall,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.string_sets,
                &state.types,
                &state.templates,
                &state.resources,
                &mut state.next_synthetic_syscall_id,
                state.allow_unknown_bare_syscalls,
            )
            .map_err(|err| format!("{}: {}", source, err))?,
        );
    }

    Ok(())
}

fn collect_block_lines(
    lines: &[&str],
    index: &mut usize,
    line_no: usize,
    terminator: &str,
) -> Result<Vec<String>, String> {
    let mut block_lines = Vec::new();
    while *index < lines.len() {
        let line = lines[*index];
        block_lines.push(line.to_string());
        *index += 1;
        if strip_comment(line)
            .trim()
            .strip_prefix(terminator)
            .is_some()
        {
            return Ok(block_lines);
        }
    }
    Err(format!(
        "line {}: block is missing closing '{}'",
        line_no, terminator
    ))
}

fn collect_pending_type_definitions(lines: &[&str]) -> Result<Vec<PendingTypeDef>, String> {
    let mut pending = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line_no = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;
        if line.is_empty()
            || line.starts_with("include ")
            || line.starts_with("const ")
            || line.starts_with("constset ")
            || line.starts_with("flagset ")
            || line.starts_with("define ")
            || line.starts_with("resource ")
            || line.starts_with("syscall ")
            || looks_like_bare_syscall(line)
            || line.contains('=')
        {
            continue;
        }
        if let Some(rest) = line.strip_prefix("type ") {
            let rest = rest.trim();
            if rest.ends_with('{') {
                pending.push(PendingTypeDef::TypeStruct {
                    line_no,
                    rest: rest.to_string(),
                    block_lines: collect_block_lines(lines, &mut index, line_no, "}")?,
                });
                continue;
            }
            if rest.ends_with('[') {
                pending.push(PendingTypeDef::TypeUnion {
                    line_no,
                    rest: rest.to_string(),
                    block_lines: collect_block_lines(lines, &mut index, line_no, "]")?,
                });
                continue;
            }
            pending.push(PendingTypeDef::TypeAlias {
                line_no,
                rest: rest.to_string(),
            });
            continue;
        }
        if line.ends_with('{') {
            pending.push(PendingTypeDef::Struct {
                line_no,
                line: line.to_string(),
                block_lines: collect_block_lines(lines, &mut index, line_no, "}")?,
            });
            continue;
        }
        if line.ends_with('[') {
            pending.push(PendingTypeDef::Union {
                line_no,
                line: line.to_string(),
                block_lines: collect_block_lines(lines, &mut index, line_no, "]")?,
            });
        }
    }
    Ok(pending)
}

fn resolve_pending_type_definitions(
    mut pending: Vec<PendingTypeDef>,
    state: &mut ParseState,
    source: &str,
) -> Result<(), String> {
    let mut round = 0usize;
    while !pending.is_empty() {
        round += 1;
        let mut progress = false;
        let mut remaining = Vec::new();
        let mut remaining_errors = Vec::new();
        let known_types = state.types.clone();
        let known_templates = state.templates.clone();
        if parse_trace_enabled() {
            eprintln!(
                "resolve_pending_type_definitions: source={} round={} pending={} known_types={} known_templates={}",
                source,
                round,
                pending.len(),
                known_types.len(),
                known_templates.len()
            );
        }
        for pending_def in pending {
            match try_parse_pending_type_def(pending_def, state, &known_types, &known_templates) {
                Ok(()) => progress = true,
                Err((pending_def, err)) if is_unresolved_type_reference_error(&err) => {
                    remaining_errors.push(err);
                    remaining.push(pending_def);
                }
                Err((pending_def, err)) => {
                    return Err(format!(
                        "{}: {} while parsing {}",
                        source,
                        err,
                        pending_def.summary()
                    ))
                }
            }
        }
        if !progress {
            let pending_type_names = remaining
                .iter()
                .filter_map(PendingTypeDef::defined_type_name)
                .collect::<HashSet<_>>();
            let relaxed_known_types = state.types.clone();
            let relaxed_known_templates = state.templates.clone();
            let mut relaxed_remaining = Vec::new();
            let mut relaxed_errors = Vec::new();
            let mut relaxed_progress = false;
            for pending_def in remaining.iter().cloned() {
                match try_parse_pending_type_def_relaxed(
                    pending_def,
                    state,
                    &relaxed_known_types,
                    &relaxed_known_templates,
                    &pending_type_names,
                ) {
                    Ok(()) => relaxed_progress = true,
                    Err((pending_def, err)) if is_unresolved_type_reference_error(&err) => {
                        relaxed_errors.push(err);
                        relaxed_remaining.push(pending_def);
                    }
                    Err((pending_def, err)) => {
                        return Err(format!(
                            "{}: {} while parsing {}",
                            source,
                            err,
                            pending_def.summary()
                        ))
                    }
                }
            }
            if relaxed_progress {
                if parse_trace_enabled() {
                    eprintln!(
                        "resolve_pending_type_definitions: source={} round={} salvaged_remaining={}",
                        source,
                        round,
                        relaxed_remaining.len()
                    );
                }
                pending = relaxed_remaining;
                continue;
            }
            let mut sample = remaining
                .iter()
                .zip(remaining_errors.iter())
                .take(3)
                .map(|(pending_def, err)| format!("{} ({})", pending_def.summary(), err))
                .collect::<Vec<_>>()
                .join("; ");
            let mut next_root = remaining_errors
                .first()
                .and_then(|err| unresolved_type_reference_name(err))
                .map(str::to_string);
            let mut seen_roots = HashSet::new();
            let mut depth = 0usize;
            while let Some(root_name) = next_root.take() {
                if !seen_roots.insert(root_name.clone()) {
                    break;
                }
                let Some((pending_def, err)) = remaining
                    .iter()
                    .zip(remaining_errors.iter())
                    .find(|(pending_def, _)| pending_def.references_type_name(&root_name))
                else {
                    break;
                };
                sample.push_str(&format!(
                    "; root {} blocked by {}",
                    root_name,
                    format!("{} ({})", pending_def.summary(), err)
                ));
                depth += 1;
                if depth >= 3 {
                    break;
                }
                next_root = unresolved_type_reference_name(err).map(str::to_string);
            }
            return Err(format!(
                "{}: unresolved type definitions: {}",
                source, sample
            ));
        }
        if parse_trace_enabled() {
            eprintln!(
                "resolve_pending_type_definitions: source={} round={} remaining={}",
                source,
                round,
                remaining.len()
            );
        }
        pending = remaining;
    }
    Ok(())
}

fn try_parse_pending_type_def(
    pending: PendingTypeDef,
    state: &mut ParseState,
    known_types: &HashMap<String, ArgType>,
    known_templates: &HashMap<String, TypeTemplate>,
) -> Result<(), (PendingTypeDef, String)> {
    try_parse_pending_type_def_impl(pending, state, known_types, known_templates, None)
}

fn try_parse_pending_type_def_relaxed(
    pending: PendingTypeDef,
    state: &mut ParseState,
    known_types: &HashMap<String, ArgType>,
    known_templates: &HashMap<String, TypeTemplate>,
    recursive_pending_types: &HashSet<String>,
) -> Result<(), (PendingTypeDef, String)> {
    try_parse_pending_type_def_impl(
        pending,
        state,
        known_types,
        known_templates,
        Some(recursive_pending_types),
    )
}

fn try_parse_pending_type_def_impl(
    pending: PendingTypeDef,
    state: &mut ParseState,
    known_types: &HashMap<String, ArgType>,
    known_templates: &HashMap<String, TypeTemplate>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<(), (PendingTypeDef, String)> {
    let result = match &pending {
        PendingTypeDef::TypeAlias { line_no, rest } => parse_type_alias(
            *line_no,
            rest,
            &state.consts,
            &state.const_sets,
            &state.flag_sets,
            &state.string_sets,
            known_types,
            known_templates,
            &state.resources,
            &mut state.types,
            &mut state.templates,
        ),
        PendingTypeDef::TypeStruct {
            line_no,
            rest,
            block_lines,
        } => {
            let lines = block_lines.iter().map(String::as_str).collect::<Vec<_>>();
            let mut index = 0usize;
            parse_type_struct_block(
                *line_no,
                rest,
                &lines,
                &mut index,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.string_sets,
                known_types,
                known_templates,
                &state.resources,
                &mut state.types,
                &mut state.templates,
                recursive_pending_types,
            )
        }
        PendingTypeDef::TypeUnion {
            line_no,
            rest,
            block_lines,
        } => {
            let lines = block_lines.iter().map(String::as_str).collect::<Vec<_>>();
            let mut index = 0usize;
            parse_type_union_block(
                *line_no,
                rest,
                &lines,
                &mut index,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.string_sets,
                known_types,
                known_templates,
                &state.resources,
                &mut state.types,
                &mut state.templates,
                recursive_pending_types,
            )
        }
        PendingTypeDef::Struct {
            line_no,
            line,
            block_lines,
        } => {
            let lines = block_lines.iter().map(String::as_str).collect::<Vec<_>>();
            let mut index = 0usize;
            parse_struct_block(
                *line_no,
                line,
                &lines,
                &mut index,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.string_sets,
                known_types,
                known_templates,
                &state.resources,
                &mut state.types,
                recursive_pending_types,
            )
        }
        PendingTypeDef::Union {
            line_no,
            line,
            block_lines,
        } => {
            let lines = block_lines.iter().map(String::as_str).collect::<Vec<_>>();
            let mut index = 0usize;
            parse_union_block(
                *line_no,
                line,
                &lines,
                &mut index,
                &state.consts,
                &state.const_sets,
                &state.flag_sets,
                &state.string_sets,
                known_types,
                known_templates,
                &state.resources,
                &mut state.types,
                recursive_pending_types,
            )
        }
    };

    result.map_err(|err| (pending, err))
}

impl PendingTypeDef {
    fn summary(&self) -> String {
        match self {
            PendingTypeDef::TypeAlias { rest, .. }
            | PendingTypeDef::TypeStruct { rest, .. }
            | PendingTypeDef::TypeUnion { rest, .. } => format!("type {}", rest),
            PendingTypeDef::Struct { line, .. } | PendingTypeDef::Union { line, .. } => {
                line.clone()
            }
        }
    }

    fn references_type_name(&self, type_name: &str) -> bool {
        let summary = self.summary();
        summary == format!("{type_name} [")
            || summary == format!("{type_name} {{")
            || summary.starts_with(&format!("type {type_name} "))
            || summary == format!("type {type_name}")
    }

    fn defined_type_name(&self) -> Option<String> {
        match self {
            PendingTypeDef::TypeAlias { rest, .. } => pending_def_type_name_from_alias(rest),
            PendingTypeDef::TypeStruct { rest, .. } | PendingTypeDef::TypeUnion { rest, .. } => {
                pending_def_type_name_from_header(rest)
            }
            PendingTypeDef::Struct { line, .. } | PendingTypeDef::Union { line, .. } => {
                pending_def_type_name_from_header(line)
            }
        }
    }
}

fn pending_def_type_name_from_alias(text: &str) -> Option<String> {
    let (head, _) = split_type_definition_head_and_body(text)?;
    pending_def_type_name_from_head(head)
}

fn pending_def_type_name_from_header(text: &str) -> Option<String> {
    let head = text
        .strip_suffix('{')
        .or_else(|| text.strip_suffix('['))
        .unwrap_or(text);
    pending_def_type_name_from_head(head)
}

fn pending_def_type_name_from_head(text: &str) -> Option<String> {
    let head = text.trim();
    let name = head
        .split_once('[')
        .map(|(name, _)| name)
        .unwrap_or(head)
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn prescan_local_resource_definitions(
    lines: &[&str],
    source: &str,
    state: &mut ParseState,
) -> Result<(), String> {
    let pending = collect_local_resource_definitions(lines)
        .into_iter()
        .map(|(line_no, rest)| (source.to_string(), line_no, rest))
        .collect::<Vec<_>>();
    resolve_pending_resource_definitions(pending, state)
}

fn collect_local_resource_definitions(lines: &[&str]) -> Vec<(usize, String)> {
    let mut resources = Vec::new();
    let mut block_depth = 0usize;
    for (index, raw_line) in lines.iter().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('}') || line.starts_with(']') {
            block_depth = block_depth.saturating_sub(1);
            continue;
        }
        if block_depth > 0 {
            if line.ends_with('{') || line.ends_with('[') {
                block_depth += 1;
            }
            continue;
        }
        if line.ends_with('{') || line.ends_with('[') {
            block_depth += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("resource ") {
            resources.push((index + 1, rest.to_string()));
        }
    }
    resources
}

fn resolve_pending_resource_definitions(
    mut pending: Vec<(String, usize, String)>,
    state: &mut ParseState,
) -> Result<(), String> {
    while !pending.is_empty() {
        let mut progress = false;
        let mut remaining = Vec::new();
        for (source, line_no, rest) in pending {
            match parse_resource(line_no, &rest, &state.consts, &mut state.resources) {
                Ok(()) => progress = true,
                Err(err) if is_unresolved_resource_base_error(&err) => {
                    remaining.push((source, line_no, rest));
                }
                Err(err) => return Err(format!("{}: {}", source, err)),
            }
        }
        if !progress {
            let (source, line_no, rest) = &remaining[0];
            return Err(format!(
                "{}: line {}: unresolved resource declaration 'resource {}'",
                source, line_no, rest
            ));
        }
        pending = remaining;
    }
    Ok(())
}

fn prescan_local_value_definitions(
    lines: &[&str],
    source: &str,
    state: &mut ParseState,
) -> Result<(), String> {
    let mut pending_implicit_sets = Vec::new();
    let mut block_depth = 0usize;
    for (index, raw_line) in lines.iter().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw_line).trim();
        if line.starts_with('}') || line.starts_with(']') {
            block_depth = block_depth.saturating_sub(1);
            continue;
        }
        if block_depth > 0 {
            if line.ends_with('{') || line.ends_with('[') {
                block_depth += 1;
            }
            continue;
        }
        if line.ends_with('{') || line.ends_with('[') {
            block_depth += 1;
        }
        if line.is_empty()
            || line.starts_with("include ")
            || line.starts_with("resource ")
            || line.starts_with("type ")
            || line.ends_with('{')
            || line.ends_with('[')
            || line.starts_with("syscall ")
            || looks_like_bare_syscall(line)
        {
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
        if line.contains('=') {
            pending_implicit_sets.push((line_no, line.to_string()));
        }
    }

    while !pending_implicit_sets.is_empty() {
        let mut progress = false;
        let mut remaining = Vec::new();
        let known_const_sets = state.const_sets.clone();
        let known_flag_sets = state.flag_sets.clone();
        let known_string_sets = state.string_sets.clone();
        for (line_no, line) in pending_implicit_sets {
            match parse_implicit_value_set(
                line_no,
                &line,
                &state.consts,
                &known_const_sets,
                &known_flag_sets,
                &known_string_sets,
                &mut state.const_sets,
                &mut state.flag_sets,
                &mut state.string_sets,
            ) {
                Ok(()) => progress = true,
                Err(err) if is_unresolved_value_reference_error(&err) => {
                    remaining.push((line_no, line));
                }
                Err(err) => return Err(format!("{}: {}", source, err)),
            }
        }
        if !progress {
            let (line_no, line) = &remaining[0];
            return Err(format!(
                "{}: line {}: unresolved value definition '{}'",
                source, line_no, line
            ));
        }
        pending_implicit_sets = remaining;
    }
    Ok(())
}

fn parse_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("SYZKALLER_RUST_TRACE_PARSE").is_some())
}

fn unresolved_type_reference_name<'a>(err: &'a str) -> Option<&'a str> {
    let prefix = "unresolved type reference '";
    let start = err.find(prefix)? + prefix.len();
    let rest = &err[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut in_char = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        if in_string || in_char {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => {
                    escape = true;
                }
                '"' if in_string => {
                    in_string = false;
                }
                '\'' if in_char => {
                    in_char = false;
                }
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '\'' => in_char = true,
            '#' => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn is_identifier_like(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}

fn looks_like_const_name(text: &str) -> bool {
    let Some(first) = text.chars().next() else {
        return false;
    };
    first.is_ascii_uppercase()
}

fn is_unresolved_value_reference_error(err: &str) -> bool {
    err.contains("unresolved value reference")
}

fn is_unresolved_resource_base_error(err: &str) -> bool {
    err.contains("unresolved resource base")
}

fn is_unresolved_type_reference_error(err: &str) -> bool {
    err.contains("unresolved type reference")
}

fn path_root_priority(file_name: &str) -> u8 {
    match file_name {
        "sys.txt.const" => 0,
        "sys.txt" => 1,
        _ => 2,
    }
}

fn path_sort_key(path: &Path) -> (u8, String, u8, String) {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let root_priority = path_root_priority(file_name);
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
    (
        root_priority,
        normalized,
        priority,
        path.display().to_string(),
    )
}

fn sibling_const_paths(path: &Path) -> Vec<PathBuf> {
    if path.extension() != Some(OsStr::new("txt")) {
        return Vec::new();
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
        return vec![path.with_file_name(format!("{}.const", file_name))];
    };

    let mut out = vec![path.with_file_name(format!("{}.const", file_name))];
    let arch_specific = path.with_file_name(format!("{}_{}.const", stem, TARGET_ARCH));
    if !out.contains(&arch_specific) {
        out.push(arch_specific);
    }
    out
}

fn const_file_arch_suffix(path: &Path) -> Option<&'static str> {
    let stem = path.file_stem()?.to_str()?;
    KNOWN_CONST_FILE_ARCHES.iter().copied().find(|arch| {
        stem.strip_suffix(arch)
            .is_some_and(|prefix| prefix.ends_with('_'))
    })
}

fn const_file_matches_target(path: &Path) -> bool {
    path.extension() != Some(OsStr::new("const"))
        || const_file_arch_suffix(path).is_none_or(|arch| arch == TARGET_ARCH)
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

        let parsed = parse_const_value(value.trim(), consts, line_no)
            .map_err(|err| format!("{}: {}", source, err))?;
        if let Some(parsed) = parsed {
            consts.insert(name.to_string(), parsed);
        }
    }
    Ok(())
}

fn parse_const_value(
    value: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<Option<u64>, String> {
    let clauses = split_top_level(value, ',')
        .into_iter()
        .map(|clause| clause.trim())
        .filter(|clause| !clause.is_empty())
        .collect::<Vec<_>>();
    if clauses.is_empty() {
        return Err(format!("line {}: constant value is empty", line_no));
    }

    if clauses.len() == 2 && !clauses[0].contains(':') && is_arch_list(clauses[1]) {
        if !arch_filter_allows_target(clauses[1], TARGET_ARCH) {
            return Ok(None);
        }
        let parsed = parse_expr(clauses[0], consts, line_no)?;
        return Ok(Some(parsed));
    }

    let mut default_value = None;
    for clause in clauses {
        if let Some((arch_filter, value_expr)) = clause.rsplit_once(':') {
            if !arch_filter_allows_target(arch_filter, TARGET_ARCH) {
                continue;
            }
            if value_expr.trim() == "???" {
                return Ok(None);
            }
            let parsed = parse_expr(value_expr.trim(), consts, line_no)?;
            return Ok(Some(parsed));
        }

        if clause == "???" {
            return Ok(None);
        }

        default_value = Some(parse_expr(clause, consts, line_no)?);
    }

    Ok(default_value)
}

fn is_known_arch_name(value: &str) -> bool {
    matches!(
        value,
        "386"
            | "amd64"
            | "arm"
            | "arm64"
            | "loong64"
            | "mips64le"
            | "ppc64le"
            | "riscv64"
            | "s390x"
    )
}

fn is_arch_list(value: &str) -> bool {
    value
        .split(':')
        .map(str::trim)
        .all(|part| !part.is_empty() && is_known_arch_name(part))
}

fn arch_filter_allows_target(filter: &str, target_arch: &str) -> bool {
    filter
        .split(':')
        .map(str::trim)
        .any(|arch| !arch.is_empty() && arch == target_arch)
}

fn file_meta_allows_target(lines: &[&str], source: &str) -> Result<bool, String> {
    let mut allow = true;
    let mut index = 0usize;
    while index < lines.len() {
        let line_no = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("meta ") else {
            if line.starts_with("type ") && line.ends_with('{') {
                collect_block_lines(lines, &mut index, line_no, "}")
                    .map_err(|err| format!("{}: {}", source, err))?;
                continue;
            }
            if line.starts_with("type ") && line.ends_with('[') {
                collect_block_lines(lines, &mut index, line_no, "]")
                    .map_err(|err| format!("{}: {}", source, err))?;
                continue;
            }
            if line.ends_with('{') {
                collect_block_lines(lines, &mut index, line_no, "}")
                    .map_err(|err| format!("{}: {}", source, err))?;
                continue;
            }
            if line.ends_with('[') {
                collect_block_lines(lines, &mut index, line_no, "]")
                    .map_err(|err| format!("{}: {}", source, err))?;
                continue;
            }
            continue;
        };
        match parse_meta_directive(line_no, rest).map_err(|err| format!("{}: {}", source, err))? {
            MetaDirective::Automatic | MetaDirective::NoExtract => {}
            MetaDirective::Arches(arches) => {
                allow &= arches.iter().any(|arch| arch == TARGET_ARCH);
            }
        }
    }
    Ok(allow)
}

fn parse_meta_directive(line_no: usize, rest: &str) -> Result<MetaDirective, String> {
    let rest = rest.trim();
    match rest {
        "automatic" => return Ok(MetaDirective::Automatic),
        "noextract" => return Ok(MetaDirective::NoExtract),
        _ => {}
    }
    let Some(inner) = bracketed(rest, "arches") else {
        return Err(format!(
            "line {}: unsupported meta statement '{}'",
            line_no, rest
        ));
    };
    let mut arches = Vec::new();
    for value in split_top_level(inner, ',') {
        let raw = value.trim();
        if raw.is_empty() {
            continue;
        }
        let bytes = parse_string_literal(raw, line_no)?;
        let arch = String::from_utf8(bytes).map_err(|err| {
            format!(
                "line {}: meta arches entry {} is not valid UTF-8: {}",
                line_no, raw, err
            )
        })?;
        if !is_known_arch_name(&arch) {
            return Err(format!(
                "line {}: unknown architecture '{}' in meta arches",
                line_no, arch
            ));
        }
        arches.push(arch);
    }
    if arches.is_empty() {
        return Err(format!("line {}: meta arches list is empty", line_no));
    }
    Ok(MetaDirective::Arches(arches))
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

fn parse_incdir_path(line_no: usize, rest: &str) -> Result<(), String> {
    let path = rest.trim();
    if path.is_empty() {
        return Err(format!("line {}: incdir path is empty", line_no));
    }
    if path
        .strip_prefix('<')
        .and_then(|path| path.strip_suffix('>'))
        .is_some()
    {
        return Ok(());
    }
    if path
        .strip_prefix('"')
        .and_then(|path| path.strip_suffix('"'))
        .is_some()
    {
        return Ok(());
    }
    Err(format!(
        "line {}: incdir must use <path> or \"path\" syntax",
        line_no
    ))
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

fn parse_define(
    line_no: usize,
    rest: &str,
    consts: &mut HashMap<String, u64>,
) -> Result<(), String> {
    let rest = rest.trim();
    let split = rest
        .find(char::is_whitespace)
        .ok_or_else(|| format!("line {}: expected define NAME VALUE", line_no))?;
    let name = rest[..split].trim();
    let value_expr = rest[split..].trim();
    if name.is_empty() {
        return Err(format!("line {}: define name is empty", line_no));
    }
    if value_expr.is_empty() {
        return Err(format!("line {}: define value is empty", line_no));
    }
    if let Ok(value) = parse_expr(value_expr, consts, line_no) {
        consts.insert(name.to_string(), value);
    }
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
        None if scalar_integer_spec(base).is_some() => {
            let (size, _) = scalar_integer_spec(base).expect("checked scalar integer spec");
            (size, vec![kind.to_string()])
        }
        None => {
            if is_identifier_like(base) {
                return Err(format!(
                    "line {}: unresolved resource base '{}'",
                    line_no, base
                ));
            }
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
    known_const_sets: &HashMap<String, ValueSet>,
    known_flag_sets: &HashMap<String, ValueSet>,
    known_string_sets: &HashMap<String, Vec<Vec<u8>>>,
    const_sets: &mut HashMap<String, ValueSet>,
    flag_sets: &mut HashMap<String, ValueSet>,
    string_sets: &mut HashMap<String, Vec<Vec<u8>>>,
) -> Result<(), String> {
    let (name, values) = line
        .split_once('=')
        .ok_or_else(|| format!("line {}: expected NAME = VALUE", line_no))?;
    let name = name.trim();
    if name == "_" {
        return Ok(());
    }
    if name.is_empty() {
        return Err(format!("line {}: value set name is empty", line_no));
    }
    let raw_values = split_top_level(values.trim(), ',');
    if raw_values
        .iter()
        .any(|value| is_string_literal(value.trim()))
    {
        let values = expand_string_value_entries(raw_values, known_string_sets, line_no)?;
        string_sets.insert(name.to_string(), values);
    } else {
        let values = expand_numeric_value_entries(
            raw_values,
            consts,
            known_const_sets,
            known_flag_sets,
            line_no,
        )?;
        let set = ValueSet { size: 4, values };
        const_sets.insert(name.to_string(), set.clone());
        flag_sets.insert(name.to_string(), set);
    }
    Ok(())
}

fn expand_string_value_entries(
    raw_values: Vec<&str>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    line_no: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let mut values = Vec::new();
    for raw_value in raw_values {
        let raw_value = raw_value.trim();
        if is_string_literal(raw_value) {
            values.push(parse_string_literal(raw_value, line_no)?);
            continue;
        }
        if let Some(set) = string_sets.get(raw_value) {
            values.extend(set.iter().cloned());
            continue;
        }
        if is_identifier_like(raw_value) {
            return Err(format!(
                "line {}: unresolved value reference '{}'",
                line_no, raw_value
            ));
        }
        return Err(format!(
            "line {}: unsupported string value entry '{}'",
            line_no, raw_value
        ));
    }
    Ok(values)
}

fn expand_numeric_value_entries(
    raw_values: Vec<&str>,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    line_no: usize,
) -> Result<Vec<u64>, String> {
    let mut values = Vec::new();
    for raw_value in raw_values {
        let raw_value = raw_value.trim();
        if let Some(set) = const_sets
            .get(raw_value)
            .or_else(|| flag_sets.get(raw_value))
        {
            values.extend(set.values.iter().copied());
            continue;
        }
        if is_identifier_like(raw_value) && !consts.contains_key(raw_value) {
            if looks_like_const_name(raw_value) {
                continue;
            }
            return Err(format!(
                "line {}: unresolved value reference '{}'",
                line_no, raw_value
            ));
        }
        values.push(parse_expr(raw_value, consts, line_no)?);
    }
    Ok(values)
}

fn parse_type_alias(
    line_no: usize,
    rest: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
    out_templates: &mut HashMap<String, TypeTemplate>,
) -> Result<(), String> {
    let arg_names = HashMap::new();
    let (name, type_text) = split_type_definition_head_and_body(rest)
        .ok_or_else(|| format!("line {}: type declaration is missing a body", line_no))?;
    let name = name.trim();
    let type_text = type_text.trim();
    if name.is_empty() || type_text.is_empty() {
        return Err(format!("line {}: malformed type declaration", line_no));
    }
    let (name, params) = parse_template_head(name, line_no)?;
    if !params.is_empty() {
        out_templates.insert(
            name.to_string(),
            TypeTemplate {
                name: name.to_string(),
                params,
                body: TemplateBody::Alias(type_text.to_string()),
            },
        );
        return Ok(());
    }
    let arg_type = parse_arg(
        type_text,
        consts,
        const_sets,
        flag_sets,
        string_sets,
        &arg_names,
        types,
        templates,
        resources,
        line_no,
        ParseArgContext {
            allow_parent_len: true,
            field_names: None,
            current_type_name: None,
            recursive_pending_types: None,
        },
    )?;
    out_types.insert(name.to_string(), annotate_named_arg_type(arg_type, &name));
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
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<(), String> {
    let name = header.strip_suffix('{').unwrap_or(header).trim();
    if name.is_empty() {
        return Err(format!("line {}: struct name is empty", line_no));
    }
    let (fields, attrs) = collect_template_block_fields(line_no, lines, index, consts, '}')?;
    let arg_type = build_struct_arg_type(
        &fields,
        Some(name),
        attrs.size,
        attrs.packed,
        attrs.align,
        consts,
        const_sets,
        flag_sets,
        string_sets,
        types,
        templates,
        resources,
        line_no,
        None,
        recursive_pending_types,
    )?;
    out_types.insert(name.to_string(), arg_type);
    Ok(())
}

fn parse_union_block(
    line_no: usize,
    header: &str,
    lines: &[&str],
    index: &mut usize,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<(), String> {
    let name = header.strip_suffix('[').unwrap_or(header).trim();
    if name.is_empty() {
        return Err(format!("line {}: union name is empty", line_no));
    }
    let (fields, attrs) = collect_template_block_fields(line_no, lines, index, consts, ']')?;
    let arg_type = build_union_arg_type(
        &fields,
        Some(name),
        attrs,
        consts,
        const_sets,
        flag_sets,
        string_sets,
        types,
        templates,
        resources,
        line_no,
        None,
        recursive_pending_types,
    )?;
    out_types.insert(name.to_string(), arg_type);
    Ok(())
}

fn parse_type_struct_block(
    line_no: usize,
    header: &str,
    lines: &[&str],
    index: &mut usize,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
    out_templates: &mut HashMap<String, TypeTemplate>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<(), String> {
    let head = header.strip_suffix('{').unwrap_or(header).trim();
    let (name, params) = parse_template_head(head, line_no)?;
    if name == "auto_aligner" && params.len() == 1 && params[0] == "N" {
        let _ = collect_block_lines(lines, index, line_no, "}")?;
        out_templates.insert(
            name.clone(),
            TypeTemplate {
                name,
                params,
                body: TemplateBody::Struct {
                    fields: vec![TemplateField {
                        name: "void".to_string(),
                        type_text: "void".to_string(),
                        attrs: FieldAttrs::default(),
                    }],
                    attrs: BlockAttrs::default(),
                },
            },
        );
        return Ok(());
    }
    let (fields, attrs) = collect_template_block_fields(line_no, lines, index, consts, '}')?;
    if params.is_empty() {
        let arg_type = build_struct_arg_type(
            &fields,
            Some(&name),
            attrs.size,
            attrs.packed,
            attrs.align,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            types,
            templates,
            resources,
            line_no,
            None,
            recursive_pending_types,
        )?;
        out_types.insert(name, arg_type);
    } else {
        out_templates.insert(
            name.clone(),
            TypeTemplate {
                name: name.clone(),
                params,
                body: TemplateBody::Struct { fields, attrs },
            },
        );
    }
    Ok(())
}

fn parse_type_union_block(
    line_no: usize,
    header: &str,
    lines: &[&str],
    index: &mut usize,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    out_types: &mut HashMap<String, ArgType>,
    out_templates: &mut HashMap<String, TypeTemplate>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<(), String> {
    let head = header.strip_suffix('[').unwrap_or(header).trim();
    let (name, params) = parse_template_head(head, line_no)?;
    let (fields, attrs) = collect_template_block_fields(line_no, lines, index, consts, ']')?;
    if params.is_empty() {
        let arg_type = build_union_arg_type(
            &fields,
            Some(&name),
            attrs,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            types,
            templates,
            resources,
            line_no,
            None,
            recursive_pending_types,
        )?;
        out_types.insert(name, arg_type);
    } else {
        out_templates.insert(
            name.clone(),
            TypeTemplate {
                name: name.clone(),
                params,
                body: TemplateBody::Union { fields, attrs },
            },
        );
    }
    Ok(())
}

fn collect_template_block_fields(
    line_no: usize,
    lines: &[&str],
    index: &mut usize,
    consts: &HashMap<String, u64>,
    terminator: char,
) -> Result<(Vec<TemplateField>, BlockAttrs), String> {
    let mut fields = Vec::new();
    let mut attrs = BlockAttrs::default();
    while *index < lines.len() {
        let field_line_no = *index + 1;
        let line = strip_comment(lines[*index]).trim();
        *index += 1;
        if line.is_empty() {
            continue;
        }
        if let Some(attr_text) = line.strip_prefix(terminator) {
            attrs = parse_block_attrs(attr_text, consts, field_line_no)?;
            break;
        }
        let mut parts = line.split_whitespace();
        let field_name = parts
            .next()
            .ok_or_else(|| format!("line {}: block field is empty", field_line_no))?;
        let raw_type_text = parts.collect::<Vec<_>>().join(" ");
        let (type_text, field_attrs) =
            if let Some((type_only, attrs_text)) = raw_type_text.split_once(" (") {
                (type_only.trim().to_string(), parse_field_attrs(attrs_text))
            } else {
                (raw_type_text, FieldAttrs::default())
            };
        if type_text.is_empty() {
            return Err(format!(
                "line {}: block field '{}' is missing a type",
                field_line_no, field_name
            ));
        }
        fields.push(TemplateField {
            name: field_name.to_string(),
            type_text,
            attrs: field_attrs,
        });
    }
    if fields.is_empty() {
        return Err(format!("line {}: block has no fields", line_no));
    }
    Ok((fields, attrs))
}

fn parse_field_attrs(text: &str) -> FieldAttrs {
    let mut attrs = FieldAttrs::default();
    let inner = text.trim().strip_suffix(')').unwrap_or(text.trim());
    for attr in split_top_level(inner, ',') {
        match attr.trim() {
            "out_overlay" => {
                attrs.overlay = true;
                attrs.dir = Some(PtrDir::Out);
            }
            "in_overlay" => {
                attrs.overlay = true;
                attrs.dir = Some(PtrDir::In);
            }
            "out" => attrs.dir = Some(PtrDir::Out),
            "inout" => attrs.dir = Some(PtrDir::InOut),
            "in" => attrs.dir = Some(PtrDir::In),
            _ => {}
        }
    }
    attrs
}

fn struct_overlay_start(fields: &[TemplateField], line_no: usize) -> Result<Option<usize>, String> {
    let overlay_indices = fields
        .iter()
        .enumerate()
        .filter_map(|(idx, field)| field.attrs.overlay.then_some(idx))
        .collect::<Vec<_>>();
    match overlay_indices.as_slice() {
        [] => Ok(None),
        [0] => Err(format!(
            "line {}: overlay field must not be the first struct field",
            line_no
        )),
        [idx] => Ok(Some(*idx)),
        _ => Err(format!(
            "line {}: multiple overlay fields in one struct are not supported",
            line_no
        )),
    }
}

fn build_struct_arg_type(
    fields: &[TemplateField],
    type_name: Option<&str>,
    declared_size: Option<usize>,
    packed: bool,
    align: Option<usize>,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    bindings: Option<&HashMap<String, String>>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<ArgType, String> {
    let arg_names = HashMap::new();
    let overlay_start = struct_overlay_start(fields, line_no)?;
    let field_names = fields
        .iter()
        .enumerate()
        .map(|(idx, field)| (field.name.clone(), idx))
        .collect::<HashMap<_, _>>();
    let field_dirs = fields
        .iter()
        .map(|field| field.attrs.dir)
        .collect::<Vec<_>>();
    let mut parsed_fields = Vec::new();
    for field in fields {
        let type_text = bindings
            .map(|bindings| substitute_template_params(&field.type_text, bindings))
            .unwrap_or_else(|| field.type_text.clone());
        let arg_type = parse_arg(
            &type_text,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            &arg_names,
            types,
            templates,
            resources,
            line_no,
            ParseArgContext {
                allow_parent_len: true,
                field_names: None,
                current_type_name: None,
                recursive_pending_types: None,
            }
            .with_current_type_name(type_name)
            .with_field_names(&field_names)
            .with_recursive_pending_types(recursive_pending_types),
        )?;
        parsed_fields.push(arg_type);
    }
    let mut parsed_field_names = fields.iter().map(|field| field.name.clone()).collect();
    let (parsed_fields, field_prefix_size, has_var_tail) =
        match crate::program::struct_layout_prefix_size(
            &parsed_fields,
            packed,
            align,
            overlay_start,
        ) {
            Ok((field_prefix_size, has_var_tail)) => {
                (parsed_fields, field_prefix_size, has_var_tail)
            }
            Err(err) if err == "only trailing variable-sized struct fields are supported" => {
                if let Some((truncated_fields, truncated_field_names)) =
                    truncate_zero_suffixed_varlen_struct_fields(fields, &parsed_fields, packed)
                {
                    let truncated_field_count = truncated_field_names.len();
                    parsed_field_names = truncated_field_names;
                    let (field_prefix_size, has_var_tail) =
                        crate::program::struct_layout_prefix_size(
                            &truncated_fields,
                            packed,
                            align,
                            overlay_start,
                        )
                        .map_err(|retry_err| format!("line {}: {}", line_no, retry_err))?;
                    return Ok(ArgType::Struct {
                        type_name: type_name.map(str::to_string),
                        fields: truncated_fields,
                        field_names: parsed_field_names,
                        field_dirs: field_dirs[..truncated_field_count].to_vec(),
                        size: declared_size.unwrap_or(field_prefix_size),
                        varlen: has_var_tail,
                        packed,
                        align,
                        overlay_start,
                    });
                }
                let coerced_fields = coerce_opaque_fields_to_pointers(&parsed_fields);
                if coerced_fields == parsed_fields {
                    return Err(format!("line {}: {}", line_no, err));
                }
                let (field_prefix_size, has_var_tail) = crate::program::struct_layout_prefix_size(
                    &coerced_fields,
                    packed,
                    align,
                    overlay_start,
                )
                .map_err(|retry_err| format!("line {}: {}", line_no, retry_err))?;
                (coerced_fields, field_prefix_size, has_var_tail)
            }
            Err(err) => return Err(format!("line {}: {}", line_no, err)),
        };
    let size = declared_size.unwrap_or(field_prefix_size);
    if size < field_prefix_size {
        return Err(format!(
            "line {}: struct declared size {} is smaller than field prefix size {}",
            line_no, size, field_prefix_size
        ));
    }
    Ok(ArgType::Struct {
        type_name: type_name.map(str::to_string),
        fields: parsed_fields,
        field_names: parsed_field_names,
        field_dirs,
        size,
        varlen: has_var_tail,
        packed,
        align,
        overlay_start,
    })
}

fn build_union_arg_type(
    fields: &[TemplateField],
    type_name: Option<&str>,
    attrs: BlockAttrs,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    bindings: Option<&HashMap<String, String>>,
    recursive_pending_types: Option<&HashSet<String>>,
) -> Result<ArgType, String> {
    let arg_names = HashMap::new();
    let all_field_names = fields
        .iter()
        .enumerate()
        .map(|(idx, field)| (field.name.clone(), idx))
        .collect::<HashMap<_, _>>();
    let mut parsed_fields = Vec::new();
    let mut parsed_field_names = Vec::new();
    let mut parsed_field_dirs = Vec::new();
    let mut skipped_recursive_fields = false;
    for field in fields {
        let type_text = bindings
            .map(|bindings| substitute_template_params(&field.type_text, bindings))
            .unwrap_or_else(|| field.type_text.clone());
        let arg_type = match parse_arg(
            &type_text,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            &arg_names,
            types,
            templates,
            resources,
            line_no,
            ParseArgContext {
                allow_parent_len: true,
                field_names: None,
                current_type_name: None,
                recursive_pending_types: None,
            }
            .with_current_type_name(type_name)
            .with_field_names(&all_field_names)
            .with_recursive_pending_types(recursive_pending_types),
        ) {
            Ok(arg_type) => arg_type,
            Err(err)
                if is_unresolved_type_reference_error(&err)
                    && recursive_pending_types.is_some_and(|pending_names| {
                        unresolved_type_reference_name(&err)
                            .is_some_and(|name| pending_names.contains(name))
                    }) =>
            {
                if let Some(pointer_arg_type) = parse_opaque_recursive_pointer_arg(&type_text) {
                    if parse_trace_enabled() {
                        eprintln!(
                            "build_union_arg_type: materializing opaque recursive pointer field {}.{} = {} ({})",
                            type_name.unwrap_or("<anonymous>"),
                            field.name,
                            type_text,
                            err
                        );
                    }
                    pointer_arg_type
                } else if attrs.varlen {
                    if parse_trace_enabled() {
                        eprintln!(
                            "build_union_arg_type: skipping cyclic pending varlen field {}.{} = {} ({})",
                            type_name.unwrap_or("<anonymous>"),
                            field.name,
                            type_text,
                            err
                        );
                    }
                    skipped_recursive_fields = true;
                    continue;
                } else {
                    return Err(err);
                }
            }
            Err(err)
                if attrs.varlen
                    && type_name.is_some_and(|name| {
                        type_text_references_type_name(&type_text, name)
                            && is_unresolved_type_reference_error(&err)
                    }) =>
            {
                if parse_trace_enabled() {
                    eprintln!(
                        "build_union_arg_type: skipping recursive varlen field {}.{} = {} ({})",
                        type_name.unwrap_or("<anonymous>"),
                        field.name,
                        type_text,
                        err
                    );
                }
                skipped_recursive_fields = true;
                continue;
            }
            Err(err)
                if attrs.varlen
                    && is_unresolved_type_reference_error(&err)
                    && recursive_pending_types.is_some_and(|pending_names| {
                        unresolved_type_reference_name(&err)
                            .is_some_and(|name| pending_names.contains(name))
                    }) =>
            {
                if parse_trace_enabled() {
                    eprintln!(
                        "build_union_arg_type: skipping cyclic pending varlen field {}.{} = {} ({})",
                        type_name.unwrap_or("<anonymous>"),
                        field.name,
                        type_text,
                        err
                    );
                }
                skipped_recursive_fields = true;
                continue;
            }
            Err(err) => return Err(err),
        };
        parsed_field_names.push(field.name.clone());
        parsed_field_dirs.push(field.attrs.dir);
        parsed_fields.push(arg_type);
    }
    if parsed_fields.is_empty() {
        if attrs.varlen && skipped_recursive_fields {
            parsed_fields.push(ArgType::Void);
            parsed_field_names.push("void".to_string());
            parsed_field_dirs.push(None);
        } else {
            return Err(format!(
                "line {}: union must retain at least one field after recursive field filtering",
                line_no
            ));
        }
    }
    let (parsed_fields, max_field_size) =
        match parsed_fields.iter().try_fold(0usize, |acc, field| {
            let size = if attrs.varlen {
                crate::program::arg_type_fixed_size(field).unwrap_or(0)
            } else {
                crate::program::arg_type_fixed_size(field)
                    .ok_or_else(|| "union fields must be fixed-size".to_string())?
            };
            Ok::<usize, String>(acc.max(size))
        }) {
            Ok(max_field_size) => (parsed_fields, max_field_size),
            Err(err) if err == "union fields must be fixed-size" => {
                let coerced_fields = coerce_opaque_fields_to_pointers(&parsed_fields);
                if coerced_fields == parsed_fields {
                    return Err(format!("line {}: {}", line_no, err));
                }
                let max_field_size = coerced_fields
                    .iter()
                    .try_fold(0usize, |acc, field| {
                        let size = crate::program::arg_type_fixed_size(field)
                            .ok_or_else(|| "union fields must be fixed-size".to_string())?;
                        Ok::<usize, String>(acc.max(size))
                    })
                    .map_err(|retry_err| format!("line {}: {}", line_no, retry_err))?;
                (coerced_fields, max_field_size)
            }
            Err(err) => return Err(format!("line {}: {}", line_no, err)),
        };
    let size = attrs.size.unwrap_or(max_field_size);
    let union_align =
        crate::program::union_type_alignment(&parsed_fields, attrs.packed, attrs.align)
            .map_err(|err| format!("line {}: {}", line_no, err))?;
    let size = if attrs.varlen {
        size
    } else {
        size.checked_add(union_align - 1)
            .map(|rounded| rounded & !(union_align - 1))
            .ok_or_else(|| format!("line {}: union size overflow", line_no))?
    };
    if size < max_field_size {
        return Err(format!(
            "line {}: union declared size {} is smaller than max field size {}",
            line_no, size, max_field_size
        ));
    }
    Ok(ArgType::Union {
        type_name: type_name.map(str::to_string),
        fields: parsed_fields,
        field_names: parsed_field_names,
        field_dirs: parsed_field_dirs,
        size,
        varlen: attrs.varlen,
        packed: attrs.packed,
        align: attrs.align,
    })
}

fn parse_opaque_recursive_pointer_arg(type_text: &str) -> Option<ArgType> {
    let inner = bracketed(type_text, "ptr").or_else(|| bracketed(type_text, "ptr64"))?;
    let parts = split_type_parts(inner);
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let dir = match parts[0].trim() {
        "in" => PtrDir::In,
        "out" => PtrDir::Out,
        "inout" => PtrDir::InOut,
        _ => return None,
    };
    let optional = match parts.get(2).map(|part| part.trim()) {
        None => false,
        Some("opt") => true,
        Some(_) => return None,
    };
    Some(ArgType::Ptr {
        inner: Box::new(ArgType::Void),
        dir,
        optional,
    })
}

fn coerce_opaque_fields_to_pointers(fields: &[ArgType]) -> Vec<ArgType> {
    fields
        .iter()
        .map(|field| coerce_opaque_arg_to_fixed_size(field).unwrap_or_else(|| field.clone()))
        .collect()
}

fn coerce_opaque_arg_to_fixed_size(field: &ArgType) -> Option<ArgType> {
    if crate::program::arg_type_fixed_size(field).is_some() {
        return Some(field.clone());
    }
    if let Some(pointer) = coerce_opaque_field_to_pointer(field) {
        return Some(pointer);
    }
    match field {
        ArgType::Array {
            inner,
            min_len,
            max_len,
        } => {
            let inner = Box::new(coerce_opaque_arg_to_fixed_size(inner)?);
            let candidate = ArgType::Array {
                inner,
                min_len: *min_len,
                max_len: *max_len,
            };
            crate::program::arg_type_fixed_size(&candidate).map(|_| candidate)
        }
        ArgType::Struct {
            type_name,
            fields,
            field_names,
            field_dirs,
            size,
            packed,
            align,
            overlay_start,
            ..
        } => {
            let fields = fields
                .iter()
                .map(coerce_opaque_arg_to_fixed_size)
                .collect::<Option<Vec<_>>>()?;
            let (field_prefix_size, has_var_tail) =
                crate::program::struct_layout_prefix_size(&fields, *packed, *align, *overlay_start)
                    .ok()?;
            if has_var_tail {
                return None;
            }
            Some(ArgType::Struct {
                type_name: type_name.clone(),
                fields,
                field_names: field_names.clone(),
                field_dirs: field_dirs.clone(),
                size: (*size).max(field_prefix_size),
                varlen: false,
                packed: *packed,
                align: *align,
                overlay_start: *overlay_start,
            })
        }
        ArgType::Union {
            type_name,
            fields,
            field_names,
            field_dirs,
            size,
            packed,
            align,
            ..
        } => {
            let fields = fields
                .iter()
                .map(coerce_opaque_arg_to_fixed_size)
                .collect::<Option<Vec<_>>>()?;
            let max_field_size = fields
                .iter()
                .filter_map(crate::program::arg_type_fixed_size)
                .max()
                .unwrap_or(0);
            let union_align =
                crate::program::union_type_alignment(&fields, *packed, *align).ok()?;
            let rounded_size = max_field_size
                .checked_add(union_align - 1)
                .map(|rounded| rounded & !(union_align - 1))?;
            Some(ArgType::Union {
                type_name: type_name.clone(),
                fields,
                field_names: field_names.clone(),
                field_dirs: field_dirs.clone(),
                size: (*size).max(rounded_size),
                varlen: false,
                packed: *packed,
                align: *align,
            })
        }
        _ => None,
    }
}

fn truncate_zero_suffixed_varlen_struct_fields(
    fields: &[TemplateField],
    parsed_fields: &[ArgType],
    packed: bool,
) -> Option<(Vec<ArgType>, Vec<String>)> {
    if !packed {
        return None;
    }
    let var_idx = parsed_fields
        .iter()
        .position(|field| crate::program::arg_type_fixed_size(field).is_none())?;
    if var_idx + 1 >= parsed_fields.len() {
        return None;
    }
    if parsed_fields[var_idx + 1..]
        .iter()
        .any(|field| !is_zero_const_arg(field))
    {
        return None;
    }
    Some((
        parsed_fields[..=var_idx].to_vec(),
        fields[..=var_idx]
            .iter()
            .map(|field| field.name.clone())
            .collect(),
    ))
}

fn is_zero_const_arg(field: &ArgType) -> bool {
    matches!(
        field,
        ArgType::Const {
            values,
            range: None,
            ..
        } if !values.is_empty() && values.iter().all(|value| *value == 0)
    )
}

fn coerce_opaque_field_to_pointer(field: &ArgType) -> Option<ArgType> {
    let dir = match field {
        ArgType::Buffer {
            dir,
            min_size,
            max_size,
        } if min_size != max_size => match dir {
            BufferDir::Plain | BufferDir::In => PtrDir::In,
            BufferDir::Out => PtrDir::Out,
            BufferDir::InOut => PtrDir::InOut,
        },
        ArgType::String {
            fixed_len: None, ..
        }
        | ArgType::Filename => PtrDir::In,
        _ => return None,
    };

    Some(ArgType::Ptr {
        inner: Box::new(field.clone()),
        dir,
        optional: false,
    })
}

fn annotate_named_arg_type(arg_type: ArgType, type_name: &str) -> ArgType {
    match arg_type {
        ArgType::Struct {
            type_name: _,
            fields,
            field_names,
            field_dirs,
            size,
            varlen,
            packed,
            align,
            overlay_start,
        } => ArgType::Struct {
            type_name: Some(type_name.to_string()),
            fields,
            field_names,
            field_dirs,
            size,
            varlen,
            packed,
            align,
            overlay_start,
        },
        ArgType::Union {
            type_name: _,
            fields,
            field_names,
            field_dirs,
            size,
            varlen,
            packed,
            align,
        } => ArgType::Union {
            type_name: Some(type_name.to_string()),
            fields,
            field_names,
            field_dirs,
            size,
            varlen,
            packed,
            align,
        },
        other => other,
    }
}

fn instantiate_template(
    template: &TypeTemplate,
    actuals: &[String],
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    ctx: ParseArgContext,
) -> Result<ArgType, String> {
    if template.params.len() != actuals.len() {
        return Err(format!(
            "line {}: template expects {} arguments, got {}",
            line_no,
            template.params.len(),
            actuals.len()
        ));
    }
    if template.name == "auto_aligner" {
        let align = parse_expr(actuals[0].trim(), consts, line_no)? as usize;
        return Ok(ArgType::Struct {
            type_name: Some(template.name.clone()),
            fields: vec![ArgType::Void],
            field_names: vec!["void".to_string()],
            field_dirs: vec![None],
            size: 0,
            varlen: false,
            packed: false,
            align: Some(align),
            overlay_start: None,
        });
    }
    let bindings = template
        .params
        .iter()
        .cloned()
        .zip(actuals.iter().cloned())
        .collect::<HashMap<_, _>>();
    match &template.body {
        TemplateBody::Alias(body) => {
            let instantiated = substitute_template_params(body, &bindings);
            let arg_names = HashMap::new();
            let arg_type = parse_arg(
                &instantiated,
                consts,
                const_sets,
                flag_sets,
                string_sets,
                &arg_names,
                types,
                templates,
                resources,
                line_no,
                ctx,
            )?;
            Ok(annotate_named_arg_type(arg_type, &template.name))
        }
        TemplateBody::Struct { fields, attrs } => build_struct_arg_type(
            fields,
            Some(&template.name),
            attrs.size,
            attrs.packed,
            attrs.align,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            types,
            templates,
            resources,
            line_no,
            Some(&bindings),
            ctx.recursive_pending_types(),
        ),
        TemplateBody::Union { fields, attrs } => build_union_arg_type(
            fields,
            Some(&template.name),
            *attrs,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            types,
            templates,
            resources,
            line_no,
            Some(&bindings),
            ctx.recursive_pending_types(),
        ),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct BlockAttrs {
    size: Option<usize>,
    varlen: bool,
    packed: bool,
    align: Option<usize>,
}

fn parse_block_attrs(
    text: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<BlockAttrs, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(BlockAttrs::default());
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

    let mut attrs = BlockAttrs::default();
    for group in groups {
        for attr in split_top_level(group, ',') {
            let attr = attr.trim();
            if attr == "packed" {
                attrs.packed = true;
                continue;
            }
            if attr == "varlen" {
                attrs.varlen = true;
                continue;
            }
            if let Some(inner) = bracketed(attr, "align") {
                let align = parse_expr(inner.trim(), consts, line_no)? as usize;
                crate::program::struct_type_alignment(&[], false, Some(align))
                    .map_err(|err| format!("line {}: {}", line_no, err))?;
                attrs.align = Some(align);
                continue;
            }
            let Some(inner) = bracketed(attr, "size") else {
                continue;
            };
            attrs.size = Some(parse_expr(inner.trim(), consts, line_no)? as usize);
        }
    }
    Ok(attrs)
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
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    next_synthetic_syscall_id: &mut u64,
    allow_unknown_bare_syscalls: bool,
) -> Result<SyscallDesc, String> {
    if let Some((left, right)) = rest.split_once("->") {
        let (name, id) = parse_name_and_id_or_lookup(
            line_no,
            left.trim(),
            next_synthetic_syscall_id,
            allow_unknown_bare_syscalls,
        )?;
        let open = right
            .find('(')
            .ok_or_else(|| format!("line {}: syscall is missing argument list", line_no))?;
        let close = find_matching_paren(right, open)
            .ok_or_else(|| format!("line {}: syscall is missing closing ')'", line_no))?;
        if close < open {
            return Err(format!("line {}: malformed argument list", line_no));
        }

        let ret = parse_return_type(right[..open].trim(), resources, line_no)?;
        let (args, arg_names) = parse_syscall_args(
            &right[open + 1..close],
            consts,
            const_sets,
            flag_sets,
            string_sets,
            types,
            templates,
            resources,
            line_no,
        )?;
        let attrs = parse_syscall_attrs(right[close + 1..].trim(), consts, line_no)?;
        return Ok(SyscallDesc {
            name: name.to_string(),
            id,
            arg_names,
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
    let (name, id) = parse_name_and_id_or_lookup(
        line_no,
        rest[..open].trim(),
        next_synthetic_syscall_id,
        allow_unknown_bare_syscalls,
    )?;
    let (args, arg_names) = parse_syscall_args(
        &rest[open + 1..close],
        consts,
        const_sets,
        flag_sets,
        string_sets,
        types,
        templates,
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
    let attrs = parse_syscall_attrs(tail, consts, line_no)?;

    Ok(SyscallDesc {
        name: name.to_string(),
        id,
        arg_names,
        args,
        ret,
        attrs,
    })
}

fn parse_syscall_attrs(
    mut tail: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<SyscallAttrs, String> {
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
                "ignore_return" => attrs.ignore_return = true,
                "breaks_returns" => attrs.breaks_returns = true,
                "no_minimize" => attrs.no_minimize = true,
                "no_squash" => attrs.no_squash = true,
                "remote_cover" => attrs.remote_cover = true,
                "snapshot" => attrs.snapshot = true,
                "kfuzz_test" => attrs.kfuzz_test = true,
                other if other.starts_with("timeout[") && other.ends_with(']') => {
                    let value = &other["timeout[".len()..other.len() - 1];
                    attrs.timeout_ms = Some(parse_expr(value.trim(), consts, line_no)?);
                }
                other if other.starts_with("prog_timeout[") && other.ends_with(']') => {
                    let value = &other["prog_timeout[".len()..other.len() - 1];
                    attrs.prog_timeout_ms = Some(parse_expr(value.trim(), consts, line_no)?);
                }
                other if other.starts_with("fsck[") && other.ends_with(']') => {
                    let value = &other["fsck[".len()..other.len() - 1];
                    let bytes = parse_string_literal(value.trim(), line_no)?;
                    let command = String::from_utf8(bytes).map_err(|err| {
                        format!(
                            "line {}: fsck command {} is not valid UTF-8: {}",
                            line_no,
                            value.trim(),
                            err
                        )
                    })?;
                    attrs.fsck_command = Some(command);
                }
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

fn parse_name_and_id_or_lookup<'a>(
    line_no: usize,
    text: &'a str,
    next_synthetic_syscall_id: &mut u64,
    allow_unknown_bare_syscalls: bool,
) -> Result<(&'a str, u64), String> {
    if let Some((name, id)) = text.rsplit_once('@') {
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("line {}: syscall name is empty", line_no));
        }
        let id = parse_integer(id.trim(), line_no)?;
        *next_synthetic_syscall_id = (*next_synthetic_syscall_id).max(id + 1);
        return Ok((name, id));
    }
    if !is_valid_syscall_name(text) {
        return Err(format!(
            "line {}: syscall must use NAME@ID syntax or a known bare syscall name",
            line_no
        ));
    }
    if let Some(id) = builtin_linux_amd64_syscall_id(text) {
        *next_synthetic_syscall_id = (*next_synthetic_syscall_id).max(id + 1);
        return Ok((text, id));
    }
    if allow_unknown_bare_syscalls {
        let id = *next_synthetic_syscall_id;
        *next_synthetic_syscall_id = next_synthetic_syscall_id.saturating_add(1);
        return Ok((text, id));
    }
    Err(format!(
        "line {}: unknown bare syscall '{}' for linux/amd64 ID lookup",
        line_no, text
    ))
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

fn linux_amd64_syscall_ids() -> &'static HashMap<&'static str, u64> {
    static IDS: OnceLock<HashMap<&'static str, u64>> = OnceLock::new();
    IDS.get_or_init(|| {
        include_str!("../data/linux_amd64_syscalls.tsv")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (name, id) = line
                    .split_once('\t')
                    .unwrap_or_else(|| panic!("malformed linux_amd64_syscalls.tsv entry: {line}"));
                let id = id.parse::<u64>().unwrap_or_else(|err| {
                    panic!("invalid linux_amd64_syscalls.tsv id for {name}: {err}")
                });
                (name, id)
            })
            .collect()
    })
}

fn builtin_linux_amd64_syscall_id(name: &str) -> Option<u64> {
    linux_amd64_syscall_ids().get(name).copied()
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
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    ctx: ParseArgContext,
) -> Result<ArgType, String> {
    let text = text.trim();
    if let Some(resource) = resources.get(text) {
        return Ok(ArgType::Resource(resource.clone()));
    }
    if let Some(arg_type) = types.get(text) {
        return Ok(arg_type.clone());
    }
    if let Some(base) = text.strip_suffix("[opt]") {
        let base = base.trim();
        if base == "vma" {
            return parse_vma("opt", line_no);
        }
        if let Some(resource) = resources.get(base) {
            return Ok(ArgType::OptionalResource(resource.clone()));
        }
        if !is_builtin_bracketed_type_name(base) {
            return parse_arg(
                base,
                consts,
                const_sets,
                flag_sets,
                string_sets,
                arg_names,
                types,
                templates,
                resources,
                line_no,
                ctx,
            );
        }
    }
    if let Some(spec) = parse_scalar_type_spec(text) {
        return Ok(ArgType::Const {
            size: spec.size,
            values: Vec::new(),
            range: None,
            endian: spec.endian,
            allow_any: true,
            bitfield_bits: spec.bitfield_bits,
        });
    }
    if let Some(arg_type) = parse_scalar_range_arg(text, consts, const_sets, flag_sets, line_no)? {
        return Ok(arg_type);
    }
    if text == "filename" {
        return Ok(ArgType::Filename);
    }
    if text == "void" {
        return Ok(ArgType::Void);
    }
    if text == "string" {
        return Ok(ArgType::String {
            values: Vec::new(),
            noz: false,
            fixed_len: None,
            filename: false,
        });
    }
    if text == "stringnoz" {
        return Ok(ArgType::String {
            values: Vec::new(),
            noz: true,
            fixed_len: None,
            filename: false,
        });
    }
    if text == "vma" {
        return Ok(ArgType::Vma {
            min_pages: 1,
            max_pages: 4,
            optional: false,
        });
    }
    if text == "vma64" {
        return Ok(ArgType::Vma {
            min_pages: 1,
            max_pages: 4,
            optional: false,
        });
    }
    if let Some(inner) = bracketed(text, "const") {
        return parse_const_arg(inner, consts, const_sets, "const", line_no);
    }
    if let Some(inner) = bracketed(text, "flags") {
        return parse_const_arg(inner, consts, flag_sets, "flags", line_no);
    }
    if let Some(inner) = bracketed(text, "proc") {
        return parse_proc(inner, consts, line_no);
    }
    if let Some(inner) = bracketed(text, "buffer") {
        return parse_buffer(inner, line_no);
    }
    if let Some(inner) = bracketed(text, "glob") {
        return parse_glob(inner, line_no);
    }
    if let Some(inner) = bracketed(text, "string") {
        return parse_string(inner, consts, string_sets, line_no, false);
    }
    if let Some(inner) = bracketed(text, "stringnoz") {
        return parse_string(inner, consts, string_sets, line_no, true);
    }
    if let Some(inner) = bracketed(text, "array") {
        return parse_array(
            inner,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            arg_names,
            types,
            templates,
            resources,
            line_no,
            ctx,
        );
    }
    if let Some(inner) = bracketed(text, "ptr") {
        return parse_ptr(
            inner,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            arg_names,
            types,
            templates,
            resources,
            line_no,
            ctx,
        );
    }
    if let Some(inner) = bracketed(text, "ptr64") {
        return parse_ptr(
            inner,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            arg_names,
            types,
            templates,
            resources,
            line_no,
            ctx,
        );
    }
    if let Some(inner) = bracketed(text, "vma") {
        return parse_vma(inner, line_no);
    }
    if let Some(inner) = bracketed(text, "vma64") {
        return parse_vma(inner, line_no);
    }
    if let Some(inner) = bracketed(text, "len") {
        return parse_len(
            inner,
            arg_names,
            types,
            templates,
            line_no,
            LengthKind::Auto,
            1,
            ctx,
        );
    }
    if let Some((scale, inner)) = bracketed_with_numeric_suffix(text, "bytesize") {
        return parse_len(
            inner,
            arg_names,
            types,
            templates,
            line_no,
            LengthKind::Bytes,
            scale,
            ctx,
        );
    }
    if let Some(inner) = bracketed(text, "bitsize") {
        return parse_len(
            inner,
            arg_names,
            types,
            templates,
            line_no,
            LengthKind::Bytes,
            8,
            ctx,
        );
    }
    if let Some(inner) = bracketed(text, "csum") {
        return parse_csum(inner, consts, arg_names, types, templates, line_no, ctx);
    }
    if let Some(inner) = bracketed(text, "offsetof") {
        return parse_offsetof(inner, arg_names, types, templates, line_no, &ctx);
    }
    if let Some((template_name, inner)) = split_type_invocation(text) {
        if let Some(template) = templates.get(template_name) {
            let actuals = split_type_parts(inner)
                .into_iter()
                .map(|part| part.trim().to_string())
                .collect::<Vec<_>>();
            return instantiate_template(
                template,
                &actuals,
                consts,
                const_sets,
                flag_sets,
                string_sets,
                types,
                templates,
                resources,
                line_no,
                ctx,
            );
        }
        return Err(format!(
            "line {}: unresolved type reference '{}'",
            line_no, text
        ));
    }
    if let Some(type_text) = strip_named_arg_prefix(text) {
        return parse_arg(
            type_text,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            arg_names,
            types,
            templates,
            resources,
            line_no,
            ctx,
        );
    }

    if is_identifier_like(text) {
        return Err(format!(
            "line {}: unresolved type reference '{}'",
            line_no, text
        ));
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
            allow_any: false,
            bitfield_bits: None,
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
                    allow_any: false,
                    bitfield_bits: None,
                });
            }
            if let Some(arg_type) =
                parse_embedded_const_constraint(single, consts, sets, line_no)?
            {
                return Ok(arg_type);
            }
            match parse_expr(single, consts, line_no) {
                Ok(value) => Ok(ArgType::Const {
                    size: 8,
                    values: vec![value],
                    range: None,
                    endian: ScalarEndian::Native,
                    allow_any: false,
                    bitfield_bits: None,
                }),
                Err(_) if expr_references_unavailable_const(single, consts) => Ok(ArgType::Const {
                    size: 8,
                    values: Vec::new(),
                    range: None,
                    endian: ScalarEndian::Native,
                    allow_any: false,
                    bitfield_bits: None,
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
            let Some(spec) = parse_scalar_type_spec(right) else {
                return Err(format!(
                    "line {}: {} must use [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax",
                    line_no, arg_kind
                ));
            };
            if let Some(set) = sets.get(left) {
                return Ok(ArgType::Const {
                    size: spec.size,
                    values: set.values.clone(),
                    range: None,
                    endian: spec.endian,
                    allow_any: false,
                    bitfield_bits: spec.bitfield_bits,
                });
            }
            match parse_expr(left, consts, line_no) {
                Ok(value) => Ok(ArgType::Const {
                    size: spec.size,
                    values: vec![value],
                    range: None,
                    endian: spec.endian,
                    allow_any: false,
                    bitfield_bits: spec.bitfield_bits,
                }),
                Err(_) if expr_references_unavailable_const(left, consts) => Ok(ArgType::Const {
                    size: spec.size,
                    values: Vec::new(),
                    range: None,
                    endian: spec.endian,
                    allow_any: false,
                    bitfield_bits: spec.bitfield_bits,
                }),
                Err(_) => match parse_embedded_const_constraint(left, consts, sets, line_no)? {
                    Some(arg_type) => match embedded_const_matches_spec(&arg_type, spec) {
                        true => Ok(arg_type),
                        false => Err(format!(
                            "line {}: embedded {} scalar '{}' is incompatible with '{}'",
                            line_no, arg_kind, left, right
                        )),
                    },
                    None => Err(format!(
                        "line {}: unknown {} set '{}' (expected [value, intN] or [set_name, intN] syntax)",
                        line_no, arg_kind, left
                    )),
                },
            }
        }
        _ => Err(format!(
            "line {}: {} must use [value], [value, intN], [set_name], [set_name, intN], or [size; values] syntax",
            line_no, arg_kind
        )),
    }
}

fn parse_embedded_const_constraint(
    text: &str,
    consts: &HashMap<String, u64>,
    sets: &HashMap<String, ValueSet>,
    line_no: usize,
) -> Result<Option<ArgType>, String> {
    if let Some(spec) = parse_scalar_type_spec(text) {
        return Ok(Some(ArgType::Const {
            size: spec.size,
            values: Vec::new(),
            range: None,
            endian: spec.endian,
            allow_any: true,
            bitfield_bits: spec.bitfield_bits,
        }));
    }
    if let Some(arg_type) = parse_scalar_range_arg(text, consts, sets, sets, line_no)? {
        return Ok(Some(arg_type));
    }
    if let Some(inner) = bracketed(text, "const") {
        return parse_const_arg(inner, consts, sets, "const", line_no).map(Some);
    }
    if let Some(inner) = bracketed(text, "flags") {
        return parse_const_arg(inner, consts, sets, "flags", line_no).map(Some);
    }
    Ok(None)
}

fn embedded_const_matches_spec(arg_type: &ArgType, spec: ScalarTypeSpec) -> bool {
    matches!(
        arg_type,
        ArgType::Const {
            size,
            endian,
            bitfield_bits,
            ..
        } if *size == spec.size
            && *endian == spec.endian
            && *bitfield_bits == spec.bitfield_bits
    )
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

fn parse_glob(inner: &str, line_no: usize) -> Result<ArgType, String> {
    let pattern = inner.trim();
    if pattern.is_empty() {
        return Err(format!("line {}: glob pattern is empty", line_no));
    }
    let _ = parse_string_literal(pattern, line_no)?;
    Ok(ArgType::Filename)
}

fn parse_array(
    inner: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    ctx: ParseArgContext,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!(
            "line {}: array must use [inner], [inner, len], or [inner, min:max] syntax",
            line_no
        ));
    }
    let inner = parse_arg(
        parts[0].trim(),
        consts,
        const_sets,
        flag_sets,
        string_sets,
        arg_names,
        types,
        templates,
        resources,
        line_no,
        ctx,
    )?;
    let (min_len, max_len) = match parts.get(1).map(|part| part.trim()) {
        None => (0usize, 4usize),
        Some(spec) => {
            if let Some((min, max)) = spec.split_once(':') {
                (
                    parse_expr(min.trim(), consts, line_no)? as usize,
                    parse_expr(max.trim(), consts, line_no)? as usize,
                )
            } else {
                let len = parse_expr(spec, consts, line_no)? as usize;
                (len, len)
            }
        }
    };
    Ok(ArgType::Array {
        inner: Box::new(inner),
        min_len,
        max_len,
    })
}

fn parse_ptr(
    inner: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
    ctx: ParseArgContext,
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
    let inner_text = parts[1].trim();
    let inner = match parse_arg(
        inner_text,
        consts,
        const_sets,
        flag_sets,
        string_sets,
        arg_names,
        types,
        templates,
        resources,
        line_no,
        ctx.clone(),
    ) {
        Ok(inner) => inner,
        Err(err)
            if is_unresolved_type_reference_error(&err)
                && (ctx.current_type_name() == Some(inner_text)
                    || ctx
                        .recursive_pending_types()
                        .is_some_and(|pending| pending.contains(inner_text))) =>
        {
            ArgType::Void
        }
        Err(err) => return Err(err),
    };
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

fn parse_vma(inner: &str, line_no: usize) -> Result<ArgType, String> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(ArgType::Vma {
            min_pages: 1,
            max_pages: 4,
            optional: false,
        });
    }
    if inner == "opt" {
        return Ok(ArgType::Vma {
            min_pages: 1,
            max_pages: 4,
            optional: true,
        });
    }
    if let Some((min, max)) = inner.split_once(':') {
        let min_pages = parse_integer(min.trim(), line_no)? as usize;
        let max_pages = parse_integer(max.trim(), line_no)? as usize;
        return Ok(ArgType::Vma {
            min_pages,
            max_pages,
            optional: false,
        });
    }
    let pages = parse_integer(inner, line_no)? as usize;
    Ok(ArgType::Vma {
        min_pages: pages,
        max_pages: pages,
        optional: false,
    })
}

fn parse_proc(
    inner: &str,
    consts: &HashMap<String, u64>,
    line_no: usize,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if !(2..=3).contains(&parts.len()) {
        return Err(format!(
            "line {}: proc must use [start, per_proc] or [start, per_proc, intN] syntax",
            line_no
        ));
    }
    let values_start = parse_expr(parts[0].trim(), consts, line_no)?;
    let values_per_proc = parse_expr(parts[1].trim(), consts, line_no)?;
    let scalar_spec = match parts.get(2).map(|part| part.trim()) {
        None | Some("") => ScalarTypeSpec {
            size: 8,
            endian: ScalarEndian::Native,
            bitfield_bits: None,
        },
        Some(type_name) => parse_scalar_type_spec(type_name).ok_or_else(|| {
            format!(
                "line {}: unsupported proc scalar type '{}' (expected int8/int16/int32/int64/intptr)",
                line_no, type_name
            )
        })?,
    };
    if scalar_spec.bitfield_bits.is_some() {
        return Err(format!(
            "line {}: proc does not support bitfield scalar storage",
            line_no
        ));
    }
    Ok(ArgType::Proc {
        size: scalar_spec.size,
        values_start,
        values_per_proc,
        endian: scalar_spec.endian,
    })
}

fn parse_string(
    inner: &str,
    consts: &HashMap<String, u64>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    line_no: usize,
    noz: bool,
) -> Result<ArgType, String> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(ArgType::String {
            values: Vec::new(),
            noz,
            fixed_len: None,
            filename: false,
        });
    }

    let parts = split_type_parts(inner);
    let (value_parts, fixed_len) = if parts.len() >= 2 {
        match parse_expr(parts[parts.len() - 1].trim(), consts, line_no) {
            Ok(len) => (&parts[..parts.len() - 1], Some(len as usize)),
            Err(_) => (parts.as_slice(), None),
        }
    } else {
        (parts.as_slice(), None)
    };
    if value_parts.is_empty() {
        return Err(format!("line {}: string source is empty", line_no));
    }

    let mut values = Vec::new();
    let mut filename = false;
    if value_parts.len() == 1 {
        let value = value_parts[0].trim();
        if value == "filename" {
            filename = true;
        } else if let Some(set) = string_sets.get(value) {
            values = set.clone();
        } else if is_string_literal(value) {
            values.push(parse_string_literal(value, line_no)?);
        } else {
            return Err(format!("line {}: unknown string set '{}'", line_no, value));
        }
    } else {
        for value in value_parts {
            let value = value.trim();
            if !is_string_literal(value) {
                return Err(format!(
                    "line {}: string must use literals, a string set name, or filename",
                    line_no
                ));
            }
            values.push(parse_string_literal(value, line_no)?);
        }
    }

    Ok(ArgType::String {
        values,
        noz,
        fixed_len,
        filename,
    })
}

fn parse_len(
    inner: &str,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    line_no: usize,
    kind: LengthKind,
    scale: usize,
    ctx: ParseArgContext,
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
    let target = parse_length_target(
        target_name,
        arg_names,
        types,
        templates,
        line_no,
        &ctx,
        "len",
    )?;
    let scalar_spec = match parts.get(1).map(|part| part.trim()) {
        None | Some("") => ScalarTypeSpec {
            size: 8,
            endian: ScalarEndian::Native,
            bitfield_bits: None,
        },
        Some(type_name) => parse_scalar_type_spec(type_name).ok_or_else(|| {
            format!(
                "line {}: unsupported len scalar type '{}' (expected int8/int16/int32/int64/intptr)",
                line_no, type_name
            )
        })?,
    };
    Ok(ArgType::Len {
        target,
        size: scalar_spec.size,
        kind,
        endian: scalar_spec.endian,
        scale,
        bitfield_bits: scalar_spec.bitfield_bits,
    })
}

fn parse_offsetof(
    inner: &str,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    line_no: usize,
    ctx: &ParseArgContext,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!(
            "line {}: offsetof must use [field] or [field, intN] syntax",
            line_no
        ));
    }
    let field_name = parts[0].trim();
    if field_name.is_empty() {
        return Err(format!("line {}: offsetof target is empty", line_no));
    }
    let target = parse_length_target(
        field_name, arg_names, types, templates, line_no, ctx, "offsetof",
    )?;
    let scalar_spec = match parts.get(1).map(|part| part.trim()) {
        None | Some("") => ScalarTypeSpec {
            size: 8,
            endian: ScalarEndian::Native,
            bitfield_bits: None,
        },
        Some(type_name) => parse_scalar_type_spec(type_name).ok_or_else(|| {
            format!(
                "line {}: unsupported offsetof scalar type '{}' (expected int8/int16/int32/int64/intptr)",
                line_no, type_name
            )
        })?,
    };
    Ok(ArgType::Len {
        target,
        size: scalar_spec.size,
        kind: LengthKind::Offset,
        endian: scalar_spec.endian,
        scale: 1,
        bitfield_bits: scalar_spec.bitfield_bits,
    })
}

fn parse_csum(
    inner: &str,
    consts: &HashMap<String, u64>,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    line_no: usize,
    ctx: ParseArgContext,
) -> Result<ArgType, String> {
    let parts = split_type_parts(inner);
    if !(3..=4).contains(&parts.len()) {
        return Err(format!(
            "line {}: csum must use [target, inet, intN] or [target, pseudo, proto, intN] syntax",
            line_no
        ));
    }
    let target_name = parts[0].trim();
    if target_name.is_empty() {
        return Err(format!("line {}: csum target is empty", line_no));
    }
    let _target = parse_length_target(
        target_name,
        arg_names,
        types,
        templates,
        line_no,
        &ctx,
        "csum",
    )?;
    match parts[1].trim() {
        "inet" if parts.len() == 3 => {}
        "pseudo" if parts.len() == 4 => {
            let proto = parts[2].trim();
            if proto.is_empty() {
                return Err(format!("line {}: csum pseudo protocol is empty", line_no));
            }
            let _ = parse_expr(proto, consts, line_no)?;
        }
        "inet" => {
            return Err(format!(
                "line {}: csum[inet] must use exactly three arguments",
                line_no
            ))
        }
        "pseudo" => {
            return Err(format!(
                "line {}: csum[pseudo] must include a protocol argument",
                line_no
            ))
        }
        other => {
            return Err(format!(
                "line {}: unsupported csum kind '{}' (expected inet or pseudo)",
                line_no, other
            ))
        }
    }
    let scalar_idx = if parts.len() == 3 { 2 } else { 3 };
    let scalar_spec = parse_scalar_type_spec(parts[scalar_idx].trim()).ok_or_else(|| {
        format!(
            "line {}: unsupported csum scalar type '{}' (expected int8/int16/int32/int64/intptr)",
            line_no,
            parts[scalar_idx].trim()
        )
    })?;
    if scalar_spec.bitfield_bits.is_some() {
        return Err(format!(
            "line {}: csum scalar type must not be a bitfield",
            line_no
        ));
    }
    Ok(ArgType::Const {
        size: scalar_spec.size,
        values: vec![0],
        range: None,
        endian: scalar_spec.endian,
        allow_any: false,
        bitfield_bits: None,
    })
}

fn parse_length_target(
    text: &str,
    arg_names: &HashMap<String, usize>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    line_no: usize,
    ctx: &ParseArgContext,
    label: &str,
) -> Result<LengthTarget, String> {
    let segments = text.split(':').map(str::trim).collect::<Vec<_>>();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(format!("line {}: {} target is malformed", line_no, label));
    }

    if segments[0] == "syscall" {
        if segments.len() < 2 {
            return Err(format!(
                "line {}: {} target must use syscall:arg_name syntax",
                line_no, label
            ));
        }
        return Ok(LengthTarget {
            root: LengthTargetRoot::Arg(segments[1].to_string()),
            fields: segments[2..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    let mut parent_hops = 0usize;
    while segments.get(parent_hops) == Some(&"parent") {
        parent_hops += 1;
    }
    if parent_hops > 0 {
        if !ctx.allow_parent_len {
            return Err(format!(
                "line {}: {} target may not use parent here",
                line_no, label
            ));
        }
        return Ok(LengthTarget {
            root: LengthTargetRoot::Parent(parent_hops),
            fields: segments[parent_hops..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    let first = segments[0];
    if arg_names.contains_key(first) {
        return Ok(LengthTarget {
            root: LengthTargetRoot::Arg(first.to_string()),
            fields: segments[1..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    if ctx
        .field_names()
        .is_some_and(|field_names| field_names.contains_key(first))
    {
        return Ok(LengthTarget {
            root: LengthTargetRoot::Current,
            fields: segments
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    if ctx.current_type_name() == Some(first) {
        return Ok(LengthTarget {
            root: LengthTargetRoot::Type(first.to_string()),
            fields: segments[1..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    if types.contains_key(first) || templates.contains_key(first) {
        return Ok(LengthTarget {
            root: LengthTargetRoot::Type(first.to_string()),
            fields: segments[1..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    if is_identifier_like(first) && (segments.len() > 1 || ctx.current_type_name().is_some()) {
        return Ok(LengthTarget {
            root: LengthTargetRoot::Type(first.to_string()),
            fields: segments[1..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    Err(format!(
        "line {}: unknown {} target root '{}'",
        line_no, label, first
    ))
}

fn expr_references_unavailable_const(text: &str, consts: &HashMap<String, u64>) -> bool {
    split_top_level(text, '|').into_iter().any(|part| {
        let part = part.trim();
        is_identifier_like(part) && looks_like_const_name(part) && !consts.contains_key(part)
    })
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
    if let Some(value) = parse_char_literal(text, line_no)? {
        return Ok(value);
    }

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

fn parse_char_literal(text: &str, line_no: usize) -> Result<Option<u64>, String> {
    if !(text.starts_with('\'') && text.ends_with('\'')) || text.len() < 3 {
        return Ok(None);
    }

    let inner = &text[1..text.len() - 1];
    let value = if let Some(escaped) = inner.strip_prefix('\\') {
        match escaped {
            "0" => 0,
            "n" => b'\n',
            "r" => b'\r',
            "t" => b'\t',
            "\\" => b'\\',
            "'" => b'\'',
            _ if escaped.len() == 3 && escaped.starts_with('x') => {
                u8::from_str_radix(&escaped[1..], 16)
                    .map_err(|_| format!("line {}: invalid char literal '{}'", line_no, text))?
            }
            _ => return Err(format!("line {}: invalid char literal '{}'", line_no, text)),
        }
    } else {
        let mut chars = inner.chars();
        let Some(ch) = chars.next() else {
            return Err(format!("line {}: invalid char literal '{}'", line_no, text));
        };
        if chars.next().is_some() {
            return Err(format!("line {}: invalid char literal '{}'", line_no, text));
        }
        if !ch.is_ascii() {
            return Err(format!("line {}: invalid char literal '{}'", line_no, text));
        }
        ch as u8
    };

    Ok(Some(value as u64))
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

fn is_string_literal(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('`') && text.ends_with('`') && text.len() >= 2)
}

fn parse_string_literal(text: &str, line_no: usize) -> Result<Vec<u8>, String> {
    if text.starts_with('`') && text.ends_with('`') {
        let inner = &text[1..text.len() - 1];
        if inner.len() % 2 != 0 {
            return Err(format!(
                "line {}: invalid raw byte literal {}: expected an even number of hex digits",
                line_no, text
            ));
        }
        let mut bytes = Vec::with_capacity(inner.len() / 2);
        let mut idx = 0;
        while idx < inner.len() {
            let next = idx + 2;
            let byte = u8::from_str_radix(&inner[idx..next], 16).map_err(|_| {
                format!(
                    "line {}: invalid raw byte literal {}: expected hexadecimal digits",
                    line_no, text
                )
            })?;
            bytes.push(byte);
            idx = next;
        }
        return Ok(bytes);
    }

    serde_json::from_str::<String>(text)
        .map(|value| value.into_bytes())
        .map_err(|err| format!("line {}: invalid string literal {}: {}", line_no, text, err))
}

fn parse_scalar_type_spec(text: &str) -> Option<ScalarTypeSpec> {
    let (base, bitfield_bits) = match text.rsplit_once(':') {
        Some((base, bits)) if !base.is_empty() => {
            let bits = bits.parse::<u8>().ok()?;
            (base, Some(bits))
        }
        _ => (text, None),
    };

    let (size, endian) = match base {
        "int8" => (1, ScalarEndian::Native),
        "int16" => (2, ScalarEndian::Native),
        "int32" => (4, ScalarEndian::Native),
        "int64" | "intptr" => (8, ScalarEndian::Native),
        "int16be" => (2, ScalarEndian::Big),
        "int32be" => (4, ScalarEndian::Big),
        "int64be" => (8, ScalarEndian::Big),
        _ => return None,
    };
    if bitfield_bits.is_some_and(|bits| bits == 0 || usize::from(bits) > size * 8) {
        return None;
    }
    Some(ScalarTypeSpec {
        size,
        endian,
        bitfield_bits,
    })
}

fn scalar_integer_spec(text: &str) -> Option<(usize, ScalarEndian)> {
    parse_scalar_type_spec(text).map(|spec| (spec.size, spec.endian))
}

fn is_builtin_bracketed_type_name(text: &str) -> bool {
    matches!(
        text,
        "const"
            | "flags"
            | "buffer"
            | "string"
            | "stringnoz"
            | "array"
            | "ptr"
            | "ptr64"
            | "vma"
            | "len"
            | "bytesize"
            | "offsetof"
    )
}

fn parse_template_head(text: &str, line_no: usize) -> Result<(String, Vec<String>), String> {
    let text = text.trim();
    if let Some((name, inner)) = split_type_invocation(text) {
        let params = split_type_parts(inner)
            .into_iter()
            .map(str::trim)
            .map(str::to_string)
            .collect::<Vec<_>>();
        if params.iter().any(|param| param.is_empty()) {
            return Err(format!(
                "line {}: template parameter list contains an empty parameter",
                line_no
            ));
        }
        return Ok((name.to_string(), params));
    }
    Ok((text.to_string(), Vec::new()))
}

fn split_type_definition_head_and_body(text: &str) -> Option<(&str, &str)> {
    let mut bracket_depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ if ch.is_whitespace() && bracket_depth == 0 => {
                let head = text[..idx].trim();
                let body = text[idx..].trim();
                if !head.is_empty() && !body.is_empty() {
                    return Some((head, body));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

fn type_text_references_type_name(text: &str, type_name: &str) -> bool {
    let mut token_start = None;
    for (idx, ch) in text.char_indices() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            token_start.get_or_insert(idx);
            continue;
        }
        if let Some(start) = token_start.take() {
            if &text[start..idx] == type_name {
                return true;
            }
        }
    }
    token_start.is_some_and(|start| &text[start..] == type_name)
}

fn parse_scalar_range_arg(
    text: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    line_no: usize,
) -> Result<Option<ArgType>, String> {
    let Some(open) = text.find('[') else {
        return Ok(None);
    };
    if !text.ends_with(']') {
        return Ok(None);
    }
    let scalar_name = text[..open].trim();
    let Some(spec) = parse_scalar_type_spec(scalar_name) else {
        return Ok(None);
    };
    let inner = &text[open + 1..text.len() - 1];
    let parts = split_type_parts(inner);
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!(
            "line {}: scalar qualifier must use [value], [min:max], or [min:max, step|opt] syntax",
            line_no
        ));
    }
    let primary = parts[0].trim();
    if primary.is_empty() {
        return Err(format!("line {}: scalar qualifier is empty", line_no));
    }
    let qualifier = parts
        .get(1)
        .map(|part| part.trim())
        .filter(|part| !part.is_empty());

    if let Some(set) = const_sets.get(primary).or_else(|| flag_sets.get(primary)) {
        if !matches!(qualifier, None | Some("opt")) {
            return Err(format!(
                "line {}: scalar value-set qualifier only supports optional ', opt'",
                line_no
            ));
        }
        return Ok(Some(ArgType::Const {
            size: spec.size,
            values: set.values.clone(),
            range: None,
            endian: spec.endian,
            allow_any: false,
            bitfield_bits: spec.bitfield_bits,
        }));
    }

    if let Some((min, max)) = primary.split_once(':') {
        if expr_references_unavailable_const(min, consts)
            || expr_references_unavailable_const(max, consts)
            || qualifier.is_some_and(|value| expr_references_unavailable_const(value, consts))
        {
            return Ok(Some(ArgType::Const {
                size: spec.size,
                values: Vec::new(),
                range: None,
                endian: spec.endian,
                allow_any: false,
                bitfield_bits: spec.bitfield_bits,
            }));
        }
        let min = parse_expr(min.trim(), consts, line_no)?;
        let max = parse_expr(max.trim(), consts, line_no)?;
        if let Some(qualifier) = qualifier {
            if qualifier != "opt" {
                let _ = parse_expr(qualifier, consts, line_no)?;
            }
        }
        return Ok(Some(ArgType::Const {
            size: spec.size,
            values: Vec::new(),
            range: Some((min, max)),
            endian: spec.endian,
            allow_any: false,
            bitfield_bits: spec.bitfield_bits,
        }));
    }

    if !matches!(qualifier, None | Some("opt")) {
        return Err(format!(
            "line {}: scalar exact-value qualifier only supports optional ', opt'",
            line_no
        ));
    }
    if expr_references_unavailable_const(primary, consts) {
        return Ok(Some(ArgType::Const {
            size: spec.size,
            values: Vec::new(),
            range: None,
            endian: spec.endian,
            allow_any: false,
            bitfield_bits: spec.bitfield_bits,
        }));
    }
    let value = parse_expr(primary, consts, line_no)?;
    Ok(Some(ArgType::Const {
        size: spec.size,
        values: vec![value],
        range: None,
        endian: spec.endian,
        allow_any: false,
        bitfield_bits: spec.bitfield_bits,
    }))
}

fn bracketed<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(prefix)?;
    let rest = rest.strip_prefix('[')?;
    rest.strip_suffix(']')
}

fn bracketed_with_numeric_suffix<'a>(text: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    if let Some(inner) = bracketed(text, prefix) {
        return Some((1, inner));
    }
    let rest = text.strip_prefix(prefix)?;
    let open = rest.find('[')?;
    let suffix = &rest[..open];
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let scale = suffix.parse::<usize>().ok()?;
    let inner = text.get(prefix.len() + suffix.len() + 1..text.len().checked_sub(1)?)?;
    Some((scale, inner))
}

fn split_type_invocation<'a>(text: &'a str) -> Option<(&'a str, &'a str)> {
    if !text.ends_with(']') {
        return None;
    }
    let mut depth = 0usize;
    let mut open = None;
    for (idx, ch) in text.char_indices() {
        match ch {
            '[' => {
                if depth == 0 {
                    open = Some(idx);
                }
                depth += 1;
            }
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && idx + 1 != text.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    let open = open?;
    let name = text[..open].trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name, &text[open + 1..text.len() - 1]))
}

fn substitute_template_params(text: &str, bindings: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            flush_template_token(&mut token, bindings, &mut out);
            in_string = true;
            out.push(ch);
            continue;
        }

        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }

        flush_template_token(&mut token, bindings, &mut out);
        out.push(ch);
    }

    flush_template_token(&mut token, bindings, &mut out);
    out
}

fn flush_template_token(token: &mut String, bindings: &HashMap<String, String>, out: &mut String) {
    if token.is_empty() {
        return;
    }
    if let Some(replacement) = bindings.get(token) {
        out.push_str(replacement);
    } else {
        out.push_str(token);
    }
    token.clear();
}

fn parse_syscall_args(
    args_str: &str,
    consts: &HashMap<String, u64>,
    const_sets: &HashMap<String, ValueSet>,
    flag_sets: &HashMap<String, ValueSet>,
    string_sets: &HashMap<String, Vec<Vec<u8>>>,
    types: &HashMap<String, ArgType>,
    templates: &HashMap<String, TypeTemplate>,
    resources: &HashMap<String, ResourceDesc>,
    line_no: usize,
) -> Result<(Vec<ArgType>, Vec<String>), String> {
    if args_str.trim().is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let raw_args = split_top_level(args_str, ',');
    let mut arg_names = HashMap::new();
    for (idx, raw_arg) in raw_args.iter().enumerate() {
        let (arg_name, _) = split_named_arg(raw_arg);
        if let Some(name) = arg_name {
            arg_names.insert(name, idx);
        }
    }
    let mut args = Vec::new();
    let mut ordered_names = Vec::new();
    for raw_arg in raw_args {
        let (arg_name, arg_text) = split_named_arg(raw_arg);
        let arg_type = parse_arg(
            arg_text,
            consts,
            const_sets,
            flag_sets,
            string_sets,
            &arg_names,
            types,
            templates,
            resources,
            line_no,
            ParseArgContext::default(),
        )?;
        if let Some(name) = arg_name {
            ordered_names.push(name);
        } else {
            ordered_names.push(String::new());
        }
        args.push(arg_type);
    }
    Ok((args, ordered_names))
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
    let mut in_string = false;
    let mut in_char = false;
    let mut escape = false;

    for (idx, ch) in text.char_indices() {
        if in_string || in_char {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => {
                    escape = true;
                }
                '"' if in_string => {
                    in_string = false;
                }
                '\'' if in_char => {
                    in_char = false;
                }
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '\'' => in_char = true,
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth = depth.saturating_sub(1),
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
        assert_eq!(descs.len(), 24);
        assert_eq!(descs[0].name, "openat");
        assert_eq!(descs[0].id, 4304);
        assert!(descs
            .iter()
            .any(|desc| desc.name == "writev" && desc.id == 8027));
        assert!(descs
            .iter()
            .any(|desc| desc.name == "sendmsg" && desc.id == 5682));
        assert!(descs
            .iter()
            .any(|desc| desc.name == "sendmmsg" && desc.id == 5673));
        assert!(descs
            .iter()
            .any(|desc| desc.name == "recvmsg" && desc.id == 5530));
        assert!(descs.iter().any(|desc| desc.name == "getpid"));
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
            define HELPER_TIMEOUT 200
            syscall eventfd2@1 -> fd(const[4; 0], const[4; 0]) (automatic_helper, no_generate, no_minimize)
            close(fd fd) (disabled, ignore_return, snapshot, breaks_returns, no_squash, remote_cover, kfuzz_test, timeout[HELPER_TIMEOUT], prog_timeout[3000], fsck["fsck.ext4 -n"])
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        assert!(descs[0].attrs.automatic_helper);
        assert!(descs[0].attrs.no_generate);
        assert!(descs[0].attrs.no_minimize);
        assert!(!descs[0].attrs.disabled);
        assert!(descs[1].attrs.disabled);
        assert!(descs[1].attrs.ignore_return);
        assert!(descs[1].attrs.snapshot);
        assert!(descs[1].attrs.breaks_returns);
        assert!(descs[1].attrs.no_squash);
        assert!(descs[1].attrs.remote_cover);
        assert!(descs[1].attrs.kfuzz_test);
        assert_eq!(descs[1].attrs.timeout_ms, Some(200));
        assert_eq!(descs[1].attrs.prog_timeout_ms, Some(3000));
        assert_eq!(descs[1].attrs.fsck_command.as_deref(), Some("fsck.ext4 -n"));
        assert!(!descs[1].attrs.no_generate);
    }

    #[test]
    fn parses_compressed_image_builtin_arguments() {
        let descs = parse_syscall_descs(
            r#"
                syscall mount_like@1 -> int(size len[img], img ptr[in, compressed_image]) (fsck["fsck.xfs -n"])
            "#,
        )
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, dir, .. } => {
                assert_eq!(*dir, PtrDir::In);
                match inner.as_ref() {
                    ArgType::Buffer { min_size, dir, .. } => {
                        assert_eq!(*min_size, 0);
                        assert_eq!(*dir, BufferDir::Plain);
                    }
                    other => panic!("unexpected compressed_image arg: {:?}", other),
                }
            }
            other => panic!("unexpected img arg: {:?}", other),
        }
        assert_eq!(descs[0].attrs.fsck_command.as_deref(), Some("fsck.xfs -n"));
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
                    ArgType::Array {
                        inner,
                        min_len,
                        max_len,
                    } => {
                        assert_eq!((*min_len, *max_len), (2, 2));
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
                    ArgType::Struct { fields, size, .. } => {
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
    fn path_loading_assigns_synthetic_ids_to_unknown_bare_syscalls() {
        let dir = temp_description_dir("synthetic-syscall-ids");
        fs::write(
            dir.join("sys.txt"),
            r#"
                resource fd[int32]: -1
                syz_totally_fake(text ptr[in, text[target]]) (disabled)
                made_up_call(fd fd)
                close(fd fd)
            "#,
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).expect("path loading should assign IDs");
        assert_eq!(descs[0].name, "syz_totally_fake");
        assert_eq!(descs[0].id, 0);
        assert_eq!(descs[1].name, "made_up_call");
        assert_eq!(descs[1].id, 1);
        assert_eq!(descs[2].name, "close");
        assert_eq!(descs[2].id, 248);
    }

    #[test]
    fn path_loading_uses_executor_ids_for_known_linux_helpers() {
        let dir = temp_description_dir("known-helper-ids");
        fs::write(
            dir.join("sys.txt"),
            r#"
                resource fd[4] = -1, 0, 1, 2, 3, 4
                resource pid[int32]
                syz_execute_func(text ptr[in, text[target]]) (disabled)
                syz_clone(flags int64, stack buffer[in], stack_len len[stack], parentid ptr[out, int32], childtid ptr[out, int32], tls buffer[in]) pid
                syz_mount_image$ext4(fs ptr[in, string["ext4"]], dir ptr[in, filename], flags int64, opts ptr[in, string], chdir bool8, size len[img], img ptr[in, compressed_image]) fd
            "#,
        )
        .unwrap();

        let descs =
            parse_syscall_descs_from_path(&dir).expect("known helpers should resolve executor IDs");
        let ids: HashMap<_, _> = descs
            .iter()
            .map(|desc| (desc.name.as_str(), desc.id))
            .collect();

        assert_eq!(ids.get("syz_execute_func"), Some(&7321));
        assert_eq!(ids.get("syz_clone"), Some(&7316));
        assert_eq!(ids.get("syz_mount_image$ext4"), Some(&7434));
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
                    ArgType::Len {
                        target, size, kind, ..
                    } => {
                        assert_eq!(
                            (target, *size, *kind),
                            (
                                &LengthTarget {
                                    root: LengthTargetRoot::Arg("peer".into()),
                                    fields: Vec::new(),
                                },
                                4,
                                LengthKind::Auto,
                            )
                        );
                    }
                    other => panic!("unexpected accept peerlen inner type: {:?}", other),
                }
            }
            other => panic!("unexpected accept peerlen arg: {:?}", other),
        }
        match &descs[1].args[2] {
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("addr".into()),
                            fields: Vec::new(),
                        },
                        4,
                        LengthKind::Auto,
                    )
                )
            }
            other => panic!("unexpected bind addrlen arg: {:?}", other),
        }
    }

    #[test]
    fn parses_forward_syscall_length_targets() {
        let descs = parse_syscall_descs(
            r#"
                type fd_set buffer[128:128]
                syscall select_like@1 -> int(n len[inp, int32], inp ptr[inout, fd_set], outp ptr[inout, fd_set, opt])
            "#,
        )
        .expect("forward syscall len targets should parse");

        match &descs[0].args[0] {
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("inp".into()),
                            fields: Vec::new(),
                        },
                        4,
                        LengthKind::Auto,
                    )
                );
            }
            other => panic!("unexpected select_like n arg: {:?}", other),
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
        assert_eq!(descs[0].id, 7192);
        assert_eq!(descs[1].name, "bind$inet");
        assert_eq!(descs[1].id, 102);
        match &descs[0].args[0] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
                ..
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
                ..
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
                    ArgType::Struct {
                        fields,
                        size,
                        packed,
                        align,
                        ..
                    } => {
                        assert_eq!(*size, 16);
                        assert!(!packed);
                        assert_eq!(*align, Some(8));
                        assert_eq!(fields.len(), 3);
                        match &fields[0] {
                            ArgType::Const {
                                size,
                                values,
                                range,
                                endian,
                                ..
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
                                ..
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
                                ..
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
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("addr".into()),
                            fields: Vec::new(),
                        },
                        8,
                        LengthKind::Auto,
                    )
                )
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
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("buf".into()),
                            fields: Vec::new(),
                        },
                        4,
                        LengthKind::Auto,
                    )
                );
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
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("buf".into()),
                            fields: Vec::new(),
                        },
                        4,
                        LengthKind::Bytes,
                    )
                );
            }
            other => panic!("unexpected recvfrom len arg: {:?}", other),
        }
    }

    #[test]
    fn parses_bitsize_length_forms() {
        let input = r#"
            type msr_bitmap {
                bitmap array[int8, 16]
                bits bitsize[bitmap, int32]
            } [packed]
            syscall use_bits@1 -> int(arg ptr[in, msr_bitmap], len bitsize[arg, int64])
        "#;
        let descs = parse_syscall_descs(input).expect("bitsize forms should parse");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => match &fields[1] {
                    ArgType::Len {
                        target,
                        size,
                        kind,
                        scale,
                        ..
                    } => {
                        assert_eq!(
                            (target, *size, *kind, *scale),
                            (
                                &LengthTarget {
                                    root: LengthTargetRoot::Current,
                                    fields: vec!["bitmap".into()],
                                },
                                4,
                                LengthKind::Bytes,
                                8,
                            )
                        );
                    }
                    other => panic!("unexpected bits field: {:?}", other),
                },
                other => panic!("unexpected msr_bitmap type: {:?}", other),
            },
            other => panic!("unexpected msr_bitmap arg: {:?}", other),
        }

        match &descs[0].args[1] {
            ArgType::Len {
                target,
                size,
                kind,
                scale,
                ..
            } => {
                assert_eq!(
                    (target, *size, *kind, *scale),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("arg".into()),
                            fields: Vec::new(),
                        },
                        8,
                        LengthKind::Bytes,
                        8,
                    )
                );
            }
            other => panic!("unexpected top-level bitsize arg: {:?}", other),
        }
    }

    #[test]
    fn parses_csum_forms_as_checksum_placeholders() {
        let input = r#"
            type ipv4_header_only {
                csum csum[parent, inet, int16be]
            } [packed]
            type tcp_like {
                csum csum[parent, pseudo, 6, int16be]
            } [packed]
            syscall use_csum@1 -> int(ip ptr[in, ipv4_header_only], tcp ptr[in, tcp_like])
        "#;
        let descs = parse_syscall_descs(input).expect("csum forms should parse");

        for arg in &descs[0].args {
            match arg {
                ArgType::Ptr { inner, .. } => match inner.as_ref() {
                    ArgType::Struct { fields, .. } => {
                        assert!(matches!(
                            &fields[0],
                            ArgType::Const {
                                size: 2,
                                values,
                                endian: ScalarEndian::Big,
                                ..
                            } if values == &vec![0]
                        ));
                    }
                    other => panic!("unexpected csum wrapper type: {:?}", other),
                },
                other => panic!("unexpected csum syscall arg: {:?}", other),
            }
        }
    }

    #[test]
    fn parses_glob_patterns_as_filenames() {
        let input = r#"
            resource fd[4] = -1, 0
            openat$sysfs(fd const[AT_FDCWD], dir ptr[in, glob["/sys/**/*:-/sys/power/state"]], flags int32, mode int32) fd
        "#;
        let descs = parse_syscall_descs(input).expect("glob patterns should parse");

        match &descs[0].args[1] {
            ArgType::Ptr { inner, dir, .. } => {
                assert_eq!(*dir, PtrDir::In);
                assert!(matches!(inner.as_ref(), ArgType::Filename));
            }
            other => panic!("unexpected glob arg type: {:?}", other),
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
    fn parses_scalar_typed_resource_roots() {
        let input = r#"
            resource fd[int32] = -1
            resource sock[fd]
            syscall socket@1 -> sock(const[4; 2], const[4; 1], const[4; 0])
            syscall close@2 -> int(fd)
        "#;
        let descs = parse_syscall_descs(input).unwrap();

        match &descs[0].ret {
            ReturnType::Resource(resource) => {
                assert_eq!(resource.kind, "sock");
                assert_eq!(resource.size, 4);
                assert_eq!(resource.lineage, vec!["fd", "sock"]);
            }
            other => panic!("unexpected socket return type: {:?}", other),
        }
        match &descs[1].args[0] {
            ArgType::Resource(resource) => {
                assert_eq!(resource.kind, "fd");
                assert_eq!(resource.size, 4);
                assert_eq!(resource.lineage, vec!["fd"]);
            }
            other => panic!("unexpected close arg type: {:?}", other),
        }
    }

    #[test]
    fn parses_builtin_alignment_and_size_constants() {
        let descs = parse_syscall_descs(
            r#"
                type alignptr[T] {
                    v T
                } [align[PTR_SIZE]]
                type page_buf {
                    data array[int8, 16]
                } [size[PAGE_SIZE]]
                syscall wrap@1 -> int(arg alignptr[int32], buf page_buf)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { align, size, .. } => {
                assert_eq!(*align, Some(TARGET_PTR_SIZE as usize));
                assert_eq!(*size, TARGET_PTR_SIZE as usize);
            }
            other => panic!("unexpected alignptr arg: {:?}", other),
        }

        match &descs[0].args[1] {
            ArgType::Struct { size, .. } => {
                assert_eq!(*size as u64, crate::program::PAGE_SIZE);
            }
            other => panic!("unexpected page_buf arg: {:?}", other),
        }
    }

    #[test]
    fn parses_builtin_aliases_and_templates() {
        let descs = parse_syscall_descs(
            r#"
                resource fd[int32] = -1
                syscall splice_like@1 -> int(pos fileoff, off ptr[in, fileoff[int64]], enabled bool8, maybe optional[int32])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Const { size, range, .. } => {
                assert_eq!(*size, 8);
                assert_eq!(*range, None);
            }
            other => panic!("unexpected plain fileoff arg: {:?}", other),
        }

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Const { size, range, .. } => {
                    assert_eq!(*size, 8);
                    assert_eq!(*range, None);
                }
                other => panic!("unexpected fileoff inner arg: {:?}", other),
            },
            other => panic!("unexpected fileoff arg: {:?}", other),
        }

        match &descs[0].args[2] {
            ArgType::Const { size, range, .. } => {
                assert_eq!(*size, 1);
                assert_eq!(*range, Some((0, 1)));
            }
            other => panic!("unexpected bool8 arg: {:?}", other),
        }

        match &descs[0].args[3] {
            ArgType::Union {
                field_names,
                varlen,
                fields,
                ..
            } => {
                assert_eq!(field_names, &vec!["val".to_string(), "void".to_string()]);
                assert!(*varlen);
                assert_eq!(fields.len(), 2);
            }
            other => panic!("unexpected optional arg: {:?}", other),
        }
    }

    #[test]
    fn structs_can_use_later_implicit_flag_sets() {
        let descs = parse_syscall_descs(
            r#"
                later_struct {
                    flags flags[later_flags, int32]
                }
                syscall use_later@1 -> int(arg later_struct)
                later_flags = 1, 2
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Const { size, values, .. } => {
                    assert_eq!(*size, 4);
                    assert_eq!(values, &vec![1, 2]);
                }
                other => panic!("unexpected later_flags field: {:?}", other),
            },
            other => panic!("unexpected later_struct arg: {:?}", other),
        }
    }

    #[test]
    fn implicit_value_sets_can_reference_later_sets() {
        let descs = parse_syscall_descs(
            r#"
                later_holder {
                    mode flags[mknod_mode, int32]
                }
                syscall use_modes@1 -> int(arg later_holder)
                mknod_mode = 1, open_mode
                open_mode = 2, 4
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Const { size, values, .. } => {
                    assert_eq!(*size, 4);
                    assert_eq!(values, &vec![1, 2, 4]);
                }
                other => panic!("unexpected mknod_mode field: {:?}", other),
            },
            other => panic!("unexpected later_holder arg: {:?}", other),
        }
    }

    #[test]
    fn anonymous_value_definitions_are_ignored() {
        parse_syscall_descs(
            r#"
                _ = UNKNOWN_CONST, ALSO_UNKNOWN
                syscall noop@1 -> int()
            "#,
        )
        .unwrap();
    }

    #[test]
    fn implicit_string_sets_can_reference_other_string_sets() {
        let descs = parse_syscall_descs(
            r#"
                extra_paths = "./cgroup.cpu/cgroup.clonechildren"
                all_paths = extra_paths, "/sys/fs/cgroup"
                syscall open_paths@1 -> int(path ptr[in, string[all_paths]])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String { values, .. } => {
                    assert_eq!(values.len(), 2);
                    assert_eq!(values[0], b"./cgroup.cpu/cgroup.clonechildren");
                    assert_eq!(values[1], b"/sys/fs/cgroup");
                }
                other => panic!("unexpected string arg: {:?}", other),
            },
            other => panic!("unexpected ptr arg: {:?}", other),
        }
    }

    #[test]
    fn string_sets_preserve_commas_inside_string_literals() {
        let descs = parse_syscall_descs(
            r#"
                usb_paths = "/sys/bus/usb/drivers/RobotFuzz Open Source InterFace, Inc./bind"
                syscall open_usb@1 -> int(path ptr[in, string[usb_paths]])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String { values, .. } => {
                    assert_eq!(values.len(), 1);
                    assert_eq!(
                        values[0],
                        b"/sys/bus/usb/drivers/RobotFuzz Open Source InterFace, Inc./bind"
                    );
                }
                other => panic!("unexpected usb string arg: {:?}", other),
            },
            other => panic!("unexpected usb ptr arg: {:?}", other),
        }
    }

    #[test]
    fn string_sets_preserve_hashes_inside_string_literals() {
        let descs = parse_syscall_descs(
            r#"
                proc_paths = "/proc/asound/card1/cable#0"
                syscall open_proc@1 -> int(path ptr[in, string[proc_paths]])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String { values, .. } => {
                    assert_eq!(values.len(), 1);
                    assert_eq!(values[0], b"/proc/asound/card1/cable#0");
                }
                other => panic!("unexpected proc string arg: {:?}", other),
            },
            other => panic!("unexpected proc ptr arg: {:?}", other),
        }
    }

    #[test]
    fn parses_char_literals_in_value_sets_and_consts() {
        let descs = parse_syscall_descs(
            r#"
                letters = 'P', 'O', 'C', 'F'
                syscall use_chars@1 -> int(a flags[letters, int8], b const[':', int8], c int8['0':'9'])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 1);
                assert_eq!(
                    values,
                    &vec![b'P' as u64, b'O' as u64, b'C' as u64, b'F' as u64]
                );
            }
            other => panic!("unexpected flags arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 1);
                assert_eq!(values, &vec![b':' as u64]);
            }
            other => panic!("unexpected const char arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { size, range, .. } => {
                assert_eq!(*size, 1);
                assert_eq!(*range, Some((b'0' as u64, b'9' as u64)));
            }
            other => panic!("unexpected ranged char arg: {:?}", other),
        }
    }

    #[test]
    fn parses_scalar_exact_ranges_steps_and_named_sets() {
        let descs = parse_syscall_descs(
            r#"
                families = 1, 2, 4
                syscall use_scalars@1 -> int(a int32[7], b int32[1:9, 2], c int8[families], d int16be[0:3, opt])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
                ..
            } => {
                assert_eq!(*size, 4);
                assert_eq!(values, &vec![7]);
                assert_eq!(*range, None);
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected scalar exact arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
                ..
            } => {
                assert_eq!(*size, 4);
                assert!(values.is_empty());
                assert_eq!(*range, Some((1, 9)));
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected scalar stepped range arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
                ..
            } => {
                assert_eq!(*size, 1);
                assert_eq!(values, &vec![1, 2, 4]);
                assert_eq!(*range, None);
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected scalar set arg: {:?}", other),
        }
        match &descs[0].args[3] {
            ArgType::Const {
                size,
                values,
                range,
                endian,
                ..
            } => {
                assert_eq!(*size, 2);
                assert!(values.is_empty());
                assert_eq!(*range, Some((0, 3)));
                assert_eq!(*endian, ScalarEndian::Big);
            }
            other => panic!("unexpected optional ranged scalar arg: {:?}", other),
        }
    }

    #[test]
    fn implicit_numeric_sets_skip_missing_arch_specific_constants() {
        let dir = temp_description_dir("implicit-set-missing-consts");
        fs::write(
            dir.join("sys.txt.const"),
            concat!(
                "arches = amd64\n",
                "CONST_PRESENT = 7\n",
                "CONST_MISSING = amd64:???\n",
                "MixedCaseMissing = amd64:???\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("sys.txt"),
            concat!(
                "vals = CONST_PRESENT, CONST_MISSING, MixedCaseMissing\n",
                "syscall use_vals@1 -> int(arg flags[vals, int32])\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 4);
                assert_eq!(values, &vec![7]);
            }
            other => panic!("unexpected filtered flag arg: {:?}", other),
        }
    }

    #[test]
    fn arch_missing_const_constraints_become_unavailable_scalars() {
        let dir = temp_description_dir("missing-const-constraints");
        fs::write(
            dir.join("sys.txt.const"),
            concat!("arches = amd64\n", "MISSING_ARCH_CONST = amd64:???\n",),
        )
        .unwrap();
        fs::write(
            dir.join("sys.txt"),
            concat!(
                "holder {\n",
                "    exact const[MISSING_ARCH_CONST, int32]\n",
                "    ranged int32[MISSING_ARCH_CONST:7]\n",
                "}\n",
                "syscall use_holder@1 -> int(arg ptr[in, holder])\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => {
                    for field in fields {
                        match field {
                            ArgType::Const {
                                values,
                                range,
                                allow_any,
                                ..
                            } => {
                                assert!(values.is_empty());
                                assert_eq!(*range, None);
                                assert!(!allow_any);
                            }
                            other => panic!("unexpected unavailable const field: {:?}", other),
                        }
                    }
                }
                other => panic!("unexpected holder type: {:?}", other),
            },
            other => panic!("unexpected holder arg: {:?}", other),
        }
    }

    #[test]
    fn char_literals_preserve_hashes_during_comment_stripping() {
        let descs = parse_syscall_descs(
            r#"
                prefixes = '%', '#'
                syscall use_prefix@1 -> int(arg flags[prefixes, int8])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Const { size, values, .. } => {
                assert_eq!(*size, 1);
                assert_eq!(values, &vec![b'%' as u64, b'#' as u64]);
            }
            other => panic!("unexpected prefix arg: {:?}", other),
        }
    }

    #[test]
    fn parses_backtick_hex_string_literals() {
        let descs = parse_syscall_descs(
            r#"
                raw_values = `616263`, `0001ff`
                syscall use_raw@1 -> int(a stringnoz[raw_values], b stringnoz[`4142`])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::String { values, noz, .. } => {
                assert!(*noz);
                assert_eq!(values, &vec![b"abc".to_vec(), vec![0x00, 0x01, 0xff]]);
            }
            other => panic!("unexpected raw set arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::String { values, noz, .. } => {
                assert!(*noz);
                assert_eq!(values, &vec![b"AB".to_vec()]);
            }
            other => panic!("unexpected raw literal arg: {:?}", other),
        }
    }

    #[test]
    fn block_fields_ignore_trailing_condition_attrs() {
        let descs = parse_syscall_descs(
            r#"
                cond_struct {
                    pad const[0, int32] (if[value[flags] == 0])
                }
                syscall use_cond@1 -> int(arg cond_struct)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Const { size, values, .. } => {
                    assert_eq!(*size, 4);
                    assert_eq!(values, &vec![0]);
                }
                other => panic!("unexpected conditioned field: {:?}", other),
            },
            other => panic!("unexpected conditioned struct arg: {:?}", other),
        }
    }

    #[test]
    fn structs_can_use_later_type_definitions() {
        let descs = parse_syscall_descs(
            r#"
                outer_holder {
                    inner ptr[in, later_inner, opt]
                }

                later_inner {
                    value int32
                }

                syscall use_later_type@1 -> int(arg outer_holder)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Ptr {
                    inner, optional, ..
                } => {
                    assert!(*optional);
                    match inner.as_ref() {
                        ArgType::Struct {
                            type_name, fields, ..
                        } => {
                            assert_eq!(type_name.as_deref(), Some("later_inner"));
                            assert_eq!(fields.len(), 1);
                        }
                        other => panic!("unexpected later inner ptr target: {:?}", other),
                    }
                }
                other => panic!("unexpected outer_holder field: {:?}", other),
            },
            other => panic!("unexpected outer_holder arg: {:?}", other),
        }
    }

    #[test]
    fn parses_fmt_template_as_underlying_scalar() {
        let descs = parse_syscall_descs(
            r#"
                tcp_mem_values {
                    v0 fmt[oct, int64]
                }
                syscall use_fmt@1 -> int(arg tcp_mem_values)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Const { size, range, .. } => {
                    assert_eq!(*size, 8);
                    assert_eq!(*range, None);
                }
                other => panic!("unexpected fmt field: {:?}", other),
            },
            other => panic!("unexpected fmt arg: {:?}", other),
        }
    }

    #[test]
    fn alias_templates_preserve_field_context_for_len_targets() {
        let descs = parse_syscall_descs(
            r#"
                holder {
                    num fmt[dec, len[cats, int16]]
                    cats array[int8]
                }
                syscall use_holder@1 -> int(arg ptr[in, holder], size len[arg])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => match &fields[0] {
                    ArgType::Len {
                        target, size, kind, ..
                    } => {
                        assert_eq!(*size, 2);
                        assert_eq!(*kind, LengthKind::Auto);
                        assert_eq!(target.root, LengthTargetRoot::Current);
                        assert_eq!(target.fields, vec!["cats".to_string()]);
                    }
                    other => panic!("unexpected fmt-derived field: {:?}", other),
                },
                other => panic!("unexpected holder type: {:?}", other),
            },
            other => panic!("unexpected holder arg: {:?}", other),
        }
    }

    #[test]
    fn arrays_can_use_named_const_lengths() {
        let descs = parse_syscall_descs(
            r#"
                const WORDS = 2
                sigset_t {
                    mask array[intptr, WORDS]
                }
                syscall use_sigset@1 -> int(arg sigset_t)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Array {
                    inner,
                    min_len,
                    max_len,
                } => {
                    assert_eq!((*min_len, *max_len), (2, 2));
                    match inner.as_ref() {
                        ArgType::Const { size, .. } => assert_eq!(*size, 8),
                        other => panic!("unexpected array inner: {:?}", other),
                    }
                }
                other => panic!("unexpected sigset field: {:?}", other),
            },
            other => panic!("unexpected sigset arg: {:?}", other),
        }
    }

    #[test]
    fn structs_can_retain_multiple_variable_buffer_fields() {
        let descs = parse_syscall_descs(
            r#"
                opaque_slots {
                    first   buffer[out]
                    second  buffer[in]
                }
                syscall use_opaque@1 -> int(arg opaque_slots)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, varlen, .. } => {
                assert!(*varlen);
                assert!(matches!(fields[0], ArgType::Buffer { .. }));
                assert!(matches!(fields[1], ArgType::Buffer { .. }));
            }
            other => panic!("unexpected opaque_slots arg: {:?}", other),
        }
    }

    #[test]
    fn parses_text_template_as_input_buffer() {
        let descs = parse_syscall_descs(
            r#"
                syscall exec_text@1 -> int(code ptr[in, text[target]])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, dir, .. } => {
                assert_eq!(*dir, PtrDir::In);
                match inner.as_ref() {
                    ArgType::Buffer { dir, .. } => assert_eq!(*dir, BufferDir::In),
                    other => panic!("unexpected text inner arg: {:?}", other),
                }
            }
            other => panic!("unexpected text arg: {:?}", other),
        }
    }

    #[test]
    fn parses_bitfield_scalars_as_underlying_integers() {
        let descs = parse_syscall_descs(
            r#"
                nibble_vals = 1, 2
                bitfields {
                    enabled int32:1
                    value int8:7[0:15]
                    regs flags[nibble_vals, int8:4]
                }
                syscall use_bits@1 -> int(arg bitfields)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => {
                assert!(matches!(fields[0], ArgType::Const { size: 4, .. }));
                assert!(matches!(fields[1], ArgType::Const { size: 1, .. }));
                assert!(matches!(fields[2], ArgType::Const { size: 1, .. }));
            }
            other => panic!("unexpected bitfields arg: {:?}", other),
        }
    }

    #[test]
    fn resources_and_scalars_accept_opt_suffix() {
        let descs = parse_syscall_descs(
            r#"
                resource fd[int32] = -1
                syscall use_opt@1 -> int(a fd[opt], b int16be[opt])
            "#,
        )
        .unwrap();

        assert!(matches!(descs[0].args[0], ArgType::OptionalResource(_)));
        assert!(matches!(descs[0].args[1], ArgType::Const { size: 2, .. }));
    }

    #[test]
    fn parses_field_level_out_directions_on_structs() {
        let descs = parse_syscall_descs(
            r#"
                resource handle[int32] = -1
                type alloc_arg {
                    flags int32
                    out_id handle (out)
                }
                syscall alloc@1 -> int(arg ptr[in, alloc_arg])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { field_dirs, .. } => {
                    assert_eq!(field_dirs, &vec![None, Some(PtrDir::Out)]);
                }
                other => panic!("unexpected alloc arg payload: {:?}", other),
            },
            other => panic!("unexpected alloc arg: {:?}", other),
        }
    }

    #[test]
    fn parses_auto_aligner_template_with_paramized_align_attr() {
        let descs = parse_syscall_descs(
            r#"
                type auto_aligner[N] {
                    void void
                } [align[N]]

                holder {
                    pad auto_aligner[8]
                    value int32
                }

                syscall use_align@1 -> int(arg holder)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Struct { align, size, .. } => {
                    assert_eq!(*align, Some(8));
                    assert_eq!(*size, 0);
                }
                other => panic!("unexpected auto_aligner field: {:?}", other),
            },
            other => panic!("unexpected holder arg: {:?}", other),
        }
    }

    #[test]
    fn structs_can_use_later_template_alias_definitions() {
        let descs = parse_syscall_descs(
            r#"
                holder {
                    attr nlattr[int32]
                }

                type nlattr[PAYLOAD] {
                    payload PAYLOAD
                } [packed]

                syscall use_later_template@1 -> int(arg holder)
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Struct { fields, packed, .. } => {
                    assert!(*packed);
                    assert!(matches!(fields[0], ArgType::Const { size: 4, .. }));
                }
                other => panic!("unexpected attr field: {:?}", other),
            },
            other => panic!("unexpected syscall arg: {:?}", other),
        }
    }

    #[test]
    fn packed_structs_can_preserve_zero_const_suffix_after_var_array() {
        let descs = parse_syscall_descs(
            r#"
                argv_array {
                    args array[ptr[in, string]]
                    z const[0, intptr]
                } [packed]

                syscall exec_like@1 -> int(argv ptr[in, argv_array])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct {
                    fields,
                    field_names,
                    varlen,
                    packed,
                    ..
                } => {
                    assert_eq!(field_names, &vec!["args", "z"]);
                    assert_eq!(fields.len(), 2);
                    assert!(*varlen);
                    assert!(*packed);
                    assert!(matches!(fields[0], ArgType::Array { .. }));
                    assert!(matches!(fields[1], ArgType::Const { range: None, .. }));
                }
                other => panic!("unexpected argv inner: {:?}", other),
            },
            other => panic!("unexpected argv arg: {:?}", other),
        }
    }

    #[test]
    fn varlen_unions_can_include_variable_sized_fields() {
        let descs = parse_syscall_descs(
            r#"
                bpf_map_update_val [
                    buf array[int8]
                    word buffer[4:4]
                ] [varlen]

                syscall use_varlen_union@1 -> int(val ptr[in, bpf_map_update_val])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    fields,
                    varlen,
                    size,
                    ..
                } => {
                    assert!(*varlen);
                    assert_eq!(*size, 4);
                    assert!(matches!(fields[0], ArgType::Array { .. }));
                }
                other => panic!("unexpected union inner: {:?}", other),
            },
            other => panic!("unexpected ptr arg: {:?}", other),
        }
    }

    #[test]
    fn parses_ptr64_arguments_on_amd64() {
        let descs = parse_syscall_descs(
            r#"
                syscall ptr64_call@1 -> int(arg ptr64[out, int32])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr {
                inner,
                dir,
                optional,
            } => {
                assert_eq!(*dir, PtrDir::Out);
                assert!(!optional);
                match inner.as_ref() {
                    ArgType::Const { size, .. } => assert_eq!(*size, 4),
                    other => panic!("unexpected ptr64 inner arg: {:?}", other),
                }
            }
            other => panic!("unexpected ptr64 arg: {:?}", other),
        }
    }

    #[test]
    fn structs_can_use_later_resource_definitions() {
        let descs = parse_syscall_descs(
            r#"
                resource fd[int32] = -1
                later_resource_holder {
                    fd fd_future
                }
                syscall use_later_resource@1 -> int(arg later_resource_holder)
                resource fd_future[fd] = -1
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Resource(resource) => {
                    assert_eq!(resource.kind, "fd_future");
                    assert_eq!(resource.lineage, vec!["fd", "fd_future"]);
                }
                other => panic!("unexpected later resource field: {:?}", other),
            },
            other => panic!("unexpected later_resource_holder arg: {:?}", other),
        }
    }

    #[test]
    fn directory_loading_prescans_sibling_resources_before_sys_txt_blocks() {
        let dir = temp_description_dir("directory-sibling-resources");
        fs::write(dir.join("cgroup.txt"), "resource fd_cgroup[fd] = -1\n").unwrap();
        fs::write(
            dir.join("sys.txt"),
            concat!(
                "resource fd[int32] = -1\n",
                "clone_args {\n",
                "    cgroup fd_cgroup\n",
                "}\n",
                "syscall use_cgroup@1 -> int(arg clone_args)\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Resource(resource) => {
                    assert_eq!(resource.kind, "fd_cgroup");
                    assert_eq!(resource.lineage, vec!["fd", "fd_cgroup"]);
                }
                other => panic!("unexpected clone_args arg field: {:?}", other),
            },
            other => panic!("unexpected use_cgroup arg: {:?}", other),
        }
    }

    #[test]
    fn directory_loading_prescans_later_sibling_resource_definitions() {
        let dir = temp_description_dir("directory-later-sibling-resources");
        fs::write(dir.join("00-child.txt"), "resource fd_child[fd_parent]\n").unwrap();
        fs::write(
            dir.join("99-parent.txt"),
            "resource fd_parent[int32] = -1\n",
        )
        .unwrap();
        fs::write(
            dir.join("sys.txt"),
            concat!(
                "holder {\n",
                "    fd fd_child\n",
                "}\n",
                "syscall use_child@1 -> int(arg holder)\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Resource(resource) => {
                    assert_eq!(resource.kind, "fd_child");
                    assert_eq!(resource.lineage, vec!["fd_parent", "fd_child"]);
                }
                other => panic!("unexpected child resource field: {:?}", other),
            },
            other => panic!("unexpected use_child arg: {:?}", other),
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
                    ArgType::Array {
                        inner,
                        min_len,
                        max_len,
                    } => {
                        assert_eq!((*min_len, *max_len), (2, 2));
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
                    ArgType::Struct { fields, size, .. } => {
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
    fn parses_known_meta_directives() {
        let descs = parse_syscall_descs(
            r#"
                meta automatic
                meta noextract
                meta arches["amd64", "arm64"]

                syscall meta_ok@1 -> int()
            "#,
        )
        .unwrap();

        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].name, "meta_ok");
    }

    #[test]
    fn parses_incdir_directives() {
        let descs = parse_syscall_descs(
            r#"
                incdir <drivers/gpu/drm/img-rogue/1.13>
                incdir "drivers/gpu/drm/img-rogue/1.13/km"

                syscall incdir_ok@1 -> int()
            "#,
        )
        .unwrap();

        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].name, "incdir_ok");
    }

    #[test]
    fn path_loading_skips_files_filtered_by_meta_arches() {
        let dir = temp_description_dir("meta-arches-filter");
        fs::write(
            dir.join("amd64.txt"),
            concat!(
                "meta arches[\"amd64\"]\n",
                "syscall amd64_only@1 -> int()\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("arm64.txt"),
            concat!(
                "meta arches[\"arm64\"]\n",
                "syscall arm64_only@2 -> int(arg missing_type)\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].name, "amd64_only");
    }

    #[test]
    fn directory_loading_prescans_later_sibling_type_definitions() {
        let dir = temp_description_dir("directory-later-sibling-types");
        fs::write(
            dir.join("00-user.txt"),
            concat!(
                "holder {\n",
                "    inner later_type\n",
                "}\n",
                "syscall use_later_type@1 -> int(arg holder)\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("99-type.txt"),
            concat!("later_type {\n", "    value int32\n", "}\n",),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Struct { fields, .. } => match &fields[0] {
                ArgType::Struct {
                    type_name, fields, ..
                } => {
                    assert_eq!(type_name.as_deref(), Some("later_type"));
                    assert_eq!(fields.len(), 1);
                }
                other => panic!("unexpected later type field: {:?}", other),
            },
            other => panic!("unexpected use_later_type arg: {:?}", other),
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
    fn parses_const_files_with_default_and_arch_specific_values() {
        let dir = temp_description_dir("const-file-arch-values");
        fs::write(
            dir.join("00-common.txt.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "arches = 386, amd64, arm64, mips64le\n",
                "BASE_DEFAULT = 8, mips64le:16\n",
                "AMD64_ONLY = 7, amd64:386\n",
                "AMD64_PICK = arm64:???, amd64:30\n",
                "MISSING_DEFAULT = ???\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("10-target.txt"),
            concat!(
                "constset base_values[4] = BASE_DEFAULT\n",
                "constset amd64_only[4] = AMD64_ONLY\n",
                "constset amd64_pick[4] = AMD64_PICK\n",
                "syscall check@1 -> int(a const[base_values], b const[amd64_only], c const[amd64_pick])\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![8]),
            other => panic!("unexpected default const arg: {:?}", other),
        }
        match &descs[0].args[1] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![7]),
            other => panic!("unexpected amd64-only const arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Const { values, .. } => assert_eq!(values, &vec![30]),
            other => panic!("unexpected arch-picked const arg: {:?}", other),
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
    fn auto_loads_target_arch_const_sibling_and_skips_other_arches() {
        let dir = temp_description_dir("sibling-arch-const");
        let base = dir.join("socket.txt");
        fs::write(
            dir.join("socket_amd64.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "AF_UNIX = 1\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("socket_arm64.const"),
            concat!(
                "# Code generated by syz-sysgen. DO NOT EDIT.\n",
                "AF_UNIX = 99\n",
            ),
        )
        .unwrap();
        fs::write(
            &base,
            concat!(
                "resource sock[4] = -1, 0\n",
                "constset unix_domain[4] = AF_UNIX\n",
                "syscall socket@1 -> sock(const[unix_domain], int32, int32)\n",
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
    fn directory_loading_prioritizes_sys_txt_root_definitions() {
        let dir = temp_description_dir("directory-sys-priority");
        fs::write(
            dir.join("acpi_thermal_rel.txt"),
            concat!(
                "resource fd_acpi_thermal_rel[fd]\n",
                "syscall keep@1 -> int(arg fd_acpi_thermal_rel)\n",
            ),
        )
        .unwrap();
        fs::write(dir.join("sys.txt"), "resource fd[4] = -1\n").unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 1);
        match &descs[0].args[0] {
            ArgType::Resource(resource) => {
                assert_eq!(resource.kind, "fd_acpi_thermal_rel");
                assert_eq!(resource.lineage, vec!["fd", "fd_acpi_thermal_rel"]);
            }
            other => panic!("unexpected resource arg: {:?}", other),
        }
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

    #[test]
    fn directory_loading_uses_target_arch_const_before_matching_txt() {
        let dir = temp_description_dir("directory-arch-const-order");
        fs::write(
            dir.join("dev_tlk_device_amd64.const"),
            concat!(
                "TE_IOCTL_OPEN_CLIENT_SESSION = 1\n",
                "TE_IOCTL_CLOSE_CLIENT_SESSION = 2\n",
                "TE_IOCTL_LAUNCH_OPERATION = 3\n",
                "TE_PARAM_TYPE_NONE = 0\n",
                "TE_PARAM_TYPE_INT_RO = 1\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("dev_tlk_device_arm64.const"),
            concat!(
                "TE_IOCTL_OPEN_CLIENT_SESSION = 11\n",
                "TE_IOCTL_CLOSE_CLIENT_SESSION = 12\n",
                "TE_IOCTL_LAUNCH_OPERATION = 13\n",
                "TE_PARAM_TYPE_NONE = 10\n",
                "TE_PARAM_TYPE_INT_RO = 11\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("dev_tlk_device.txt"),
            concat!(
                "resource fd[int32] = -1\n",
                "resource fd_tlk[fd]\n",
                "resource te_session_id[int32]\n",
                "te_oper_param_type_flags = TE_PARAM_TYPE_NONE, TE_PARAM_TYPE_INT_RO\n",
                "openat$tlk_device(fd const[0, int32], file ptr[in, string[\"/dev/tlk_device\"]], flags int32) fd_tlk\n",
                "ioctl$TE_IOCTL_OPEN_CLIENT_SESSION(fd fd_tlk, cmd const[TE_IOCTL_OPEN_CLIENT_SESSION], arg ptr[inout, te_opensession])\n",
                "ioctl$TE_IOCTL_CLOSE_CLIENT_SESSION(fd fd_tlk, cmd const[TE_IOCTL_CLOSE_CLIENT_SESSION], arg ptr[inout, te_closesession])\n",
                "ioctl$TE_IOCTL_LAUNCH_OPERATION(fd fd_tlk, cmd const[TE_IOCTL_LAUNCH_OPERATION], arg ptr[inout, te_launchop])\n",
                "te_opensession {\n",
                "    operation te_operation\n",
                "    answer ptr[out, te_answer]\n",
                "}\n",
                "te_closesession {\n",
                "    session_id te_session_id\n",
                "    answer ptr[out, te_answer]\n",
                "}\n",
                "te_answer {\n",
                "    result int32\n",
                "    session_id te_session_id\n",
                "}\n",
                "te_launchop {\n",
                "    session_id te_session_id\n",
                "    operation te_operation\n",
                "    answer int64\n",
                "}\n",
                "te_operation {\n",
                "    list_head ptr[in, te_oper_param]\n",
                "}\n",
                "te_oper_param {\n",
                "    type flags[te_oper_param_type_flags, int32]\n",
                "    next_ptr_user ptr[in, te_oper_param, opt]\n",
                "}\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let generatable = crate::program::transitively_generatable_syscalls(&descs);
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(descs.len(), 4);
        assert_eq!(generatable.enabled, vec![0, 1, 2, 3]);
        assert!(generatable.disabled.is_empty());
        match &descs[1].args[2] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => match &fields[0] {
                    ArgType::Struct { fields, .. } => match &fields[0] {
                        ArgType::Ptr { inner, .. } => match inner.as_ref() {
                            ArgType::Struct { fields, .. } => match &fields[0] {
                                ArgType::Const { values, .. } => assert_eq!(values, &vec![0, 1]),
                                other => panic!("unexpected te_oper_param type field: {:?}", other),
                            },
                            other => panic!("unexpected te_oper_param pointee: {:?}", other),
                        },
                        other => panic!("unexpected list_head field: {:?}", other),
                    },
                    other => panic!("unexpected te_operation field: {:?}", other),
                },
                other => panic!("unexpected te_opensession inner type: {:?}", other),
            },
            other => panic!("unexpected ioctl open arg: {:?}", other),
        }
    }

    #[test]
    fn parses_fixed_and_varlen_union_blocks() {
        let descs = parse_syscall_descs(
            r#"
                maybe_word [
                    small int16
                    full int32
                ] [size[8]]
                flex_word [
                    small int16
                    full int32
                ] [varlen]
                syscall take_value@1 -> int(arg maybe_word)
                syscall take_ptr@2 -> int(arg ptr[in, flex_word])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Union {
                fields,
                size,
                varlen,
                ..
            } => {
                assert_eq!(*size, 8);
                assert!(!varlen);
                assert_eq!(fields.len(), 2);
                assert_eq!(crate::program::arg_type_fixed_size(&fields[0]), Some(2));
                assert_eq!(crate::program::arg_type_fixed_size(&fields[1]), Some(4));
            }
            other => panic!("unexpected fixed union arg: {:?}", other),
        }

        match &descs[1].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    fields,
                    size,
                    varlen,
                    ..
                } => {
                    assert_eq!(*size, 4);
                    assert!(*varlen);
                    assert_eq!(fields.len(), 2);
                }
                other => panic!("unexpected varlen union inner type: {:?}", other),
            },
            other => panic!("unexpected varlen union arg: {:?}", other),
        }
    }

    #[test]
    fn parses_vma_forms() {
        let descs = parse_syscall_descs(
            r#"
                syscall take_vma@1 -> int(v0 vma, l0 len[v0], v1 vma[5], l1 len[v1], v2 vma[7:9], l2 len[v2], v3 vma[opt])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Vma {
                min_pages,
                max_pages,
                optional,
            } => {
                assert_eq!((*min_pages, *max_pages, *optional), (1, 4, false));
            }
            other => panic!("unexpected default vma arg: {:?}", other),
        }
        match &descs[0].args[2] {
            ArgType::Vma {
                min_pages,
                max_pages,
                optional,
            } => {
                assert_eq!((*min_pages, *max_pages, *optional), (5, 5, false));
            }
            other => panic!("unexpected fixed vma arg: {:?}", other),
        }
        match &descs[0].args[4] {
            ArgType::Vma {
                min_pages,
                max_pages,
                optional,
            } => {
                assert_eq!((*min_pages, *max_pages, *optional), (7, 9, false));
            }
            other => panic!("unexpected ranged vma arg: {:?}", other),
        }
        match &descs[0].args[6] {
            ArgType::Vma {
                min_pages,
                max_pages,
                optional,
            } => {
                assert_eq!((*min_pages, *max_pages, *optional), (1, 4, true));
            }
            other => panic!("unexpected optional vma arg: {:?}", other),
        }
    }

    #[test]
    fn parses_string_forms_and_sets() {
        let descs = parse_syscall_descs(
            r#"
                const NAME_LEN = 12
                path_values = "/dev/null", "/dev/zero"
                device_names = "binder0", "binder1"
                syscall take_strings@1 -> int(path ptr[in, string[path_values]], raw ptr[in, stringnoz["abc", 8]], name ptr[in, string[filename, 16]], device ptr[in, string[device_names, NAME_LEN]], plain ptr[in, string])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String {
                    values,
                    noz,
                    fixed_len,
                    filename,
                } => {
                    assert_eq!(values.len(), 2);
                    assert_eq!(values[0], b"/dev/null");
                    assert!(!noz);
                    assert_eq!(*fixed_len, None);
                    assert!(!filename);
                }
                other => panic!("unexpected string-set inner type: {:?}", other),
            },
            other => panic!("unexpected string-set arg: {:?}", other),
        }

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String {
                    values,
                    noz,
                    fixed_len,
                    filename,
                } => {
                    assert_eq!(values, &vec![b"abc".to_vec()]);
                    assert!(*noz);
                    assert_eq!(*fixed_len, Some(8));
                    assert!(!filename);
                }
                other => panic!("unexpected stringnoz inner type: {:?}", other),
            },
            other => panic!("unexpected stringnoz arg: {:?}", other),
        }

        match &descs[0].args[2] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String {
                    values,
                    noz,
                    fixed_len,
                    filename,
                } => {
                    assert!(values.is_empty());
                    assert!(!noz);
                    assert_eq!(*fixed_len, Some(16));
                    assert!(*filename);
                }
                other => panic!("unexpected filename-string inner type: {:?}", other),
            },
            other => panic!("unexpected filename-string arg: {:?}", other),
        }

        match &descs[0].args[3] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String {
                    values,
                    noz,
                    fixed_len,
                    filename,
                } => {
                    assert_eq!(values, &vec![b"binder0".to_vec(), b"binder1".to_vec()]);
                    assert!(!noz);
                    assert_eq!(*fixed_len, Some(12));
                    assert!(!filename);
                }
                other => panic!("unexpected const-length string-set inner type: {:?}", other),
            },
            other => panic!("unexpected const-length string-set arg: {:?}", other),
        }
    }

    #[test]
    fn parses_string_literals_with_embedded_nul_bytes() {
        let descs = parse_syscall_descs(
            r#"
                syscall take_nul_string@1 -> int(arg ptr[in, string["ab\u0000cd"]])
            "#,
        )
        .expect("embedded NUL string literal should parse");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::String {
                    values,
                    noz,
                    fixed_len,
                    ..
                } => {
                    assert_eq!(values, &vec![b"ab\0cd".to_vec()]);
                    assert!(!noz);
                    assert_eq!(*fixed_len, None);
                }
                other => panic!("unexpected embedded-NUL string type: {:?}", other),
            },
            other => panic!("unexpected embedded-NUL string arg: {:?}", other),
        }
    }

    #[test]
    fn parses_and_instantiates_type_templates() {
        let descs = parse_syscall_descs(
            r#"
                type wrap[PAYLOAD] {
                    payload PAYLOAD
                }
                type alias_wrap[PAYLOAD] wrap[PAYLOAD]
                syscall write_wrap@1 -> int(fd const[1, int32], data ptr[in, alias_wrap[stringnoz["syz", 8]]], size len[data])
            "#,
        )
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, size, .. } => {
                    assert_eq!(*size, 8);
                    assert_eq!(fields.len(), 1);
                    match &fields[0] {
                        ArgType::String {
                            values,
                            noz,
                            fixed_len,
                            filename,
                        } => {
                            assert_eq!(values, &vec![b"syz".to_vec()]);
                            assert!(*noz);
                            assert_eq!(*fixed_len, Some(8));
                            assert!(!filename);
                        }
                        other => panic!("unexpected instantiated payload type: {:?}", other),
                    }
                }
                other => panic!("unexpected instantiated inner type: {:?}", other),
            },
            other => panic!("unexpected template arg: {:?}", other),
        }
    }

    #[test]
    fn rejects_template_arity_mismatch() {
        let err = parse_syscall_descs(
            r#"
                type wrap[PAYLOAD] {
                    payload PAYLOAD
                }
                syscall bad_wrap@1 -> int(data ptr[in, wrap[int8, int16]])
            "#,
        )
        .expect_err("arity mismatch must be rejected");

        assert!(err.contains("template expects 1 arguments, got 2"));
    }

    #[test]
    fn parses_parent_derived_lengths_inside_struct_templates() {
        let descs = parse_syscall_descs(
            r#"
                type msg[PAYLOAD] {
                    size bytesize[parent, int32]
                    kind const[7, int32]
                    payload PAYLOAD
                } [packed]
                syscall write_msg@1 -> int(fd const[1, int32], data ptr[in, msg[int32]], len len[data, int32])
            "#,
        )
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, size, .. } => {
                    assert_eq!(*size, 12);
                    match &fields[0] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Parent(1),
                                        fields: Vec::new(),
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected msg size field: {:?}", other),
                    }
                }
                other => panic!("unexpected msg inner type: {:?}", other),
            },
            other => panic!("unexpected msg arg: {:?}", other),
        }
    }

    #[test]
    fn parses_offsetof_and_void_inside_structs() {
        let descs = parse_syscall_descs(
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
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct {
                    fields,
                    field_names,
                    size,
                    ..
                } => {
                    assert_eq!(*size, 8);
                    assert_eq!(field_names, &vec!["nla_len", "nla_type", "payload", "end"]);
                    match &fields[0] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Current,
                                        fields: vec!["end".into()],
                                    },
                                    2,
                                    LengthKind::Offset,
                                )
                            );
                        }
                        other => panic!("unexpected nla_len field: {:?}", other),
                    }
                    assert!(matches!(fields[3], ArgType::Void));
                }
                other => panic!("unexpected nlattr inner type: {:?}", other),
            },
            other => panic!("unexpected nlattr arg: {:?}", other),
        }
    }

    #[test]
    fn parses_named_path_length_targets() {
        let descs = parse_syscall_descs(
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
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => {
                    match &fields[1] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Type("path_outer".into()),
                                        fields: vec!["inner".into()],
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected type-root length field: {:?}", other),
                    }
                    match &fields[2] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Current,
                                        fields: vec!["inner".into()],
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected current-root length field: {:?}", other),
                    }
                }
                other => panic!("unexpected path_outer arg: {:?}", other),
            },
            other => panic!("unexpected data arg: {:?}", other),
        }

        match &descs[0].args[2] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => {
                    match &fields[1] {
                        ArgType::Struct { fields, .. } => match &fields[0] {
                            ArgType::Len {
                                target, size, kind, ..
                            } => {
                                assert_eq!(
                                    (target, *size, *kind),
                                    (
                                        &LengthTarget {
                                            root: LengthTargetRoot::Parent(2),
                                            fields: vec!["payload".into()],
                                        },
                                        4,
                                        LengthKind::Bytes,
                                    )
                                );
                            }
                            other => panic!("unexpected parent-root length field: {:?}", other),
                        },
                        other => panic!("unexpected parent_meta field: {:?}", other),
                    }
                    match &fields[2] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Arg("data".into()),
                                        fields: Vec::new(),
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected syscall-root length field: {:?}", other),
                    }
                }
                other => panic!("unexpected helper_outer arg: {:?}", other),
            },
            other => panic!("unexpected ctx arg: {:?}", other),
        }

        match &descs[0].args[3] {
            ArgType::Len {
                target, size, kind, ..
            } => {
                assert_eq!(
                    (target, *size, *kind),
                    (
                        &LengthTarget {
                            root: LengthTargetRoot::Arg("data".into()),
                            fields: vec!["inner".into()],
                        },
                        4,
                        LengthKind::Auto,
                    )
                );
            }
            other => panic!("unexpected top-level arg-path length: {:?}", other),
        }
    }

    #[test]
    fn parses_forward_type_roots_inside_mutually_recursive_named_types() {
        let descs = parse_syscall_descs(
            r#"
                outer {
                    header inner
                    payload array[int8, 8]
                } [packed]
                inner {
                    payload_len bytesize[outer:payload, int32]
                } [packed]
                syscall use_outer@1 -> int(arg ptr[in, outer])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => match &fields[0] {
                    ArgType::Struct { fields, .. } => match &fields[0] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Type("outer".into()),
                                        fields: vec!["payload".into()],
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected nested length field: {:?}", other),
                    },
                    other => panic!("unexpected nested header type: {:?}", other),
                },
                other => panic!("unexpected outer arg type: {:?}", other),
            },
            other => panic!("unexpected syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_single_segment_type_roots_inside_type_context() {
        let descs = parse_syscall_descs(
            r#"
                outer {
                    hdr inner
                    payload array[int8]
                }
                inner {
                    total bytesize[outer, int32]
                } [packed]
                syscall use_outer@1 -> int(arg ptr[in, outer])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => match &fields[0] {
                    ArgType::Struct { fields, .. } => match &fields[0] {
                        ArgType::Len {
                            target, size, kind, ..
                        } => {
                            assert_eq!(
                                (target, *size, *kind),
                                (
                                    &LengthTarget {
                                        root: LengthTargetRoot::Type("outer".into()),
                                        fields: vec![],
                                    },
                                    4,
                                    LengthKind::Bytes,
                                )
                            );
                        }
                        other => panic!("unexpected single-segment type-root field: {:?}", other),
                    },
                    other => panic!("unexpected nested header type: {:?}", other),
                },
                other => panic!("unexpected outer arg type: {:?}", other),
            },
            other => panic!("unexpected syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_auto_generated_ieee802154_policy_union_fragment() {
        let dir = temp_description_dir("auto-ieee802154-policy");
        fs::write(
            dir.join("00-base.txt"),
            concat!(
                "devnames = \"\", \"lo\"\n",
                "resource ifindex[int32]\n",
                "type devname string[devnames, 16]\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("10-netlink.txt"),
            concat!(
                "type nlattr_t[TYPE, PAYLOAD] {\n",
                "    nla_len offsetof[size, int16]\n",
                "    nla_type TYPE\n",
                "    payload PAYLOAD\n",
                "    size void\n",
                "} [packed, align[4]]\n",
                "type nlattr[TYPE, PAYLOAD] nlattr_t[const[TYPE, int16], PAYLOAD]\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("20-auto.txt"),
            concat!(
                "syscall use_auto_policy@1 -> int(arg ptr[in, ieee802154_policy_nl802154$auto])\n",
                "ieee802154_policy_nl802154$auto [\n",
                "    IEEE802154_ATTR_DEV_NAME nlattr[IEEE802154_ATTR_DEV_NAME, devname]\n",
                "    IEEE802154_ATTR_DEV_INDEX nlattr[IEEE802154_ATTR_DEV_INDEX, ifindex]\n",
                "    IEEE802154_ATTR_PHY_NAME nlattr[IEEE802154_ATTR_PHY_NAME, stringnoz]\n",
                "    IEEE802154_ATTR_STATUS nlattr[IEEE802154_ATTR_STATUS, int8]\n",
                "    IEEE802154_ATTR_SHORT_ADDR nlattr[IEEE802154_ATTR_SHORT_ADDR, int16]\n",
                "    IEEE802154_ATTR_HW_ADDR nlattr[IEEE802154_ATTR_HW_ADDR, int64]\n",
                "    IEEE802154_ATTR_PAN_ID nlattr[IEEE802154_ATTR_PAN_ID, int16]\n",
                "    IEEE802154_ATTR_ED_LIST nlattr[IEEE802154_ATTR_ED_LIST, array[int8, 27]]\n",
                "    IEEE802154_ATTR_CHANNEL_PAGE_LIST nlattr[IEEE802154_ATTR_CHANNEL_PAGE_LIST, array[int8, 128]]\n",
                "    IEEE802154_ATTR_LBT_ENABLED nlattr[IEEE802154_ATTR_LBT_ENABLED, bool8]\n",
                "] [varlen]\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    type_name,
                    fields,
                    varlen,
                    ..
                } => {
                    assert_eq!(
                        type_name.as_deref(),
                        Some("ieee802154_policy_nl802154$auto")
                    );
                    assert_eq!(fields.len(), 10);
                    assert!(*varlen);
                }
                other => panic!("unexpected auto policy inner type: {:?}", other),
            },
            other => panic!("unexpected auto policy arg: {:?}", other),
        }
    }

    #[test]
    fn fixed_unions_accept_uniform_length_string_set_fields() {
        let descs = parse_syscall_descs(
            r#"
                nft_flowtable_name = "syz0", "syz1", "syz2"
                type nlattr[TYPE, PAYLOAD] {
                    nla_len offsetof[size, int16]
                    nla_type const[TYPE, int16]
                    payload PAYLOAD
                    size void
                } [packed, align[4]]
                nft_flow_offload_policy [
                    NFTA_FLOW_TABLE_NAME nlattr[0xaa, string[nft_flowtable_name]]
                ]
                syscall use_flow@1 -> int(arg ptr[in, nft_flow_offload_policy])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    size,
                    varlen,
                    fields,
                    ..
                } => {
                    assert_eq!(*size, 12);
                    assert!(!varlen);
                    assert_eq!(fields.len(), 1);
                }
                other => panic!("unexpected flow policy inner type: {:?}", other),
            },
            other => panic!("unexpected flow policy arg: {:?}", other),
        }
    }

    #[test]
    fn varlen_unions_can_skip_self_recursive_fields() {
        let descs = parse_syscall_descs(
            r#"
                recursive_attr [
                    generic array[int8]
                    nested array[recursive_attr]
                ] [varlen]
                syscall use_recursive@1 -> int(arg ptr[in, recursive_attr])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    field_names,
                    fields,
                    varlen,
                    ..
                } => {
                    assert!(*varlen);
                    assert_eq!(field_names, &vec!["generic".to_string()]);
                    assert_eq!(fields.len(), 1);
                }
                other => panic!("unexpected recursive union inner type: {:?}", other),
            },
            other => panic!("unexpected recursive union arg: {:?}", other),
        }
    }

    #[test]
    fn parses_nl_generic_attr_style_recursive_union() {
        let descs = parse_syscall_descs(
            r#"
                resource fd[int32]
                resource pid[int32]
                resource uid[int32]
                type ipv4_addr int32
                type ipv6_addr array[int8, 16]
                type nlattr_tt[TYPE, NETORDER, NESTED, PAYLOAD] {
                    nla_len offsetof[size, int16]
                    nla_type TYPE
                    NLA_F_NET_BYTEORDER const[NETORDER, int16:1]
                    NLA_F_NESTED const[NESTED, int16:1]
                    payload PAYLOAD
                    size void
                } [packed, align[4]]
                type nlnest[TYPE, PAYLOAD] nlattr_tt[const[TYPE, int16:14], 0, 1, PAYLOAD]
                nl_generic_attr [
                    generic array[int8]
                    typed nlattr_tt[int16:14[0:10], 0, 0, nl_generic_attr_data]
                    nested nlnest[int16:14[0:10], array[nl_generic_attr]]
                ] [varlen]
                nl_generic_attr_data [
                    void void
                    u32 int32
                    u64 int64
                    ipv4 ipv4_addr
                    ipv6 ipv6_addr
                    fd fd
                    pid pid
                    uid uid
                    str string
                    binary array[int8]
                ] [varlen]
                syscall use_nlattr@1 -> int(arg ptr[in, nl_generic_attr])
            "#,
        )
        .unwrap();

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    type_name,
                    field_names,
                    fields,
                    varlen,
                    ..
                } => {
                    assert_eq!(type_name.as_deref(), Some("nl_generic_attr"));
                    assert!(varlen);
                    assert_eq!(
                        field_names,
                        &vec!["generic".to_string(), "typed".to_string()]
                    );
                    assert_eq!(fields.len(), 2);
                }
                other => panic!("unexpected nl_generic_attr inner type: {:?}", other),
            },
            other => panic!("unexpected nl_generic_attr arg: {:?}", other),
        }
    }

    #[test]
    fn directory_loading_handles_auto_policies_that_reference_nl_generic_attr() {
        let dir = temp_description_dir("auto-nl-generic-attr");
        fs::write(
            dir.join("00-sys.txt"),
            concat!(
                "resource fd[int32]\n",
                "resource pid[int32]\n",
                "resource uid[int32]\n",
                "type ipv4_addr int32\n",
                "type ipv6_addr array[int8, 16]\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("10-socket_netlink.txt"),
            concat!(
                "type nlattr_tt[TYPE, NETORDER, NESTED, PAYLOAD] {\n",
                "    nla_len offsetof[size, int16]\n",
                "    nla_type TYPE\n",
                "    NLA_F_NET_BYTEORDER const[NETORDER, int16:1]\n",
                "    NLA_F_NESTED const[NESTED, int16:1]\n",
                "    payload PAYLOAD\n",
                "    size void\n",
                "} [packed, align[4]]\n",
                "type nlnest[TYPE, PAYLOAD] nlattr_tt[const[TYPE, int16:14], 0, 1, PAYLOAD]\n",
                "nl_generic_attr [\n",
                "    generic array[int8]\n",
                "    typed nlattr_tt[int16:14[0:10], 0, 0, nl_generic_attr_data]\n",
                "    nested nlattr_tt[int16:14[0:10], 0, 1, array[nl_generic_attr]]\n",
                "] [varlen]\n",
                "nl_generic_attr_data [\n",
                "    void void\n",
                "    u32 int32\n",
                "    u64 int64\n",
                "    ipv4 ipv4_addr\n",
                "    ipv6 ipv6_addr\n",
                "    fd fd\n",
                "    pid pid\n",
                "    uid uid\n",
                "    str string\n",
                "    binary array[int8]\n",
                "] [varlen]\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("20-auto.txt"),
            concat!(
                "ip_vs_cmd_policy_ip_vs_ctl$auto [\n",
                "    IPVS_CMD_ATTR_SERVICE nlnest[IPVS_CMD_ATTR_SERVICE, array[nl_generic_attr]]\n",
                "    IPVS_CMD_ATTR_DEST nlnest[IPVS_CMD_ATTR_DEST, array[nl_generic_attr]]\n",
                "] [varlen]\n",
                "syscall use_auto@1 -> int(arg ptr[in, ip_vs_cmd_policy_ip_vs_ctl$auto])\n",
            ),
        )
        .unwrap();

        let descs = parse_syscall_descs_from_path(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    type_name,
                    fields,
                    varlen,
                    ..
                } => {
                    assert_eq!(
                        type_name.as_deref(),
                        Some("ip_vs_cmd_policy_ip_vs_ctl$auto")
                    );
                    assert!(varlen);
                    assert_eq!(fields.len(), 2);
                }
                other => panic!("unexpected auto policy type: {:?}", other),
            },
            other => panic!("unexpected auto policy arg: {:?}", other),
        }
    }

    #[test]
    fn parses_trailing_varlen_structs_and_ranged_arrays() {
        let descs = parse_syscall_descs(
            r#"
                type blob_msg {
                    count bytesize[data, int32]
                    data array[int8, 4:8]
                } [packed]
                type qid {
                    path int32
                    version int32
                } [packed]
                type walk_msg {
                    nwqid len[wqid, int16]
                    wqid array[qid, 1:3]
                } [packed]
                syscall write_blob@1 -> int(fd const[1, int32], data ptr[in, blob_msg], size len[data, int32])
                syscall write_walk@2 -> int(fd const[1, int32], data ptr[in, walk_msg], size len[data, int32])
            "#,
        )
        .unwrap();

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct {
                    fields,
                    size,
                    varlen,
                    ..
                } => {
                    assert_eq!(*size, 4);
                    assert!(*varlen);
                    match &fields[1] {
                        ArgType::Array {
                            inner,
                            min_len,
                            max_len,
                        } => {
                            assert_eq!((*min_len, *max_len), (4, 8));
                            assert!(matches!(inner.as_ref(), ArgType::Const { size: 1, .. }));
                        }
                        other => panic!("unexpected blob payload field: {:?}", other),
                    }
                }
                other => panic!("unexpected blob_msg inner type: {:?}", other),
            },
            other => panic!("unexpected blob_msg arg: {:?}", other),
        }

        match &descs[1].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct {
                    fields,
                    size,
                    varlen,
                    ..
                } => {
                    assert_eq!(*size, 2);
                    assert!(*varlen);
                    match &fields[1] {
                        ArgType::Array {
                            inner,
                            min_len,
                            max_len,
                        } => {
                            assert_eq!((*min_len, *max_len), (1, 3));
                            match inner.as_ref() {
                                ArgType::Struct { size, varlen, .. } => {
                                    assert_eq!(*size, 8);
                                    assert!(!*varlen);
                                }
                                other => panic!("unexpected qid element type: {:?}", other),
                            }
                        }
                        other => panic!("unexpected walk_msg array field: {:?}", other),
                    }
                }
                other => panic!("unexpected walk_msg inner type: {:?}", other),
            },
            other => panic!("unexpected walk_msg arg: {:?}", other),
        }
    }

    #[test]
    fn parses_proc_scalars_in_top_level_and_vnet_style_structs() {
        let descs = parse_syscall_descs(
            r#"
                type ipv4_addr_initdev {
                    a0 const[0xac, int8]
                    a1 const[0x1e, int8]
                    a2 int8[0:1]
                    a3 proc[1, 1, int8]
                }
                syscall use_proc@1 -> int(dev proc[1792, 2], addr ptr[in, ipv4_addr_initdev])
            "#,
        )
        .expect("proc-bearing target should parse");

        match &descs[0].args[0] {
            ArgType::Proc {
                size,
                values_start,
                values_per_proc,
                endian,
            } => {
                assert_eq!(*size, 8);
                assert_eq!(*values_start, 1792);
                assert_eq!(*values_per_proc, 2);
                assert_eq!(*endian, ScalarEndian::Native);
            }
            other => panic!("unexpected top-level proc arg: {:?}", other),
        }

        match &descs[0].args[1] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, size, .. } => {
                    assert_eq!(*size, 4);
                    match &fields[3] {
                        ArgType::Proc {
                            size,
                            values_start,
                            values_per_proc,
                            endian,
                        } => {
                            assert_eq!(*size, 1);
                            assert_eq!(*values_start, 1);
                            assert_eq!(*values_per_proc, 1);
                            assert_eq!(*endian, ScalarEndian::Native);
                        }
                        other => panic!("unexpected inline proc field: {:?}", other),
                    }
                }
                other => panic!("unexpected inline proc struct: {:?}", other),
            },
            other => panic!("unexpected inline proc syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_out_overlay_structs_with_explicit_parent_size() {
        let descs = parse_syscall_descs(
            r#"
                type overlay_args {
                    kind int32
                    devid int32 (out_overlay)
                    magic int32
                } [size[8]]
                type overlay_outer {
                    prefix int32
                    payload overlay_args
                    suffix int32
                } [size[16]]
                syscall use_overlay@1 -> int(arg ptr[inout, overlay_outer])
            "#,
        )
        .expect("overlay-bearing target should parse");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct {
                    fields,
                    size,
                    overlay_start,
                    ..
                } => {
                    assert_eq!(*size, 16);
                    assert_eq!(*overlay_start, None);
                    match &fields[1] {
                        ArgType::Struct {
                            fields,
                            size,
                            overlay_start,
                            ..
                        } => {
                            assert_eq!(*size, 8);
                            assert_eq!(*overlay_start, Some(1));
                            assert_eq!(fields.len(), 3);
                        }
                        other => panic!("unexpected overlay payload type: {:?}", other),
                    }
                }
                other => panic!("unexpected overlay outer type: {:?}", other),
            },
            other => panic!("unexpected overlay syscall arg: {:?}", other),
        }
    }

    #[test]
    fn unions_can_wait_for_later_template_aliases() {
        let descs = parse_syscall_descs(
            r#"
                sock_addr [
                    kern sock_addr_kern
                    proc sock_addr_proc
                ]
                type port_id int32[1:2]
                type sock_addr_t[FAMILY, PID, GROUPS] {
                    family const[FAMILY, int16]
                    pad const[0, int16]
                    pid PID
                    groups GROUPS
                }
                type sock_addr_proc sock_addr_t[1, port_id, flags[proc_groups, int32]]
                type sock_addr_kern sock_addr_t[1, const[0, int32], flags[proc_groups, int32]]
                proc_groups = 0, 1
                syscall use_sockaddr@1 -> int(addr ptr[in, sock_addr])
            "#,
        )
        .expect("later template aliases should resolve through pending rounds");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    type_name,
                    fields,
                    field_names,
                    ..
                } => {
                    assert_eq!(type_name.as_deref(), Some("sock_addr"));
                    assert_eq!(fields.len(), 2);
                    assert_eq!(field_names, &vec!["kern".to_string(), "proc".to_string()]);
                }
                other => panic!("unexpected sockaddr union: {:?}", other),
            },
            other => panic!("unexpected sockaddr syscall arg: {:?}", other),
        }
    }

    #[test]
    fn varlen_unions_can_skip_indirect_recursive_pending_fields() {
        let descs = parse_syscall_descs(
            r#"
                cyc_a [
                    base int32
                    next cyc_b
                ] [varlen]
                cyc_b [
                    base int32
                    next cyc_c
                ] [varlen]
                cyc_c [
                    base int32
                    next cyc_a
                ] [varlen]
                syscall use_cycle@1 -> int(arg ptr[in, cyc_a])
            "#,
        )
        .expect("indirect recursive varlen unions should salvage non-cyclic fields");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    fields,
                    field_names,
                    varlen,
                    ..
                } => {
                    assert!(*varlen);
                    assert_eq!(fields.len(), 1);
                    assert_eq!(field_names, &vec!["base".to_string()]);
                    assert!(matches!(fields[0], ArgType::Const { size: 4, .. }));
                }
                other => panic!("unexpected cycle union type: {:?}", other),
            },
            other => panic!("unexpected cycle syscall arg: {:?}", other),
        }
    }

    #[test]
    fn varlen_unions_can_fall_back_to_void_when_only_recursive_fields_remain() {
        let descs = parse_syscall_descs(
            r#"
                cyc_only_a [
                    next cyc_only_b
                ] [varlen]
                cyc_only_b [
                    next cyc_only_a
                ] [varlen]
                syscall use_cycle_only@1 -> int(arg ptr[in, cyc_only_a])
            "#,
        )
        .expect("purely recursive varlen unions should keep a conservative placeholder");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union {
                    fields,
                    field_names,
                    varlen,
                    ..
                } => {
                    assert!(*varlen);
                    assert_eq!(fields.len(), 1);
                    assert_eq!(field_names, &vec!["void".to_string()]);
                    assert!(matches!(fields[0], ArgType::Void));
                }
                other => panic!("unexpected pure cycle union type: {:?}", other),
            },
            other => panic!("unexpected pure cycle syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_adf_auto_pointer_cycles_conservatively() {
        let descs = parse_syscall_descs(
            r#"
                adf_cfg_val_type$auto = 1, 2, 3
                adf_user_cfg_ctl_data$auto {
                    adf_user_cfg_ctl_data_0 adf_user_cfg_ctl_data_0$auto
                    device_id int8
                } [packed]
                adf_user_cfg_ctl_data_0$auto [
                    config_section ptr[inout, adf_user_cfg_section$auto]
                    padding const[0, int64]
                ]
                adf_user_cfg_key_val$auto {
                    key array[int8, 64]
                    val array[int8, 64]
                    adf_user_cfg_key_val_2 adf_user_cfg_key_val_2$auto
                    type flags[adf_cfg_val_type$auto, int32]
                } [packed]
                adf_user_cfg_key_val_2$auto [
                    next ptr[inout, adf_user_cfg_key_val$auto, opt]
                    padding3 const[0, int64]
                ]
                adf_user_cfg_section$auto {
                    name array[int8, 64]
                    adf_user_cfg_section_1 adf_user_cfg_section_1$auto
                    adf_user_cfg_section_2 adf_user_cfg_section_2$auto
                } [packed]
                adf_user_cfg_section_1$auto [
                    params ptr[inout, adf_user_cfg_key_val$auto]
                    padding1 const[0, int64]
                ]
                adf_user_cfg_section_2$auto [
                    next ptr[inout, adf_user_cfg_section$auto, opt]
                    padding3 const[0, int64]
                ]
                syscall use_adf@1 -> int(arg ptr[inout, adf_user_cfg_ctl_data$auto])
            "#,
        )
        .expect("ADF auto pointer cycles should parse");

        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn fixed_unions_can_coerce_nested_opaque_struct_fields_to_pointers() {
        let descs = parse_syscall_descs(
            r#"
                event_ext {
                    len len[ptr, int32]
                    ptr buffer[in]
                } [packed]
                event_data [
                    ext event_ext
                    raw array[int8, 12]
                ]
                syscall use_event@1 -> int(arg ptr[in, event_data])
            "#,
        )
        .expect("fixed unions should accept nested opaque struct fields");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Union { fields, .. } => match &fields[0] {
                    ArgType::Struct { fields, size, .. } => {
                        assert_eq!(*size, 12);
                        assert!(matches!(
                            &fields[1],
                            ArgType::Ptr {
                                inner,
                                dir: PtrDir::In,
                                optional: false,
                            } if matches!(inner.as_ref(), ArgType::Buffer { .. })
                        ));
                    }
                    other => panic!("unexpected ext field type: {:?}", other),
                },
                other => panic!("unexpected event_data type: {:?}", other),
            },
            other => panic!("unexpected event_data arg: {:?}", other),
        }
    }

    #[test]
    fn parses_self_referential_struct_pointers_conservatively() {
        let descs = parse_syscall_descs(
            r#"
                robust_list$auto {
                    next ptr[inout, robust_list$auto, opt]
                }
                robust_list_head$auto {
                    list robust_list$auto
                    futex_offset intptr
                    list_op_pending ptr[inout, robust_list$auto]
                }
                syscall use_robust@1 -> int(arg ptr[inout, robust_list_head$auto])
            "#,
        )
        .expect("self-referential struct pointers should parse");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => {
                    match &fields[0] {
                        ArgType::Struct { fields, .. } => {
                            assert!(matches!(
                                &fields[0],
                                ArgType::Ptr {
                                    inner,
                                    dir: PtrDir::InOut,
                                    optional: true
                                } if matches!(inner.as_ref(), ArgType::Void)
                            ));
                        }
                        other => panic!("unexpected robust_list field: {:?}", other),
                    }
                    assert!(matches!(
                        &fields[2],
                        ArgType::Ptr {
                            inner,
                            dir: PtrDir::InOut,
                            optional: false
                        } if matches!(inner.as_ref(), ArgType::Struct { .. })
                    ));
                }
                other => panic!("unexpected robust_list_head type: {:?}", other),
            },
            other => panic!("unexpected robust syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_indirect_recursive_struct_pointer_cycles_conservatively() {
        let descs = parse_syscall_descs(
            r#"
                alpha {
                    beta ptr64[inout, beta, opt]
                } [packed]
                beta {
                    alpha ptr64[inout, alpha, opt]
                } [packed]
                syscall use_cycle@1 -> int(arg ptr[inout, alpha])
            "#,
        )
        .expect("indirect recursive struct pointer cycles should parse");

        match &descs[0].args[0] {
            ArgType::Ptr { inner, .. } => match inner.as_ref() {
                ArgType::Struct { fields, .. } => {
                    assert!(matches!(
                        &fields[0],
                        ArgType::Ptr {
                            inner,
                            dir: PtrDir::InOut,
                            optional: true,
                        } if matches!(inner.as_ref(), ArgType::Void)
                    ));
                }
                other => panic!("unexpected alpha type: {:?}", other),
            },
            other => panic!("unexpected cycle syscall arg: {:?}", other),
        }
    }

    #[test]
    fn parses_vma64_alias_forms() {
        let descs = parse_syscall_descs(
            r#"
                syscall use_vma64@1 -> int(addr vma64, sized vma64[2:3], opt ptr[in, vma64[1:2]])
            "#,
        )
        .expect("vma64 aliases should parse");

        assert!(matches!(
            descs[0].args[0],
            ArgType::Vma {
                min_pages: 1,
                max_pages: 4,
                optional: false
            }
        ));
        assert!(matches!(
            descs[0].args[1],
            ArgType::Vma {
                min_pages: 2,
                max_pages: 3,
                optional: false
            }
        ));
        assert!(matches!(
            descs[0].args[2],
            ArgType::Ptr { ref inner, .. }
                if matches!(inner.as_ref(), ArgType::Vma { min_pages: 1, max_pages: 2, .. })
        ));
    }
}
