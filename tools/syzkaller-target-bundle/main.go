package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type skipCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type filterSet map[string]struct{}

func newFilterSet(values []string) filterSet {
	ret := make(filterSet, len(values))
	for _, value := range values {
		ret[value] = struct{}{}
	}
	return ret
}

func (f filterSet) Allow(name string) bool {
	if len(f) == 0 {
		return true
	}
	_, ok := f[name]
	return ok
}

type skipSummary map[string]int

func newSkipSummary() skipSummary {
	return make(skipSummary)
}

func (s skipSummary) Note(reason string) {
	s[reason]++
}

func (s skipSummary) Counts() []skipCount {
	out := make([]skipCount, 0, len(s))
	for reason, count := range s {
		out = append(out, skipCount{Reason: reason, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

type bundleDocument struct {
	FormatVersion int                 `json:"format_version"`
	Source        bundleSource        `json:"source"`
	ExportSummary bundleExportSummary `json:"export_summary"`
	Syscalls      []bundleSyscall     `json:"syscalls"`
}

type bundleSource struct {
	Kind                 string `json:"kind"`
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	SyzkallerGitRevision string `json:"syzkaller_git_revision"`
}

type bundleExportSummary struct {
	TotalSyscalls    int         `json:"total_syscalls"`
	ExportedSyscalls int         `json:"exported_syscalls"`
	SkippedSyscalls  int         `json:"skipped_syscalls"`
	SkipReasons      []skipCount `json:"skip_reasons"`
}

type bundleSyscall struct {
	Name     string          `json:"name"`
	ID       uint64          `json:"id"`
	ArgNames []string        `json:"arg_names"`
	Args     []any           `json:"args"`
	Ret      any             `json:"ret"`
	Attrs    bundleCallAttrs `json:"attrs"`
}

type bundleCallAttrs struct {
	AutomaticHelper bool    `json:"automatic_helper"`
	NoGenerate      bool    `json:"no_generate"`
	Disabled        bool    `json:"disabled"`
	IgnoreReturn    bool    `json:"ignore_return"`
	BreaksReturns   bool    `json:"breaks_returns"`
	NoMinimize      bool    `json:"no_minimize"`
	NoSquash        bool    `json:"no_squash"`
	RemoteCover     bool    `json:"remote_cover"`
	Snapshot        bool    `json:"snapshot"`
	KfuzzTest       bool    `json:"kfuzz_test"`
	TimeoutMS       *uint64 `json:"timeout_ms"`
	ProgTimeoutMS   *uint64 `json:"prog_timeout_ms"`
	FsckCommand     *string `json:"fsck_command"`
}

func readAllowedSyscallsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read syscall manifest %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	allowed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allowed = append(allowed, line)
	}
	return allowed, nil
}

func loadAllowedSyscalls(args []string, syscallsFile string) ([]string, error) {
	allowed := append([]string{}, args...)
	if syscallsFile == "" {
		return allowed, nil
	}

	fromFile, err := readAllowedSyscallsFile(syscallsFile)
	if err != nil {
		return nil, err
	}
	return append(fromFile, allowed...), nil
}

func buildBundle(osName, arch string, allowed []string) (bundleDocument, error) {
	target, err := prog.GetTarget(osName, arch)
	if err != nil {
		return bundleDocument{}, err
	}

	filter := newFilterSet(allowed)
	skips := newSkipSummary()
	exported := make([]bundleSyscall, 0, len(target.Syscalls))
	considered := 0
	for _, call := range target.Syscalls {
		if !filter.Allow(call.Name) {
			continue
		}
		considered++
		desc, reason, ok := exportSyscall(call)
		if !ok {
			skips.Note(reason)
			continue
		}
		exported = append(exported, desc)
	}

	return bundleDocument{
		FormatVersion: 1,
		Source: bundleSource{
			Kind:                 "upstream-syzkaller",
			OS:                   osName,
			Arch:                 arch,
			SyzkallerGitRevision: "local-replace",
		},
		ExportSummary: bundleExportSummary{
			TotalSyscalls:    considered,
			ExportedSyscalls: len(exported),
			SkippedSyscalls:  considered - len(exported),
			SkipReasons:      skips.Counts(),
		},
		Syscalls: exported,
	}, nil
}

func exportSyscall(call *prog.Syscall) (bundleSyscall, string, bool) {
	args := make([]any, 0, len(call.Args))
	argNames := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		exported, reason, ok := exportType(arg.Type)
		if !ok {
			return bundleSyscall{}, fmt.Sprintf("%s: %s", call.Name, reason), false
		}
		args = append(args, exported)
		argNames = append(argNames, arg.Name)
	}
	ret, ok := exportReturn(call.Ret)
	if !ok {
		return bundleSyscall{}, fmt.Sprintf("%s: unsupported return type", call.Name), false
	}

	return bundleSyscall{
		Name:     call.Name,
		ID:       uint64(call.ID),
		ArgNames: argNames,
		Args:     args,
		Ret:      ret,
		Attrs:    exportAttrs(call.Attrs),
	}, "", true
}

func exportReturn(ret prog.Type) (any, bool) {
	if ret == nil {
		return "None", true
	}
	if resource, ok := ret.(*prog.ResourceType); ok {
		exported, _, ok := exportResourceType(resource)
		return map[string]any{"Resource": exported}, ok
	}
	return "Int", true
}

func exportType(typ prog.Type) (any, string, bool) {
	switch t := typ.(type) {
	case *prog.ResourceType:
		exported, tag, ok := exportResourceType(t)
		if !ok {
			return nil, "unsupported resource type", false
		}
		return map[string]any{tag: exported}, "", true
	case *prog.ConstType:
		if t.Size() == 0 {
			return "Void", "", true
		}
		exported, ok := exportConstVariant(int(t.Size()), []uint64{t.Val}, nil, false, t.Format(), t.BitfieldLength())
		if !ok {
			return nil, "unsupported const format", false
		}
		return exported, "", true
	case *prog.IntType:
		var valueRange any
		allowAny := true
		if t.Kind == prog.IntRange {
			valueRange = []uint64{t.RangeBegin, t.RangeEnd}
			allowAny = false
		}
		exported, ok := exportConstVariant(int(t.Size()), nil, valueRange, allowAny, t.Format(), t.BitfieldLength())
		if !ok {
			return nil, "unsupported int format", false
		}
		return exported, "", true
	case *prog.FlagsType:
		exported, ok := exportConstVariant(int(t.Size()), append([]uint64{}, t.Vals...), nil, false, t.Format(), t.BitfieldLength())
		if !ok {
			return nil, "unsupported flags format", false
		}
		return exported, "", true
	case *prog.PtrType:
		inner, reason, ok := exportType(t.Elem)
		if !ok {
			return nil, reason, false
		}
		dir, ok := exportPtrDir(t.ElemDir)
		if !ok {
			return nil, "unsupported pointer direction", false
		}
		return map[string]any{
			"Ptr": map[string]any{
				"inner":    inner,
				"dir":      dir,
				"optional": t.Optional(),
			},
		}, "", true
	case *prog.BufferType:
		return exportBufferType(t)
	case *prog.StructType:
		return exportStructType(t)
	case *prog.LenType:
		return exportLenType(t)
	case *prog.VmaType:
		return exportVmaType(t), "", true
	case *prog.ArrayType:
		return exportArrayType(t)
	case *prog.UnionType:
		return exportUnionType(t)
	case *prog.ProcType:
		return exportProcType(t)
	default:
		return nil, fmt.Sprintf("unsupported type %T", typ), false
	}
}

func exportResourceType(t *prog.ResourceType) (map[string]any, string, bool) {
	resource := map[string]any{
		"kind":    t.Desc.Name,
		"size":    int(t.Size()),
		"values":  append([]uint64{}, t.Desc.Values...),
		"lineage": append([]string{}, t.Desc.Kind...),
	}
	tag := "Resource"
	if t.Optional() {
		tag = "OptionalResource"
	}
	return resource, tag, true
}

func exportConstVariant(
	size int,
	values []uint64,
	valueRange any,
	allowAny bool,
	format prog.BinaryFormat,
	bitfieldLength uint64,
) (map[string]any, bool) {
	endian, ok := exportEndian(format)
	if !ok {
		return nil, false
	}
	if values == nil {
		values = []uint64{}
	}
	if size > 8 {
		if valueRange == nil && !allowAny && allZeroValues(values) && bitfieldLength == 0 {
			return exportWideZeroConstStruct(size), true
		}
		return nil, false
	}

	var bitfield any
	if bitfieldLength != 0 {
		bitfield = bitfieldLength
	}

	return map[string]any{
		"Const": map[string]any{
			"size":          size,
			"values":        values,
			"range":         valueRange,
			"endian":        endian,
			"allow_any":     allowAny,
			"bitfield_bits": bitfield,
		},
	}, true
}

func allZeroValues(values []uint64) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}

func exportWideZeroConstStruct(size int) map[string]any {
	fields := make([]any, 0, (size+7)/8)
	fieldNames := make([]string, 0, (size+7)/8)
	fieldDirs := make([]any, 0, (size+7)/8)
	remaining := size
	index := 0
	for remaining > 0 {
		chunk := 8
		if remaining < chunk {
			chunk = remaining
		}
		fields = append(fields, map[string]any{
			"Const": map[string]any{
				"size":          chunk,
				"values":        []uint64{0},
				"range":         nil,
				"endian":        "Native",
				"allow_any":     false,
				"bitfield_bits": nil,
			},
		})
		fieldNames = append(fieldNames, fmt.Sprintf("chunk%d", index))
		fieldDirs = append(fieldDirs, nil)
		remaining -= chunk
		index++
	}
	return map[string]any{
		"Struct": map[string]any{
			"type_name":     nil,
			"fields":        fields,
			"field_names":   fieldNames,
			"field_dirs":    fieldDirs,
			"size":          size,
			"varlen":        false,
			"packed":        true,
			"align":         nil,
			"overlay_start": nil,
		},
	}
}

func exportEndian(format prog.BinaryFormat) (string, bool) {
	switch format {
	case prog.FormatNative:
		return "Native", true
	case prog.FormatBigEndian:
		return "Big", true
	default:
		return "", false
	}
}

func exportPtrDir(dir prog.Dir) (string, bool) {
	switch dir {
	case prog.DirIn:
		return "In", true
	case prog.DirOut:
		return "Out", true
	case prog.DirInOut:
		return "InOut", true
	default:
		return "", false
	}
}

func exportBufferType(t *prog.BufferType) (any, string, bool) {
	switch t.Kind {
	case prog.BufferFilename:
		if !t.Varlen() || t.NoZ {
			var fixedLen any
			if !t.Varlen() {
				fixedLen = int(t.Size())
			}
			return map[string]any{
				"String": map[string]any{
					"values":    []any{},
					"noz":       t.NoZ,
					"fixed_len": fixedLen,
					"filename":  true,
				},
			}, "", true
		}
		return "Filename", "", true
	case prog.BufferBlobRand:
		if t.Varlen() {
			return map[string]any{
				"Buffer": map[string]any{
					"min_size": 0,
					"max_size": 4096,
					"dir":      "Plain",
				},
			}, "", true
		}
		return map[string]any{
			"Buffer": map[string]any{
				"min_size": int(t.Size()),
				"max_size": int(t.Size()),
				"dir":      "Plain",
			},
		}, "", true
	case prog.BufferBlobRange:
		return map[string]any{
			"Buffer": map[string]any{
				"min_size": int(t.RangeBegin),
				"max_size": int(t.RangeEnd),
				"dir":      "Plain",
			},
		}, "", true
	case prog.BufferString:
		values := make([]any, 0, len(t.Values))
		for _, value := range t.Values {
			raw := []byte(value)
			if !t.NoZ && len(raw) > 0 && raw[len(raw)-1] == 0 {
				raw = raw[:len(raw)-1]
			}
			encoded := make([]int, 0, len(raw))
			for _, b := range raw {
				encoded = append(encoded, int(b))
			}
			values = append(values, encoded)
		}
		var fixedLen any
		if !t.Varlen() {
			fixedLen = int(t.Size())
		}
		return map[string]any{
			"String": map[string]any{
				"values":    values,
				"noz":       t.NoZ,
				"fixed_len": fixedLen,
				"filename":  false,
			},
		}, "", true
	default:
		return nil, fmt.Sprintf("unsupported buffer kind %d", t.Kind), false
	}
}

func exportStructType(t *prog.StructType) (any, string, bool) {
	fields := make([]any, 0, len(t.Fields))
	fieldNames := make([]string, 0, len(t.Fields))
	fieldDirs := make([]any, 0, len(t.Fields))
	for _, field := range t.Fields {
		if field.Condition != nil {
			return nil, "unsupported conditional struct field", false
		}
		exported, reason, ok := exportType(field.Type)
		if !ok {
			return nil, reason, false
		}
		fields = append(fields, exported)
		fieldNames = append(fieldNames, field.Name)
		if field.HasDirection {
			dir, ok := exportPtrDir(field.Direction)
			if !ok {
				return nil, "unsupported struct field direction", false
			}
			fieldDirs = append(fieldDirs, dir)
		} else {
			fieldDirs = append(fieldDirs, nil)
		}
	}

	var typeName any
	if t.TemplateName() != "" {
		typeName = t.TemplateName()
	}
	var align any
	if t.AlignAttr != 0 {
		align = int(t.AlignAttr)
	}
	var overlayStart any
	if t.OverlayField != 0 {
		overlayStart = t.OverlayField
	}
	size := int(t.TypeSize)
	if t.Varlen() {
		prefixSize := exportedStructPrefixSize(fields)
		if size < prefixSize {
			size = prefixSize
		}
	}

	return map[string]any{
		"Struct": map[string]any{
			"type_name":     typeName,
			"fields":        fields,
			"field_names":   fieldNames,
			"field_dirs":    fieldDirs,
			"size":          size,
			"varlen":        t.Varlen(),
			"packed":        true,
			"align":         align,
			"overlay_start": overlayStart,
		},
	}, "", true
}

func exportArrayType(t *prog.ArrayType) (any, string, bool) {
	inner, reason, ok := exportType(t.Elem)
	if !ok {
		return nil, reason, false
	}

	minLen := 0
	maxLen := 10
	if t.Kind == prog.ArrayRangeLen {
		minLen = int(t.RangeBegin)
		maxLen = int(t.RangeEnd)
	}
	if maxLen < minLen {
		maxLen = minLen
	}

	return map[string]any{
		"Array": map[string]any{
			"inner":   inner,
			"min_len": minLen,
			"max_len": maxLen,
		},
	}, "", true
}

func exportUnionType(t *prog.UnionType) (any, string, bool) {
	fields := make([]any, 0, len(t.Fields))
	fieldNames := make([]string, 0, len(t.Fields))
	fieldDirs := make([]any, 0, len(t.Fields))
	for _, field := range t.Fields {
		if field.Condition != nil {
			return nil, "unsupported conditional union field", false
		}
		exported, reason, ok := exportType(field.Type)
		if !ok {
			return nil, reason, false
		}
		fields = append(fields, exported)
		fieldNames = append(fieldNames, field.Name)
		if field.HasDirection {
			dir, ok := exportPtrDir(field.Direction)
			if !ok {
				return nil, "unsupported union field direction", false
			}
			fieldDirs = append(fieldDirs, dir)
		} else {
			fieldDirs = append(fieldDirs, nil)
		}
	}

	var typeName any
	if t.TemplateName() != "" {
		typeName = t.TemplateName()
	}
	size := int(t.TypeSize)
	if t.Varlen() {
		minSize := exportedVarlenUnionMinSize(fields)
		if size < minSize {
			size = minSize
		}
	}

	return map[string]any{
		"Union": map[string]any{
			"type_name":   typeName,
			"fields":      fields,
			"field_names": fieldNames,
			"field_dirs":  fieldDirs,
			"size":        size,
			"varlen":      t.Varlen(),
			"packed":      true,
			"align":       nil,
		},
	}, "", true
}

func exportProcType(t *prog.ProcType) (any, string, bool) {
	endian, ok := exportEndian(t.Format())
	if !ok {
		return nil, "unsupported proc format", false
	}
	return map[string]any{
		"Proc": map[string]any{
			"size":            int(t.Size()),
			"values_start":    t.ValuesStart,
			"values_per_proc": t.ValuesPerProc,
			"endian":          endian,
		},
	}, "", true
}

func exportLenType(t *prog.LenType) (any, string, bool) {
	if len(t.Path) == 0 {
		return nil, "unsupported empty len path", false
	}
	endian, ok := exportEndian(t.Format())
	if !ok {
		return nil, "unsupported len format", false
	}

	root, fields, ok := exportLengthTarget(t.Path)
	if !ok {
		return nil, "unsupported len target path", false
	}

	kind := "Auto"
	scale := 1
	if t.Offset {
		kind = "Offset"
		if t.BitSize != 0 {
			scale = int(t.BitSize / 8)
		}
	} else if t.BitSize != 0 {
		kind = "Bytes"
		scale = int(t.BitSize / 8)
	}
	if scale == 0 {
		scale = 1
	}

	var bitfield any
	if t.BitfieldLength() != 0 {
		bitfield = t.BitfieldLength()
	}

	return map[string]any{
		"Len": map[string]any{
			"target": map[string]any{
				"root":   root,
				"fields": fields,
			},
			"size":          int(t.Size()),
			"kind":          kind,
			"endian":        endian,
			"scale":         scale,
			"bitfield_bits": bitfield,
		},
	}, "", true
}

func exportLengthTarget(path []string) (any, []string, bool) {
	if len(path) == 0 {
		return nil, nil, false
	}
	if path[0] == prog.SyscallRef {
		if len(path) < 2 {
			return nil, nil, false
		}
		return map[string]any{"Arg": path[1]}, append([]string{}, path[2:]...), true
	}
	parentHops := 0
	for parentHops < len(path) && path[parentHops] == prog.ParentRef {
		parentHops++
	}
	if parentHops > 0 {
		return map[string]any{"Parent": parentHops}, append([]string{}, path[parentHops:]...), true
	}
	return map[string]any{"Arg": path[0]}, append([]string{}, path[1:]...), true
}

func exportVmaType(t *prog.VmaType) any {
	minPages := int(t.RangeBegin)
	maxPages := int(t.RangeEnd)
	if minPages == 0 && maxPages == 0 {
		minPages = 1
		maxPages = 4
	}
	if minPages == 0 {
		minPages = 1
	}
	if maxPages < minPages {
		maxPages = minPages
	}
	return map[string]any{
		"Vma": map[string]any{
			"min_pages": minPages,
			"max_pages": maxPages,
			"optional":  t.Optional(),
		},
	}
}

func exportedStructPrefixSize(fields []any) int {
	size := 0
	for _, field := range fields {
		fieldSize, fixed := exportedArgFixedSize(field)
		if !fixed {
			break
		}
		size += fieldSize
	}
	return size
}

func exportedVarlenUnionMinSize(fields []any) int {
	maxSize := 0
	for _, field := range fields {
		fieldSize, fixed := exportedArgFixedSize(field)
		if fixed && fieldSize > maxSize {
			maxSize = fieldSize
		}
	}
	return maxSize
}

func exportedArgFixedSize(value any) (int, bool) {
	switch node := value.(type) {
	case string:
		if node == "Void" {
			return 0, true
		}
		return 0, false
	case map[string]any:
		if payload, ok := node["Const"].(map[string]any); ok {
			size, _ := payload["size"].(int)
			return size, true
		}
		if payload, ok := node["Proc"].(map[string]any); ok {
			size, _ := payload["size"].(int)
			return size, true
		}
		if payload, ok := node["Resource"].(map[string]any); ok {
			size, _ := payload["size"].(int)
			return size, true
		}
		if payload, ok := node["OptionalResource"].(map[string]any); ok {
			size, _ := payload["size"].(int)
			return size, true
		}
		if _, ok := node["Ptr"]; ok {
			return 8, true
		}
		if _, ok := node["Vma"]; ok {
			return 8, true
		}
		if payload, ok := node["Len"].(map[string]any); ok {
			size, _ := payload["size"].(int)
			return size, true
		}
		if payload, ok := node["Buffer"].(map[string]any); ok {
			minSize, minOK := payload["min_size"].(int)
			maxSize, maxOK := payload["max_size"].(int)
			if minOK && maxOK && minSize == maxSize {
				return maxSize, true
			}
			return 0, false
		}
		if payload, ok := node["String"].(map[string]any); ok {
			fixedLen, ok := payload["fixed_len"].(int)
			return fixedLen, ok
		}
		if payload, ok := node["Struct"].(map[string]any); ok {
			varlen, _ := payload["varlen"].(bool)
			if !varlen {
				size, _ := payload["size"].(int)
				return size, true
			}
			return 0, false
		}
		if payload, ok := node["Union"].(map[string]any); ok {
			varlen, _ := payload["varlen"].(bool)
			if !varlen {
				size, _ := payload["size"].(int)
				return size, true
			}
			return 0, false
		}
		if payload, ok := node["Array"].(map[string]any); ok {
			minLen, minOK := payload["min_len"].(int)
			maxLen, maxOK := payload["max_len"].(int)
			inner, innerOK := payload["inner"]
			if !minOK || !maxOK || !innerOK || minLen != maxLen {
				return 0, false
			}
			innerSize, fixed := exportedArgFixedSize(inner)
			if !fixed {
				return 0, false
			}
			return innerSize * minLen, true
		}
	}
	return 0, false
}

func exportAttrs(attrs prog.SyscallAttrs) bundleCallAttrs {
	timeout := zeroAsNil(attrs.Timeout)
	progTimeout := zeroAsNil(attrs.ProgTimeout)
	fsck := stringAsNil(attrs.Fsck)
	return bundleCallAttrs{
		AutomaticHelper: attrs.AutomaticHelper,
		NoGenerate:      attrs.NoGenerate,
		Disabled:        attrs.Disabled,
		IgnoreReturn:    attrs.IgnoreReturn,
		BreaksReturns:   attrs.BreaksReturns,
		NoMinimize:      attrs.NoMinimize,
		NoSquash:        false,
		RemoteCover:     attrs.RemoteCover,
		Snapshot:        false,
		KfuzzTest:       false,
		TimeoutMS:       timeout,
		ProgTimeoutMS:   progTimeout,
		FsckCommand:     fsck,
	}
}

func zeroAsNil(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

func stringAsNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func main() {
	var output string
	var syscallsFile string
	flag.StringVar(&output, "output", "", "path to the JSON bundle to write")
	flag.StringVar(&syscallsFile, "syscalls-file", "", "optional newline-delimited syscall manifest")
	flag.Parse()

	allowed, err := loadAllowedSyscalls(flag.Args(), syscallsFile)
	if err != nil {
		panic(err)
	}

	doc, err := buildBundle("linux", "amd64", allowed)
	if err != nil {
		panic(err)
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}

	if output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			panic(err)
		}
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			panic(err)
		}
		return
	}

	if err := os.WriteFile(output, data, 0o644); err != nil {
		panic(fmt.Errorf("write %s: %w", output, err))
	}
}
