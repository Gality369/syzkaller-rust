package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFilterSetMatchesExplicitNames(t *testing.T) {
	filter := newFilterSet([]string{"openat", "close"})
	if !filter.Allow("openat") {
		t.Fatalf("expected openat to be allowed")
	}
	if filter.Allow("socket") {
		t.Fatalf("did not expect socket to be allowed")
	}
}

func TestReadAllowedSyscallsFileSkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "linux-amd64-core.syscalls")
	data := []byte("# curated bundle seed\nopenat\n\n  read  \n# tail comment\nwritev\n")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("os.WriteFile failed: %v", err)
	}

	got, err := readAllowedSyscallsFile(path)
	if err != nil {
		t.Fatalf("readAllowedSyscallsFile failed: %v", err)
	}
	want := []string{"openat", "read", "writev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected syscall list: got %v want %v", got, want)
	}
}

func TestLoadAllowedSyscallsPrependsManifestEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "linux-amd64-core.syscalls")
	if err := os.WriteFile(path, []byte("openat\nclose\n"), 0o644); err != nil {
		t.Fatalf("os.WriteFile failed: %v", err)
	}

	got, err := loadAllowedSyscalls([]string{"read", "write"}, path)
	if err != nil {
		t.Fatalf("loadAllowedSyscalls failed: %v", err)
	}
	want := []string{"openat", "close", "read", "write"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected merged syscall list: got %v want %v", got, want)
	}
}

func TestSkipSummaryCountsReasons(t *testing.T) {
	summary := newSkipSummary()
	summary.Note("unsupported ptr64")
	summary.Note("unsupported ptr64")
	summary.Note("unsupported text")

	counts := summary.Counts()
	if counts[0].Reason != "unsupported ptr64" || counts[0].Count != 2 {
		t.Fatalf("unexpected first count: %+v", counts[0])
	}
	if counts[1].Reason != "unsupported text" || counts[1].Count != 1 {
		t.Fatalf("unexpected second count: %+v", counts[1])
	}
}

func TestBuildBundleExportsSimpleFilteredSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"getpid"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if doc.FormatVersion != 1 {
		t.Fatalf("unexpected format version: %d", doc.FormatVersion)
	}
	if doc.Source.Kind != "upstream-syzkaller" || doc.Source.OS != "linux" || doc.Source.Arch != "amd64" {
		t.Fatalf("unexpected source: %+v", doc.Source)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	if doc.Syscalls[0].Name != "getpid" {
		t.Fatalf("unexpected syscall export: %+v", doc.Syscalls[0])
	}
	if doc.ExportSummary.ExportedSyscalls != 1 {
		t.Fatalf("unexpected export summary: %+v", doc.ExportSummary)
	}
}

func TestBuildBundleExportsResourceAndScalarSyscalls(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"close", "socket"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 2 {
		t.Fatalf("expected 2 syscalls, got %d", len(doc.Syscalls))
	}

	closeCall := doc.Syscalls[0]
	if closeCall.Name != "close" {
		t.Fatalf("unexpected first syscall: %+v", closeCall)
	}
	if len(closeCall.Args) != 1 {
		t.Fatalf("expected close to have 1 arg, got %d", len(closeCall.Args))
	}
	arg0, ok := closeCall.Args[0].(map[string]any)
	if !ok {
		t.Fatalf("expected close arg to be a tagged enum object, got %T", closeCall.Args[0])
	}
	if _, ok := arg0["Resource"]; !ok {
		t.Fatalf("expected close arg to export as Resource, got %+v", arg0)
	}

	socketCall := doc.Syscalls[1]
	if socketCall.Name != "socket" {
		t.Fatalf("unexpected second syscall: %+v", socketCall)
	}
	if len(socketCall.Args) != 3 {
		t.Fatalf("expected socket to have 3 args, got %d", len(socketCall.Args))
	}
	if socketCall.Ret == "Int" {
		t.Fatalf("expected socket return to preserve resource type")
	}
	ret, ok := socketCall.Ret.(map[string]any)
	if !ok {
		t.Fatalf("expected socket return to be a tagged enum object, got %T", socketCall.Ret)
	}
	if _, ok := ret["Resource"]; !ok {
		t.Fatalf("expected socket return to export as Resource, got %+v", ret)
	}
}

func TestBuildBundleExportsFilenamePointerSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"openat"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	call := doc.Syscalls[0]
	if call.Name != "openat" {
		t.Fatalf("unexpected syscall export: %+v", call)
	}
	if len(call.Args) != 4 {
		t.Fatalf("expected openat to have 4 args, got %d", len(call.Args))
	}
	ptr, ok := call.Args[1].(map[string]any)
	if !ok {
		t.Fatalf("expected pathname arg to be tagged enum object, got %T", call.Args[1])
	}
	ptrPayload, ok := ptr["Ptr"].(map[string]any)
	if !ok {
		t.Fatalf("expected pathname arg to export as Ptr, got %+v", ptr)
	}
	inner, ok := ptrPayload["inner"].(string)
	if !ok || inner != "Filename" {
		t.Fatalf("expected pathname pointer inner type to be Filename, got %+v", ptrPayload["inner"])
	}
}

func TestBuildBundleExportsStructuredPointerSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"pipe2"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	call := doc.Syscalls[0]
	if call.Name != "pipe2" {
		t.Fatalf("unexpected syscall export: %+v", call)
	}
	ptr, ok := call.Args[0].(map[string]any)
	if !ok {
		t.Fatalf("expected pipe2 first arg to be tagged enum object, got %T", call.Args[0])
	}
	ptrPayload, ok := ptr["Ptr"].(map[string]any)
	if !ok {
		t.Fatalf("expected pipe2 first arg to export as Ptr, got %+v", ptr)
	}
	inner, ok := ptrPayload["inner"].(map[string]any)
	if !ok {
		t.Fatalf("expected pipe2 inner type to be tagged enum object, got %T", ptrPayload["inner"])
	}
	if _, ok := inner["Struct"]; !ok {
		t.Fatalf("expected pipe2 pointer inner type to be Struct, got %+v", inner)
	}
}

func TestBuildBundleExportsBufferAndLenSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"read"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	call := doc.Syscalls[0]
	if call.Name != "read" {
		t.Fatalf("unexpected syscall export: %+v", call)
	}
	ptr, ok := call.Args[1].(map[string]any)
	if !ok {
		t.Fatalf("expected read buffer arg to be tagged enum object, got %T", call.Args[1])
	}
	ptrPayload, ok := ptr["Ptr"].(map[string]any)
	if !ok {
		t.Fatalf("expected read buffer arg to export as Ptr, got %+v", ptr)
	}
	inner, ok := ptrPayload["inner"].(map[string]any)
	if !ok {
		t.Fatalf("expected read pointer inner type to be tagged enum object, got %T", ptrPayload["inner"])
	}
	if _, ok := inner["Buffer"]; !ok {
		t.Fatalf("expected read pointer inner type to be Buffer, got %+v", inner)
	}
	lenArg, ok := call.Args[2].(map[string]any)
	if !ok {
		t.Fatalf("expected read len arg to be tagged enum object, got %T", call.Args[2])
	}
	if _, ok := lenArg["Len"]; !ok {
		t.Fatalf("expected read len arg to export as Len, got %+v", lenArg)
	}
}

func TestBuildBundleExportsVmaAndLenSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"munmap"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	call := doc.Syscalls[0]
	if call.Name != "munmap" {
		t.Fatalf("unexpected syscall export: %+v", call)
	}
	arg0, ok := call.Args[0].(map[string]any)
	if !ok {
		t.Fatalf("expected munmap first arg to be tagged enum object, got %T", call.Args[0])
	}
	if _, ok := arg0["Vma"]; !ok {
		t.Fatalf("expected munmap first arg to export as Vma, got %+v", arg0)
	}
	arg1, ok := call.Args[1].(map[string]any)
	if !ok {
		t.Fatalf("expected munmap second arg to be tagged enum object, got %T", call.Args[1])
	}
	if _, ok := arg1["Len"]; !ok {
		t.Fatalf("expected munmap second arg to export as Len, got %+v", arg1)
	}
}

func TestBuildBundleExportsRangedIntsWithEmptyValueLists(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"mmap"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(encoded), `"values":null`) {
		t.Fatalf("expected ranged const values to serialize as [], got %s", string(encoded))
	}
}

func TestBuildBundleExportsArraySyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"writev"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(encoded), `"Array"`) {
		t.Fatalf("expected writev export to contain an Array type, got %s", string(encoded))
	}
}

func TestBuildBundleExportsUnionSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"connect"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(encoded), `"Union"`) {
		t.Fatalf("expected connect export to contain a Union type, got %s", string(encoded))
	}
}

func TestBuildBundleExportsVarlenStructSyscall(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"sendmsg"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if len(doc.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(doc.Syscalls))
	}
}

func TestBuildBundleSerializesStringValuesAsByteArrays(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"sendmsg"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(encoded), `"values":["`) {
		t.Fatalf("expected String values to serialize as numeric byte arrays, got %s", string(encoded))
	}
}

func TestBuildBundlePreservesFixedFilenameBuffers(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"accept"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(encoded), `"filename":true`) {
		t.Fatalf("expected accept export to preserve fixed filename buffers as string metadata, got %s", string(encoded))
	}
}

func TestBuildBundleKeepsFixedStringsWithinStorageBounds(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"accept"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if err := assertFixedStringsFit(doc); err != nil {
		t.Fatalf("expected exported fixed strings to fit Rust storage rules: %v", err)
	}
}

func TestBuildBundleDoesNotEmitWideConstScalars(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"accept"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if err := assertNoWideConstScalars(doc); err != nil {
		t.Fatalf("expected exported const scalars to stay within Rust native sizes: %v", err)
	}
}

func TestBuildBundleGivesVarlenStructsTheirFixedPrefixSize(t *testing.T) {
	doc, err := buildBundle("linux", "amd64", []string{"sendmmsg"})
	if err != nil {
		t.Fatalf("buildBundle failed: %v", err)
	}
	if err := assertVarlenStructPrefixSizes(doc); err != nil {
		t.Fatalf("expected exported varlen structs to include their fixed prefix size: %v", err)
	}
}

func assertFixedStringsFit(value any) error {
	switch node := value.(type) {
	case bundleDocument:
		return assertFixedStringsFit(node.Syscalls)
	case []bundleSyscall:
		for _, item := range node {
			if err := assertFixedStringsFit(item); err != nil {
				return err
			}
		}
	case bundleSyscall:
		if err := assertFixedStringsFit(node.Args); err != nil {
			return err
		}
	case []any:
		for _, item := range node {
			if err := assertFixedStringsFit(item); err != nil {
				return err
			}
		}
	case map[string]any:
		if payload, ok := node["String"].(map[string]any); ok {
			noz, _ := payload["noz"].(bool)
			fixedLen, hasFixedLen := payload["fixed_len"].(int)
			if hasFixedLen && !noz {
				values, _ := payload["values"].([]any)
				for _, rawValue := range values {
					bytes, ok := rawValue.([]int)
					if !ok {
						return fmt.Errorf("unexpected string value representation %T", rawValue)
					}
					if len(bytes)+1 > fixedLen {
						return fmt.Errorf("string literal len %d exceeds fixed len %d", len(bytes)+1, fixedLen)
					}
				}
			}
		}
		for _, item := range node {
			if err := assertFixedStringsFit(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func assertNoWideConstScalars(value any) error {
	switch node := value.(type) {
	case bundleDocument:
		return assertNoWideConstScalars(node.Syscalls)
	case []bundleSyscall:
		for _, item := range node {
			if err := assertNoWideConstScalars(item); err != nil {
				return err
			}
		}
	case bundleSyscall:
		if err := assertNoWideConstScalars(node.Args); err != nil {
			return err
		}
	case []any:
		for _, item := range node {
			if err := assertNoWideConstScalars(item); err != nil {
				return err
			}
		}
	case map[string]any:
		if payload, ok := node["Const"].(map[string]any); ok {
			if size, ok := payload["size"].(int); ok && size > 8 {
				return fmt.Errorf("found unsupported const width %d", size)
			}
		}
		for _, item := range node {
			if err := assertNoWideConstScalars(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func assertVarlenStructPrefixSizes(value any) error {
	switch node := value.(type) {
	case bundleDocument:
		return assertVarlenStructPrefixSizes(node.Syscalls)
	case []bundleSyscall:
		for _, item := range node {
			if err := assertVarlenStructPrefixSizes(item); err != nil {
				return err
			}
		}
	case bundleSyscall:
		if err := assertVarlenStructPrefixSizes(node.Args); err != nil {
			return err
		}
	case []any:
		for _, item := range node {
			if err := assertVarlenStructPrefixSizes(item); err != nil {
				return err
			}
		}
	case map[string]any:
		if payload, ok := node["Struct"].(map[string]any); ok {
			if varlen, _ := payload["varlen"].(bool); varlen {
				size, _ := payload["size"].(int)
				fields, _ := payload["fields"].([]any)
				prefix := 0
				for _, field := range fields {
					fieldSize, fixed := exportedFixedSize(field)
					if !fixed {
						break
					}
					prefix += fieldSize
				}
				if size < prefix {
					return fmt.Errorf("varlen struct size %d is smaller than fixed prefix %d", size, prefix)
				}
			}
		}
		for _, item := range node {
			if err := assertVarlenStructPrefixSizes(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func exportedFixedSize(value any) (int, bool) {
	switch node := value.(type) {
	case string:
		if node == "Filename" {
			return 0, false
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
			if fixedLen, ok := payload["fixed_len"].(int); ok {
				return fixedLen, true
			}
			return 0, false
		}
		if payload, ok := node["Struct"].(map[string]any); ok {
			if varlen, _ := payload["varlen"].(bool); !varlen {
				size, _ := payload["size"].(int)
				return size, true
			}
			return 0, false
		}
		if payload, ok := node["Union"].(map[string]any); ok {
			if varlen, _ := payload["varlen"].(bool); !varlen {
				size, _ := payload["size"].(int)
				return size, true
			}
			return 0, false
		}
		if _, ok := node["Void"]; ok {
			return 0, true
		}
		if payload, ok := node["Array"].(map[string]any); ok {
			minLen, minOK := payload["min_len"].(int)
			maxLen, maxOK := payload["max_len"].(int)
			inner, innerOK := payload["inner"]
			if !minOK || !maxOK || !innerOK || minLen != maxLen {
				return 0, false
			}
			innerSize, fixed := exportedFixedSize(inner)
			if !fixed {
				return 0, false
			}
			return innerSize * minLen, true
		}
	}
	return 0, false
}
