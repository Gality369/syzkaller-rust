package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		fail(err)
	}

	if len(os.Args) == 1 {
		names := make([]string, 0, len(target.Syscalls))
		for _, call := range target.Syscalls {
			names = append(names, call.Name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		return
	}

	for _, name := range os.Args[1:] {
		call, ok := target.SyscallMap[name]
		if !ok {
			fail(fmt.Errorf("unknown syscall %q", name))
		}
		fmt.Printf("%s %d\n", call.Name, call.ID)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
