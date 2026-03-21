use rand::Rng;
use std::collections::HashMap;

// ============================================================
// Syscall metadata for Linux/amd64 minimal subset
// ============================================================

/// Argument type for syscall parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgType {
    /// Integer constant or flags.
    Const {
        size: usize, // 1, 2, 4, or 8 bytes
        values: Vec<u64>, // possible values (empty = any)
    },
    /// File descriptor (resource).
    Fd,
    /// Pointer to a buffer.
    Ptr {
        inner: Box<ArgType>,
        dir: PtrDir,
    },
    /// Raw data buffer.
    Buffer {
        min_size: usize,
        max_size: usize,
    },
    /// Filename string.
    Filename,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PtrDir {
    In,
    Out,
    InOut,
}

/// Syscall descriptor.
#[derive(Debug, Clone)]
pub struct SyscallDesc {
    pub name: &'static str,
    pub id: u64, // syzkaller internal ID (index into executor's syscalls[] table for linux/amd64)
    pub args: Vec<ArgType>,
    pub ret: ReturnType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReturnType {
    None,
    Fd, // returns a file descriptor
    Int,
}

/// A concrete argument value.
#[derive(Debug, Clone)]
pub enum ArgValue {
    Const(u64),
    FdRef(usize), // index of the call that created this fd
    FdNew,        // placeholder: this call creates a new fd
    Buffer(Vec<u8>),
    Filename(String),
    Null,
}

/// A single syscall invocation.
#[derive(Debug, Clone)]
pub struct Call {
    pub syscall_idx: usize, // index into SYSCALLS
    pub args: Vec<ArgValue>,
}

/// A test program: a sequence of syscall invocations.
#[derive(Debug, Clone)]
pub struct Program {
    pub calls: Vec<Call>,
}

// ============================================================
// Physical memory layout (matching syzkaller)
// ============================================================

/// Base virtual address for data in the test process.
pub const DATA_OFFSET: u64 = 0x0000_2000_0000;
/// Page size for argument allocation.
pub const PAGE_SIZE: u64 = 4096;

// ============================================================
// Linux/amd64 syscall table (minimal subset)
// ============================================================

// Common flag values
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;

const AT_FDCWD: u64 = 0xFFFF_FFFF_FFFF_FF9C; // -100 as u64

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;

/// Get the syscall descriptors (initialized at runtime).
pub fn get_syscall_descs() -> Vec<SyscallDesc> {
    vec![
        // 0: openat(dirfd, pathname, flags, mode) -> fd
        SyscallDesc {
            name: "openat",
            id: 4348, // syzkaller linux/amd64 ID
            args: vec![
                ArgType::Const { size: 8, values: vec![AT_FDCWD] },
                ArgType::Filename,
                ArgType::Const { size: 4, values: vec![O_RDONLY, O_WRONLY, O_RDWR, O_CREAT | O_RDWR, O_CREAT | O_WRONLY | O_TRUNC] },
                ArgType::Const { size: 4, values: vec![0o666, 0o777, 0o644] },
            ],
            ret: ReturnType::Fd,
        },
        // 1: close(fd)
        SyscallDesc {
            name: "close",
            id: 246,
            args: vec![ArgType::Fd],
            ret: ReturnType::Int,
        },
        // 2: read(fd, buf, count)
        SyscallDesc {
            name: "read",
            id: 5264,
            args: vec![
                ArgType::Fd,
                ArgType::Ptr { inner: Box::new(ArgType::Buffer { min_size: 1, max_size: 256 }), dir: PtrDir::Out },
                ArgType::Const { size: 8, values: vec![16, 64, 128, 256] },
            ],
            ret: ReturnType::Int,
        },
        // 3: write(fd, buf, count)
        SyscallDesc {
            name: "write",
            id: 7686,
            args: vec![
                ArgType::Fd,
                ArgType::Ptr { inner: Box::new(ArgType::Buffer { min_size: 1, max_size: 256 }), dir: PtrDir::In },
                ArgType::Const { size: 8, values: vec![16, 64, 128, 256] },
            ],
            ret: ReturnType::Int,
        },
        // 4: pipe2(pipefd[2], flags) -> 0 on success
        SyscallDesc {
            name: "pipe2",
            id: 4916,
            args: vec![
                ArgType::Ptr { inner: Box::new(ArgType::Buffer { min_size: 8, max_size: 8 }), dir: PtrDir::Out },
                ArgType::Const { size: 4, values: vec![0, O_CLOEXEC, O_NONBLOCK] },
            ],
            ret: ReturnType::Int,
        },
        // 5: dup3(oldfd, newfd, flags) -> fd
        SyscallDesc {
            name: "dup3",
            id: 297,
            args: vec![
                ArgType::Fd,
                ArgType::Fd,
                ArgType::Const { size: 4, values: vec![0, O_CLOEXEC] },
            ],
            ret: ReturnType::Fd,
        },
        // 6: socket(domain, type, protocol) -> fd
        SyscallDesc {
            name: "socket",
            id: 7256,
            args: vec![
                ArgType::Const { size: 4, values: vec![AF_INET, AF_INET6, AF_UNIX] },
                ArgType::Const { size: 4, values: vec![SOCK_STREAM, SOCK_DGRAM] },
                ArgType::Const { size: 4, values: vec![0] },
            ],
            ret: ReturnType::Fd,
        },
        // 7: eventfd2(initval, flags) -> fd
        SyscallDesc {
            name: "eventfd2",
            id: 318,
            args: vec![
                ArgType::Const { size: 4, values: vec![0, 1] },
                ArgType::Const { size: 4, values: vec![0, O_CLOEXEC, O_NONBLOCK] },
            ],
            ret: ReturnType::Fd,
        },
        // 8: mmap(addr, length, prot, flags, fd, offset)
        SyscallDesc {
            name: "mmap",
            id: 4214,
            args: vec![
                ArgType::Const { size: 8, values: vec![0] },
                ArgType::Const { size: 8, values: vec![PAGE_SIZE, PAGE_SIZE * 2, PAGE_SIZE * 4] },
                ArgType::Const { size: 4, values: vec![PROT_READ, PROT_WRITE, PROT_READ | PROT_WRITE] },
                ArgType::Const { size: 4, values: vec![MAP_PRIVATE | MAP_ANONYMOUS] },
                ArgType::Const { size: 4, values: vec![0xFFFF_FFFF_FFFF_FFFFu64] },
                ArgType::Const { size: 8, values: vec![0] },
            ],
            ret: ReturnType::Int,
        },
        // 9: munmap(addr, length)
        SyscallDesc {
            name: "munmap",
            id: 4331,
            args: vec![
                ArgType::Const { size: 8, values: vec![DATA_OFFSET] },
                ArgType::Const { size: 8, values: vec![PAGE_SIZE] },
            ],
            ret: ReturnType::Int,
        },
        // 10: mprotect(addr, length, prot)
        SyscallDesc {
            name: "mprotect",
            id: 4287,
            args: vec![
                ArgType::Const { size: 8, values: vec![DATA_OFFSET] },
                ArgType::Const { size: 8, values: vec![PAGE_SIZE] },
                ArgType::Const { size: 4, values: vec![PROT_READ, PROT_WRITE, PROT_READ | PROT_WRITE] },
            ],
            ret: ReturnType::Int,
        },
        // 11: mkdirat(dirfd, path, mode)
        SyscallDesc {
            name: "mkdirat",
            id: 4196,
            args: vec![
                ArgType::Const { size: 8, values: vec![AT_FDCWD] },
                ArgType::Filename,
                ArgType::Const { size: 4, values: vec![0o777, 0o755] },
            ],
            ret: ReturnType::Int,
        },
        // 12: unlinkat(dirfd, path, flags)
        SyscallDesc {
            name: "unlinkat",
            id: 7659,
            args: vec![
                ArgType::Const { size: 8, values: vec![AT_FDCWD] },
                ArgType::Filename,
                ArgType::Const { size: 4, values: vec![0, 0x200] },
            ],
            ret: ReturnType::Int,
        },
        // 13: fstat(fd, statbuf)
        SyscallDesc {
            name: "fstat",
            id: 480,
            args: vec![
                ArgType::Fd,
                ArgType::Ptr { inner: Box::new(ArgType::Buffer { min_size: 144, max_size: 144 }), dir: PtrDir::Out },
            ],
            ret: ReturnType::Int,
        },
        // 14: getcwd(buf, size)
        SyscallDesc {
            name: "getcwd",
            id: 504,
            args: vec![
                ArgType::Ptr { inner: Box::new(ArgType::Buffer { min_size: 128, max_size: 128 }), dir: PtrDir::Out },
                ArgType::Const { size: 8, values: vec![128] },
            ],
            ret: ReturnType::Int,
        },
        // 15: getpid()
        SyscallDesc {
            name: "getpid",
            id: 537,
            args: vec![],
            ret: ReturnType::Int,
        },
        // 16: getuid()
        SyscallDesc {
            name: "getuid",
            id: 856,
            args: vec![],
            ret: ReturnType::Int,
        },
        // 17: ioctl(fd, request, arg)
        SyscallDesc {
            name: "ioctl",
            id: 955,
            args: vec![
                ArgType::Fd,
                ArgType::Const { size: 8, values: vec![0x5401, 0x5402, 0x540B, 0x5421] },
                ArgType::Const { size: 8, values: vec![0] },
            ],
            ret: ReturnType::Int,
        },
    ]
}

/// Generate random filenames for fuzzing.
pub fn random_filename(rng: &mut impl Rng) -> String {
    let names = [
        "./file0", "./file1", "./file2",
        "./dir0/file0", "./dir1/file1",
        "/tmp/syz0", "/tmp/syz1",
        "./a", "./b", "./c",
    ];
    names[rng.gen_range(0..names.len())].to_string()
}

/// Collect indices of syscalls that produce file descriptors.
pub fn fd_producing_syscalls(descs: &[SyscallDesc]) -> Vec<usize> {
    descs.iter().enumerate()
        .filter(|(_, d)| d.ret == ReturnType::Fd)
        .map(|(i, _)| i)
        .collect()
}

/// Collect indices of syscalls that consume file descriptors.
pub fn fd_consuming_syscalls(descs: &[SyscallDesc]) -> Vec<usize> {
    descs.iter().enumerate()
        .filter(|(_, d)| d.args.iter().any(|a| matches!(a, ArgType::Fd)))
        .map(|(i, _)| i)
        .collect()
}
