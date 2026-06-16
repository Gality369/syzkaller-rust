use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::OnceLock;

const TMPFS_MOUNT_IMAGE_SYSCALL: &str = "syz_mount_image$tmpfs";
const READ_PART_TABLE_SYSCALL: &str = "syz_read_part_table";
const MOUNT_IMAGE_PREFIX: &str = "syz_mount_image$";
const KVM_ASSERT_PREFIX: &str = "syz_kvm_assert_";
const MOUNT_IMAGE_ARG_IDX: usize = 6;
const READ_PART_TABLE_ARG_IDX: usize = 1;

pub fn has_builtin_generation_support(name: &str) -> bool {
    if name == TMPFS_MOUNT_IMAGE_SYSCALL {
        return true;
    }
    compressed_image_seed_map().contains_key(name)
}

pub fn non_fuzzer_helper_reason(name: &str, kfuzz_test: bool) -> Option<&'static str> {
    if name.starts_with(KVM_ASSERT_PREFIX) {
        Some("test-only helper")
    } else if kfuzz_test {
        Some("specialized kfuzz_test helper")
    } else {
        None
    }
}

pub fn is_non_fuzzer_helper(name: &str, kfuzz_test: bool) -> bool {
    non_fuzzer_helper_reason(name, kfuzz_test).is_some()
}

pub fn special_buffer_arg_bytes(desc_name: &str, arg_idx: usize) -> Option<&'static [u8]> {
    match (desc_name, arg_idx) {
        (TMPFS_MOUNT_IMAGE_SYSCALL, MOUNT_IMAGE_ARG_IDX) => Some(&[]),
        (READ_PART_TABLE_SYSCALL, READ_PART_TABLE_ARG_IDX) => compressed_image_seed_map()
            .get(desc_name)
            .map(|seed| seed.as_ref()),
        (name, MOUNT_IMAGE_ARG_IDX) if name.starts_with(MOUNT_IMAGE_PREFIX) => {
            compressed_image_seed_map()
                .get(name)
                .map(|seed| seed.as_ref())
        }
        _ => None,
    }
}

fn compressed_image_seed_map() -> &'static HashMap<&'static str, Box<[u8]>> {
    static SEEDS: OnceLock<HashMap<&'static str, Box<[u8]>>> = OnceLock::new();
    SEEDS.get_or_init(|| {
        include_str!("../data/linux_amd64_compressed_image_seeds.tsv")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (name, encoded) = line.split_once('\t').unwrap_or_else(|| {
                    panic!("malformed linux_amd64_compressed_image_seeds.tsv entry: {line}")
                });
                let seed = STANDARD.decode(encoded).unwrap_or_else(|err| {
                    panic!("invalid base64 seed for {name}: {err}");
                });
                (name, seed.into_boxed_slice())
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_seed_backed_linux_helpers() {
        assert!(has_builtin_generation_support("syz_read_part_table"));
        assert!(has_builtin_generation_support("syz_mount_image$ext4"));
        assert!(has_builtin_generation_support("syz_mount_image$tmpfs"));
        assert!(!has_builtin_generation_support("eventfd2"));
    }

    #[test]
    fn returns_special_buffer_bytes_for_seeded_helpers() {
        assert!(
            special_buffer_arg_bytes("syz_read_part_table", 1)
                .expect("part-table helper should have a seed")
                .len()
                > 16
        );
        assert!(
            special_buffer_arg_bytes("syz_mount_image$ext4", 6)
                .expect("ext4 mount helper should have a seed")
                .len()
                > 16
        );
        assert_eq!(
            special_buffer_arg_bytes("syz_mount_image$tmpfs", 6),
            Some(&[][..])
        );
        assert!(special_buffer_arg_bytes("syz_mount_image$ext4", 5).is_none());
    }

    #[test]
    fn classifies_non_fuzzer_helpers() {
        assert_eq!(
            non_fuzzer_helper_reason("syz_kvm_assert_syzos_uexit$x86", false),
            Some("test-only helper")
        );
        assert_eq!(
            non_fuzzer_helper_reason("syz_kfuzztest_run", true),
            Some("specialized kfuzz_test helper")
        );
        assert!(!is_non_fuzzer_helper("eventfd2", false));
    }
}
