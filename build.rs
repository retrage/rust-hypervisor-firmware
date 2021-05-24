use std::process::Command;
use std::env;
use std::path::{Path, PathBuf};

fn build_lib(src_path: &Path) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_path = src_path.join("Cargo.toml");

    let mut build_cmd = Command::new(env!("CARGO"));
    build_cmd.current_dir(src_path);
    build_cmd.arg("build");
    build_cmd
        .arg("--manifest-path")
        .arg(&manifest_path);
    build_cmd
        .arg("--target")
        .arg("target.json");
    build_cmd
        .arg("-Zbuild-std=core,alloc");
    build_cmd
        .arg("-Zbuild-std-features=compiler-builtins-mem");
    build_cmd
        .arg("-Zunstable-options");
    build_cmd
        .arg("--out-dir")
        .arg(&out_dir);
    build_cmd
        .arg("--verbose");

    if !build_cmd.status().unwrap().success() {
        panic!("build failed");
    }

    let elf_name = src_path
        .file_name().expect("Invalid ELF file name")
        .to_str().expect("Failed to convert to str");
    let elf_path = PathBuf::from(&out_dir).join(elf_name);

    assert!(elf_path.exists(), "{} does not exist", elf_path.display());

    let obj_name = format!("{}.o", elf_name);
    let obj_path = PathBuf::from(&out_dir).join(obj_name);

    let mut objcopy = Command::new("objcopy");
    objcopy
        .arg("-Ibinary")
        .arg("-Bi386")
        .arg("-Oelf64-x86-64");
    objcopy
        .arg("--rename-section")
        .arg(".data=.bin.data,alloc,load,data,contents");
    objcopy
        .arg(elf_path)
        .arg(&obj_path);

    if !objcopy.status().unwrap().success() {
        panic!("objcopy failed");
    }

    let lib_name = format!("lib{}.a", elf_name);
    let lib_path = PathBuf::from(&out_dir).join(lib_name);
    let mut ar = Command::new("ar");
    ar
        .arg("crus")
        .arg(lib_path)
        .arg(obj_path);

    if !ar.status().unwrap().success() {
        panic!("ar failed");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.as_path().display());
    println!("cargo:rustc-link-lib=static={}", &elf_name);
    println!("cargo:rerun-if-changed={}", src_path.display());
}

fn main() {
    let mut cur_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    cur_dir.push("efi_runtime");

    build_lib(cur_dir.as_path());

    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");
}
