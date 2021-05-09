use std::process::Command;
//use std::env;
use std::path::Path;

fn main() {
    let out_dir = "/home/akira/src/hv-fw/rust-hypervisor-firmware/target/target/debug";

    Command::new("strip").arg("reloc_test_bin")
                         .current_dir(&Path::new(&out_dir))
                         .status()
                         .unwrap();
    Command::new("objcopy").args(&["-Ibinary", "-Bi386", "-Oelf64-x86-64"])
                           .args(&["--rename-section", ".data=.bin.reloc.data,alloc,load,data,contents"])
                           .arg("reloc_test_bin")
                           .arg("reloc_test_bin.o")
                           .current_dir(&Path::new(&out_dir))
                           .status()
                           .unwrap();
    Command::new("ar").args(&["crus"])
                      .arg("libreloc_test_bin.a")
                      .arg("reloc_test_bin.o")
                      .current_dir(&Path::new(&out_dir))
                      .status()
                      .unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=reloc_test_bin");
    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed={}", out_dir);
}
