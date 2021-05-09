use std::process::Command;
use std::env;

fn main() {
    let current_dir = env::current_dir().unwrap();
    let mut out_dir = current_dir.clone();
    out_dir.push("target");
    out_dir.push("target");
    out_dir.push("debug");
    //let out_dir = "/home/akira/src/hv-fw/rust-hypervisor-firmware/target/target/debug";

    let mut reloc_src = current_dir.clone();
    reloc_src.push("reloc_test_bin");
    Command::new("sh").args(&["cargo", "build", "--target", "target.json", "-Zbuild-std=core", "-Zbuild-std-features=compiler-builtins-mem", "--verbose"])
                         .current_dir(reloc_src.as_path())
                         .status()
                         .unwrap();

    Command::new("strip").arg("reloc_test_bin")
                         .current_dir(out_dir.as_path())
                         .status()
                         .unwrap();
    Command::new("objcopy").args(&["-Ibinary", "-Bi386", "-Oelf64-x86-64"])
                           .args(&["--rename-section", ".data=.bin.reloc.data,alloc,load,data,contents"])
                           .arg("reloc_test_bin")
                           .arg("reloc_test_bin.o")
                           .current_dir(out_dir.as_path())
                           .status()
                           .unwrap();
    Command::new("ar").args(&["crus"])
                      .arg("libreloc_test_bin.a")
                      .arg("reloc_test_bin.o")
                      .current_dir(out_dir.as_path())
                      .status()
                      .unwrap();

    println!("cargo:rustc-link-search=native={}",
             out_dir.as_path().to_str().unwrap());
    println!("cargo:rustc-link-lib=static=reloc_test_bin");
    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed={}",
             reloc_src.as_path().to_str().unwrap());
}
