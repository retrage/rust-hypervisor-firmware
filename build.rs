use std::process::Command;
use std::env;

fn main() {
    let current_dir = env::current_dir().unwrap();
    let mut out_dir = current_dir.clone();
    out_dir.push("target");
    out_dir.push("target");
    out_dir.push("debug");

    let bin_name = "efi_runtime";
    let mut efi_runtime = current_dir.clone();
    efi_runtime.push(bin_name);
    Command::new("sh").args(&["cargo", "build", "--target", "target.json", "-Zbuild-std=core", "-Zbuild-std-features=compiler-builtins-mem", "--verbose"])
                         .current_dir(efi_runtime.as_path())
                         .status()
                         .unwrap();

    /*
    Command::new("strip").arg("reloc_test_bin")
                         .current_dir(out_dir.as_path())
                         .status()
                         .unwrap();
                         */
    let obj_name = format!("{}.o", bin_name);
    Command::new("objcopy").args(&["-Ibinary", "-Bi386", "-Oelf64-x86-64"])
                           .args(&["--rename-section", ".data=.bin.data,alloc,load,data,contents"])
                           .arg(bin_name)
                           .arg(obj_name.as_str())
                           .current_dir(out_dir.as_path())
                           .status()
                           .unwrap();
    let ar_name = format!("lib{}.a", bin_name);
    Command::new("ar").args(&["crus"])
                      .arg(ar_name.as_str())
                      .arg(obj_name.as_str())
                      .current_dir(out_dir.as_path())
                      .status()
                      .unwrap();

    println!("cargo:rustc-link-search=native={}",
             out_dir.as_path().to_str().unwrap());
    println!("cargo:rustc-link-lib=static={}", bin_name);
    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed={}",
             efi_runtime.as_path().to_str().unwrap());
}
