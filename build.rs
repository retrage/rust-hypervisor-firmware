/*
use llvm_tools;
use std::{
    env,
    path::PathBuf,
    process::{self, Command},
};
*/

fn main() {
    println!("cargo:rerun-if-changed=aarch64-unknown-none.json");
    println!("cargo:rerun-if-changed=aarch64-unknown-none.ld");
    println!("cargo:rerun-if-changed=x86_64-unknown-none.json");
    println!("cargo:rerun-if-changed=x86_64-unknown-none.ld");

    /*
    let target = env::var("TARGET").expect("TARGET not set");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    if target == "aarch64-unknown-none" {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

        let llvm_tools = match llvm_tools::LlvmTools::new() {
            Ok(tools) => tools,
            Err(llvm_tools::Error::NotFound) => {
                eprintln!("Error: llvm-tools not found");
                eprintln!("Maybe the rustup component `llvm-tools-preview` is missing?");
                eprintln!("  Install it through: `rustup component add llvm-tools-preview`");
                process::exit(1);
            }
            Err(err) => {
                eprintln!("Failed to retrieve llvm-tools component: {:?}", err);
                process::exit(1);
            }
        };

        let firmware_elf_name = "hypervisor-fw";
        let firmware_elf = out_dir.join(&firmware_elf_name);

        assert!(
            firmware_elf.exists(),
            "The firmware ELF does not exist: {}",
            firmware_elf.display()
        );

        let firmware_bin_name = format!("{}.bin", firmware_elf_name);
        let firmware_bin = out_dir.join(&firmware_bin_name);
        let objcopy = llvm_tools
            .tool(&llvm_tools::exe("llvm-objcopy"))
            .expect("llvm-objcopy not found in llvm-tools");
        let mut cmd = Command::new(&objcopy);
        cmd.arg("--output-target=binary");
        cmd.arg(&firmware_elf);
        cmd.arg(&firmware_bin);
        let exit_status = cmd
            .status()
            .expect("Failed to run objcopy to create raw binary");
        if !exit_status.success() {
            eprintln!("Error: Creating raw binary failed");
            process::exit(1);
        }
    }
    */
}
