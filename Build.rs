// SPDX-License-Identifier: MIT
use std::{env, path::PathBuf, process::Command};

fn main() {
    for file in [
        "Policy.ads",
        "Policy.adb",
        "Configuration.adc",
        "Policy.gpr",
    ] {
        println!("cargo:rerun-if-changed=Policy/{file}");
    }
    println!("cargo:rerun-if-env-changed=GNAT_GCC");
    println!("cargo:rerun-if-env-changed=AR");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let configuration = std::fs::read_to_string(root.join("Policy/Configuration.adc"))
        .expect("Ada restrictions are required");
    std::fs::write(out.join("Configuration.adc"), format!("{configuration}\npragma Source_File_Name (Policy, Spec_File_Name => \"Policy.ads\");\npragma Source_File_Name (Policy, Body_File_Name => \"Policy.adb\");\n"))
        .expect("write Ada source mapping");
    let compiler = env::var_os("GNAT_GCC").unwrap_or_else(|| "gcc".into());
    let mut compile = Command::new(compiler);
    compile
        // Contracts are proved separately. Enabling Ada assertion exceptions at
        // this pure C boundary would permit unwinding into Rust. Normal Ada
        // language checks remain enabled; these unsigned operations cannot raise.
        .args(["-c", "-x", "ada", "-gnat2022", "-gnatwa", "-O2", "-fPIC"])
        .arg(format!("-I{}", root.join("Policy").display()))
        .arg(format!(
            "-gnatec={}",
            out.join("Configuration.adc").display()
        ))
        .arg(root.join("Policy/Policy.adb"))
        .arg("-o")
        .arg(out.join("Policy.o"))
        .current_dir(&out);
    assert!(
        compile
            .status()
            .expect("GNAT compiler is required; set GNAT_GCC")
            .success(),
        "Ada policy compilation failed"
    );
    assert!(
        Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
            .arg("crs")
            .arg(out.join("libHyperNetPolicy.a"))
            .arg(out.join("Policy.o"))
            .status()
            .expect("archiver is required")
            .success(),
        "Ada policy archive failed"
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=HyperNetPolicy");
}
