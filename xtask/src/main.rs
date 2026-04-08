use std::process::Command;
use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
enum Options {
    BuildEbpf,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();

    match opts {
        Options::BuildEbpf => build_ebpf()?,
    }

    Ok(())
}

fn build_ebpf() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--package", "botguard-ebpf",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release",
        ])
        .status()
        .context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!("✅ eBPF programs compiled successfully.");
    Ok(())
}
