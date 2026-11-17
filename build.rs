use sha3::{Digest, Keccak256, Sha3_256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

fn main() -> io::Result<()> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = vec![
        PathBuf::from("build.rs"),
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("crates/flock-backend/Cargo.toml"),
        PathBuf::from("rust-toolchain.toml"),
        PathBuf::from(".cargo/config.toml"),
        PathBuf::from("vendor/p3-recursion/Cargo.toml"),
        PathBuf::from("vendor/p3-sumcheck/Cargo.toml"),
        PathBuf::from("vendor/p3-multi-stark/Cargo.toml"),
    ];
    collect_sources(&root, Path::new("src"), &mut files)?;
    collect_sources(&root, Path::new("crates/flock-backend/src"), &mut files)?;
    collect_sources(&root, Path::new("vendor/p3-recursion/src"), &mut files)?;
    collect_sources(&root, Path::new("vendor/p3-sumcheck/src"), &mut files)?;
    collect_sources(&root, Path::new("vendor/p3-multi-stark/src"), &mut files)?;
    files.sort();
    let mut keccak = Keccak256::new();
    let mut sha3 = Sha3_256::new();
    for relative in files {
        let path = root.join(&relative);
        println!("cargo:rerun-if-changed={}", path.display());
        let name = relative.to_string_lossy();
        let contents = fs::read(path)?;
        // Keep the previous path/NUL/contents/NUL fingerprint framing without
        // embedding megabytes of source text in every benchmark executable.
        for bytes in [name.as_bytes(), &[0], contents.as_slice(), &[0]] {
            keccak.update(bytes);
        }
        // The archived prime CLI used length-prefixed framing for its SHA3 hash.
        sha3.update((name.len() as u64).to_le_bytes());
        sha3.update(name.as_bytes());
        sha3.update((contents.len() as u64).to_le_bytes());
        sha3.update(&contents);
    }
    println!(
        "cargo:rustc-env=IMT_SOURCE_KECCAK256={:x}",
        keccak.finalize()
    );
    println!("cargo:rustc-env=IMT_SOURCE_SHA3_256={:x}", sha3.finalize());
    Ok(())
}

fn collect_sources(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    println!("cargo:rerun-if-changed={}", root.join(directory).display());
    for entry in fs::read_dir(root.join(directory))? {
        let relative = directory.join(entry?.file_name());
        if root.join(&relative).is_dir() {
            collect_sources(root, &relative, files)?;
        } else if relative.extension().is_some_and(|ext| ext == "rs") {
            files.push(relative);
        }
    }
    Ok(())
}
