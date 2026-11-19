use sha3::{Digest, Keccak256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

fn main() -> io::Result<()> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = [
        "build.rs",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ]
    .map(PathBuf::from)
    .to_vec();
    for package in [
        "",
        "crates/flock-backend",
        "vendor/p3-recursion",
        "vendor/p3-sumcheck",
        "vendor/p3-multi-stark",
        "vendor/p3-gkr",
        "vendor/p3-bus",
    ] {
        let directory = Path::new(package);
        files.push(directory.join("Cargo.toml"));
        collect_sources(&root, &directory.join("src"), &mut files)?;
    }
    files.sort();
    let mut keccak = Keccak256::new();
    for relative in files {
        let path = root.join(&relative);
        println!("cargo:rerun-if-changed={}", path.display());
        let name = relative.to_string_lossy();
        let contents = fs::read(path)?;
        for bytes in [name.as_bytes(), &[0], contents.as_slice(), &[0]] {
            keccak.update(bytes);
        }
    }
    println!(
        "cargo:rustc-env=IMT_SOURCE_KECCAK256={:x}",
        keccak.finalize()
    );
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
