//! File-backed proof nodes and cleanup for one demo invocation.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use recursive_imt_prover::{
    binary::{
        aggregation_tree::TreeProof,
        relation::{AggregatePublic, ClientPublic},
        veil::{aggregate::MaskedChildInput, child::MaskedMembershipProof},
    },
    files::read_bounded,
};
use tempfile::TempDir;

pub(super) fn scratch_directory(parent: &Path) -> Result<TempDir> {
    // Install the handler before allocating the directory. Holding the lock
    // during creation also covers an interrupt between mkdir and registration.
    let pending = Arc::new(Mutex::new(None::<PathBuf>));
    let interrupted = Arc::clone(&pending);
    ctrlc::set_handler(move || {
        if let Some(path) = interrupted.lock().unwrap().as_ref() {
            let _ = fs::remove_dir_all(path);
        }
        std::process::exit(130);
    })
    .context("install demo cleanup handler")?;
    let mut path = pending.lock().unwrap();
    fs::create_dir_all(parent)?;
    let scratch = tempfile::Builder::new()
        .prefix(".tree-demo-")
        .tempdir_in(parent)?;
    *path = Some(scratch.path().to_owned());
    Ok(scratch)
}

#[derive(Clone)]
pub(super) struct StoredProof<P> {
    pub public: P,
    path: PathBuf,
}

impl<P> StoredProof<P> {
    pub fn write(dir: &Path, level: usize, index: usize, public: P, bytes: &[u8]) -> Result<Self> {
        let path = dir.join(format!("{level}-{index}.proof"));
        fs::write(&path, bytes)?;
        Ok(Self { public, path })
    }
}

impl StoredProof<ClientPublic> {
    pub fn load(&self) -> Result<MaskedChildInput> {
        Ok(MaskedChildInput {
            public: self.public.clone(),
            proof: MaskedMembershipProof::from_bytes(&read_bounded(&self.path, 64 << 20)?)?,
        })
    }
}

impl StoredProof<AggregatePublic> {
    pub fn load(&self) -> Result<TreeProof> {
        Ok(TreeProof {
            public: self.public.clone(),
            proof: read_bounded(&self.path, 16 << 20)?,
        })
    }
}
