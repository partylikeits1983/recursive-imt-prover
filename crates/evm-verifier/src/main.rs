use std::{
    env, fs,
    io::{self, Write},
};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let (Some(root), Some(path), None) = (args.next(), args.next(), args.next()) else {
        bail!("usage: evm-verifier <expected-root-hex> <terminal-proof.abi>");
    };
    let root = root.to_str().context("root must be hexadecimal")?;
    let root = root.strip_prefix("0x").unwrap_or(root);
    let mut bytes = [0; 32];
    hex::decode_to_slice(root, &mut bytes)
        .context("expected eight big-endian u32 root elements")?;
    let elements: [[u8; 4]; 8] = bytes.as_chunks::<4>().0.try_into().expect("32 bytes");
    let proof = fs::read(path).context("read terminal proof")?;
    let calldata = evm_verifier::verify_calldata(elements.map(u32::from_be_bytes), &proof)?;
    io::stdout().lock().write_all(&calldata)?;
    Ok(())
}
