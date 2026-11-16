//! Read-only metadata export, not a VM guest or recursive verification routine.
use anyhow::Result;
use recursive_imt_poc::{client, codec};
use spartan_whir::{PoseidonEngine, QuinticExtension};
fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: inspect-client <trusted-client-vk.bin>"))?;
    let mut vk: client::VerifyingKey = codec::read(std::path::Path::new(&path), 2)?;
    vk.authenticate()
        .map_err(|e| anyhow::anyhow!("key authentication: {e:?}"))?;
    let cfg =
        spartan_whir::full_zk_spark_guest_verifier_config::<PoseidonEngine<QuinticExtension>>(&vk)
            .map_err(|e| anyhow::anyhow!("config export: {e:?}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"purpose":"Public verifier metadata audit only; no VM/guest","key_id":codec::id(2,&vk)?,"domain":vk.domain_separator(),"derived":cfg})
        )?
    );
    Ok(())
}
