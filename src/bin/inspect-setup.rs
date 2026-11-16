//! Explicit parameter validation experiment; never lowers the security target.
use anyhow::Result;
use recursive_imt_poc::{client, fixtures};
fn main() -> Result<()> {
    let f = fixtures::pair(8, false)?;
    let c = client::build(8, &f.clients[0], &f.witnesses[0])?;
    println!("{}", serde_json::to_string(&c.stats)?);
    for pow in [10, 12, 16, 22] {
        let mut cfg = client::config();
        cfg.whir_params.pow_bits = pow;
        println!("trying witness PoW ceiling {pow}");
        match client::ProvingKey::setup(c.shape.clone(), cfg.clone()) {
            Ok((_pk, _vk)) => {
                println!("VALID {}", serde_json::to_string(&cfg)?);
                return Ok(());
            }
            Err(e) => println!("REJECTED {e:?}"),
        }
    }
    anyhow::bail!("no supported schedule")
}
