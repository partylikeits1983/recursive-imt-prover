//! Root-only IMT prover using the pinned LeanVM child verifier, WHIR and deferred bytecode argument.
use crate::{
    cells::cell_bytes,
    child::gen_verify,
    deferred::{DeferredBytecodeClaim, aggregate_deferred_claims, bytecode_sums},
    guest::{fs_seed, unified_guest},
    hints::Hints,
    proof::AggregateProof,
};
use experimental_lean_vm_core::ExperimentalProver as P;
use fiat_shamir_prover::merkle::hash_to_scalars;
use isa::Prover;
use lean_vm_core::cpu::{from_scalar, public_input_bytes, to_scalar};
use primitives::field::F128;
use std::time::{Duration, Instant};

type Hash = [u8; 32];
const MASKED_CLIENT: bool = false;
const BENCHMARK_LEAVES: usize = 64;
const LEAF_LOG_INV_RATE: usize = 2;
const MERGE_LOG_INV_RATE: usize = 1;

fn hash(parts: &[&[u8]]) -> Hash {
    keccak256::hash(&parts.concat())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Statement {
    digest: Hash,
    count: u8,
}

impl Statement {
    fn leaf(root: Hash) -> Self {
        Self {
            digest: hash(&[b"IMT-AGG-LEAF-V3", &root, &[0; 64]]),
            count: 1,
        }
    }
    fn merge(a: Self, b: Self) -> Self {
        assert!(a.count == b.count && a.count.is_power_of_two() && a.count <= 32);
        Self {
            digest: hash(&[
                b"IMT-AGG-NODE-V2",
                &a.digest,
                &[a.count],
                &b.digest,
                &[b.count],
            ]),
            count: 2 * a.count,
        }
    }
    fn public(self, d: &DeferredBytecodeClaim) -> [F128; 2] {
        let header = fs_seed()
            .into_iter()
            .chain(hash_to_scalars(&self.digest))
            .chain([
                F128::from(u128::from(self.count)),
                F128::ZERO,
                F128::ZERO,
                F128::ZERO,
            ]);
        hash_to_scalars(&keccak256::hash(&cell_bytes(header.chain(d.cells()))))
    }
}

struct Node {
    claim: Statement,
    proof: AggregateProof,
    cycles: usize,
}

#[derive(Clone, Copy)]
enum Transcript {
    Recursive,
    Terminal,
}

fn verify(proof: &AggregateProof, claim: Statement) -> bool {
    verify_with_transcript(proof, claim, Transcript::Recursive)
}

fn verify_with_transcript(
    proof: &AggregateProof,
    claim: Statement,
    transcript: Transcript,
) -> bool {
    let deferred = DeferredBytecodeClaim::recompute(proof.bytecode_point.clone());
    let check = match transcript {
        Transcript::Recursive => verifier::verify_execution,
        Transcript::Terminal => verifier::verify_hash_chain_execution,
    };
    check(
        unified_guest().bytecode(),
        &public_input_bytes(&claim.public(&deferred)),
        &proof.proof,
    )
    .is_ok()
}

fn start(claim: Statement) -> Hints {
    let mut hints = Hints::default();
    hints.push("count", vec![F128::from(u128::from(claim.count))]);
    hints.push("fs_seed", fs_seed().to_vec());
    hints
}

fn split(h: &mut Hints, digest: Hash) {
    for bytes in digest.chunks_exact(16) {
        h.push(
            "word_bits",
            (0..128)
                .map(|i| F128::from(u128::from((bytes[i / 8] >> (i % 8)) & 1)))
                .collect(),
        );
    }
}

fn prove(
    claim: Statement,
    hints: Hints,
    d: DeferredBytecodeClaim,
    rate: usize,
    transcript: Transcript,
) -> Result<Node, String> {
    let (proof, stats) = P::prove_with_transcript(
        unified_guest(),
        &hints.witness(),
        claim.public(&d).map(|x| to_scalar(&x)),
        rate,
        matches!(transcript, Transcript::Terminal),
    )
    .map_err(|error| error.to_string())?;
    Ok(Node {
        claim,
        cycles: stats.cycles,
        proof: AggregateProof {
            bytecode_point: d.bytecode_point,
            proof,
        },
    })
}

fn leaf(secret: &Hash, index: u32, path: &[Hash; 32]) -> Result<Node, String> {
    let mut root = hash(&[b"IMT-PREIMAGE-V01", secret]);
    let mut entries = Vec::new();
    for (level, sibling) in path.iter().enumerate() {
        let side = (index >> level) & 1;
        let mut entry = hash_to_scalars(sibling).to_vec();
        entry.push(F128::from(u128::from(side)));
        entries.push(entry);
        let pair = if side == 0 {
            [root, *sibling]
        } else {
            [*sibling, root]
        };
        root = hash(&[b"IMT-KECCAK-NODE1", &pair[0], &pair[1]]);
    }
    let claim = Statement::leaf(root);
    let d = DeferredBytecodeClaim::leaf();
    let mut h = start(claim);
    h.push("preimage", hash_to_scalars(secret).to_vec());
    for entry in entries {
        h.push("path", entry);
    }
    split(&mut h, root);
    h.push("leaf_defer", vec![d.bytecode_value]);
    prove(claim, h, d, LEAF_LOG_INV_RATE, Transcript::Recursive)
}

/// Input contains only the public root and the decoded masked proof transcript.
fn masked_leaf(input: &std::path::Path) -> Result<Node, String> {
    use std::io::Read;
    let mut data = Vec::new();
    const MAX_BYTES:u64 = 64 << 20;
    std::fs::File::open(input).and_then(|f|f.take(MAX_BYTES+1).read_to_end(&mut data)).map_err(|e|e.to_string())?;
    if data.len() as u64 > MAX_BYTES {return Err("oversize masked leaf input".into());}
    let mut bytes = data.as_slice();
    fn take<'a>(bytes:&mut &'a [u8], n:usize)->Result<&'a [u8],String> {
        let (a,b)=bytes.split_at_checked(n).ok_or("truncated masked leaf input")?;
        *bytes=b;Ok(a)
    }
    fn size(bytes:&mut &[u8])->Result<usize,String> {
        Ok(u32::from_le_bytes(take(bytes,4)?.try_into().unwrap()) as usize)
    }
    if take(&mut bytes,8)?!=b"IMTZKH01" {return Err("invalid masked leaf format".into());}
    let root:Hash=take(&mut bytes,32)?.try_into().unwrap();
    let claim=Statement::leaf(root);
    let mut h=start(claim);
    let mut names=std::collections::BTreeSet::new();
    let n=size(&mut bytes)?;
    if n>4096 {return Err("too many masked proof streams".into());}
    for _ in 0..n {
        let length=size(&mut bytes)?;
        if !(1..=96).contains(&length){return Err("invalid masked proof key".into());}
        let key=std::str::from_utf8(take(&mut bytes,length)?).map_err(|e|e.to_string())?;
        if matches!(key,"count"|"fs_seed"|"child_count"|"child_digests"|"word_bits"|"leaf_defer") || !names.insert(key) {return Err("reserved or duplicate proof stream".into());}
        let entries=size(&mut bytes)?;
        if entries>bytes.len()/4 {return Err("truncated stream".into());}
        let mut stream=Vec::new();
        for _ in 0..entries {
            let words=size(&mut bytes)?;
            if words==0 || words>bytes.len()/16 {return Err("invalid hint entry".into());}
            stream.push(take(&mut bytes,16*words)?.as_chunks::<16>().0.iter().map(|x|F128::from(u128::from_le_bytes(*x))).collect());
        }
        h.0.push((key.to_owned(),stream));
    }
    if !bytes.is_empty(){return Err("trailing masked proof streams".into());}
    let d=DeferredBytecodeClaim::leaf();
    split(&mut h,root);
    h.push("leaf_defer",vec![d.bytecode_value]);
    prove(claim,h,d,LEAF_LOG_INV_RATE,Transcript::Recursive)
}

// A deterministic growing tree. Each user opens a different leaf at a different later root.
fn leaves(batch: usize) -> Result<Vec<Node>, String> {
    let secrets: Vec<_> = (0..batch)
        .map(|i| hash(&[b"imt-recursion-secret", &[i as u8]]))
        .collect();
    let mut leaves: Vec<_> = secrets
        .iter()
        .map(|s| hash(&[b"IMT-PREIMAGE-V01", s]))
        .collect();
    let mut nodes = Vec::new();
    for (index, secret) in secrets.iter().enumerate() {
        leaves.push(hash(&[b"imt-recursion-append", &[index as u8]]));
        let mut layer = leaves.clone();
        let mut empty = [0; 32];
        let mut pos = index;
        let mut path = Vec::new();
        for _ in 0..32 {
            path.push(*layer.get(pos ^ 1).unwrap_or(&empty));
            if layer.len() % 2 == 1 {
                layer.push(empty);
            }
            layer = layer
                .chunks_exact(2)
                .map(|p| hash(&[b"IMT-KECCAK-NODE1", &p[0], &p[1]]))
                .collect();
            empty = hash(&[b"IMT-KECCAK-NODE1", &empty, &empty]);
            pos >>= 1;
        }
        let [root] = layer[..] else {
            panic!("expected one IMT root")
        };
        let node = leaf(secret, index as u32, &path.try_into().unwrap())?;
        assert!(node.claim == Statement::leaf(root));
        nodes.push(node);
    }
    Ok(nodes)
}

fn merge(a: &Node, b: &Node, rate: usize, transcript: Transcript) -> Result<Node, String> {
    let children = [a, b];
    let claim = Statement::merge(a.claim, b.claim);
    let mut h = start(claim);
    h.push("child_count", vec![F128::from(u128::from(a.claim.count))]);
    h.push(
        "child_digests",
        children
            .iter()
            .flat_map(|c| hash_to_scalars(&c.claim.digest))
            .collect(),
    );
    split(&mut h, a.claim.digest);
    let carried_points: Vec<_> = children
        .iter()
        .map(|n| n.proof.bytecode_point.clone())
        .collect();
    let carried_sums = bytecode_sums::<P>(&carried_points);
    let carried: Vec<_> = carried_points
        .into_iter()
        .zip(&carried_sums)
        .map(|(p, s)| DeferredBytecodeClaim::from_sums(p, s))
        .collect();
    let public: Vec<_> = children
        .iter()
        .zip(&carried)
        .map(|(n, d)| n.claim.public(d))
        .collect();
    let program = unified_guest();
    let summaries: Vec<_> = children
        .iter()
        .zip(&public)
        .map(|(n, p)| {
            verifier::replay_unchecked(program.bytecode(), &public_input_bytes(p), &n.proof.proof)
                .unwrap()
        })
        .collect();
    let points: Vec<Vec<F128>> = summaries
        .iter()
        .map(|s| s.bytecode_point.iter().copied().map(from_scalar).collect())
        .collect();
    let fresh_sums = bytecode_sums::<P>(&points);
    let kbc = program.prog.len().trailing_zeros() as usize;
    let mut claims = Vec::with_capacity(4);
    for (i, p) in points.into_iter().enumerate() {
        h.push("child_defer", carried[i].cells());
        h.extend(gen_verify(kbc, &children[i].proof.proof, &summaries[i]).unwrap());
        claims.extend([
            DeferredBytecodeClaim::from_sums(p, &fresh_sums[i]),
            carried[i].clone(),
        ]);
    }
    let sums = fresh_sums
        .into_iter()
        .zip(carried_sums)
        .flat_map(|(a, b)| [a, b])
        .collect();
    let (batch, d) = aggregate_deferred_claims::<P>(&public, &claims, sums);
    h.extend(batch);
    prove(claim, h, d, rate, transcript)
}

fn benchmark(batch: usize, rate: usize, out: Option<&std::path::Path>) -> Result<(), String> {
    if !batch.is_power_of_two() || !(2..=64).contains(&batch) {
        return Err("batch must be a power of two from 2 to 64".into());
    }
    if let Some(dir) = out {
        std::fs::create_dir(dir).map_err(|e| e.to_string())?;
    }
    let _ = unified_guest();
    let t = Instant::now();
    let mut layer = leaves(batch)?;
    println!(
        "leaves count={batch} total_s={:.3} first_bytes={}",
        t.elapsed().as_secs_f64(),
        layer[0].proof.to_bytes().len()
    );
    assert!(layer.iter().all(|n| verify(&n.proof, n.claim)));
    let mut expected: Vec<_> = layer.iter().map(|n| n.claim).collect();
    while expected.len() > 1 {
        expected = expected
            .chunks_exact(2)
            .map(|p| Statement::merge(p[0], p[1]))
            .collect();
    }
    let mut total = Duration::ZERO;
    while layer.len() > 1 {
        if layer.len() == 2
            && let Some(dir) = out
        {
            save(&dir.join("left.imt"), &layer[0])?;
            save(&dir.join("right.imt"), &layer[1])?;
        }
        let t = Instant::now();
        let next: Vec<_> = layer
            .chunks_exact(2)
            .map(|pair| {
                merge(
                    &pair[0],
                    &pair[1],
                    if layer.len() == 2 {
                        rate
                    } else {
                        MERGE_LOG_INV_RATE
                    },
                    Transcript::Recursive,
                )
            })
            .collect::<Result<_, _>>()?;
        let elapsed = t.elapsed();
        total += elapsed;
        println!(
            "merges={} leaves_per_node={} total_s={:.3} mean_s={:.3} first_cycles={} first_bytes={}",
            next.len(),
            next[0].claim.count,
            elapsed.as_secs_f64(),
            elapsed.as_secs_f64() / next.len() as f64,
            next[0].cycles,
            next[0].proof.to_bytes().len()
        );
        layer = next;
    }
    if let Some(dir) = out {
        save(&dir.join("root.imt"), &layer[0])?;
    }
    let wire = layer[0].proof.to_bytes();
    let proof = AggregateProof::from_bytes(&wire).unwrap();
    let t = Instant::now();
    assert!(verify(&proof, expected[0]));
    let elapsed = t.elapsed();
    let mut wrong = expected[0];
    wrong.digest[0] ^= 1;
    assert!(!verify(&proof, wrong));
    assert!(!verify(
        &proof,
        Statement {
            count: expected[0].count / 2,
            ..expected[0]
        }
    ));
    let mut bad = proof;
    bad.bytecode_point[0] += F128::ONE;
    assert!(!verify(&bad, expected[0]));
    println!(
        "root verified count={batch} bytes={} native_verify_ms={:.3} all_merges_s={:.3}",
        wire.len(),
        elapsed.as_secs_f64() * 1000.,
        total.as_secs_f64()
    );
    report(&layer[0]);
    Ok(())
}

fn report(n: &Node) {
    let wire = n.proof.to_bytes();
    println!(
        "digest={} count={} proof_bytes={} zero_bytes={}",
        hex(&n.claim.digest),
        n.claim.count,
        wire.len(),
        wire.iter().filter(|&&byte| byte == 0).count(),
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}

fn save(path: &std::path::Path, n: &Node) -> Result<(), String> {
    use std::io::Write;
    let mut data = n.claim.digest.to_vec();
    data.push(n.claim.count);
    data.extend(n.proof.to_bytes());
    std::fs::File::create_new(path)
        .and_then(|mut f| f.write_all(&data))
        .map_err(|e| e.to_string())
}

fn load(path: &str) -> Result<Node, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let (header, wire) = data.split_at_checked(33).ok_or("short IMT bundle")?;
    let count = header[32];
    if !count.is_power_of_two() || count > 64 {
        return Err("invalid IMT count".into());
    }
    Ok(Node {
        claim: Statement {
            digest: header[..32].try_into().unwrap(),
            count,
        },
        proof: AggregateProof::from_bytes(wire).ok_or("invalid proof encoding")?,
        cycles: 0,
    })
}

// One long-lived prover per CLI job. The coordinator writes synthetic witnesses
// into its private job directory and sends only the level and position of a ready node.
fn worker() -> Result<(), String> {
    use std::io::{self, BufRead, Write};
    let mut replies = io::stdout().lock();
    writeln!(
        replies,
        "ready {}",
        hex(&unified_guest().bytecode().fiat_shamir_iv())
    )
    .and_then(|()| replies.flush())
    .map_err(|e| e.to_string())?;
    for request in io::stdin().lock().lines() {
        let line = request.map_err(|e| e.to_string())?;
        let (level, index) = line.split_once(' ').ok_or("expected level and index")?;
        let level = level.parse::<usize>().map_err(|e| e.to_string())?;
        let index = index.parse::<usize>().map_err(|e| e.to_string())?;
        if level > 6 || index >= (64 >> level) {
            return Err("invalid proof tree position".into());
        }
        let start = Instant::now();
        let node = if level == 0 && MASKED_CLIENT {
            masked_leaf(std::path::Path::new(&format!("{index}.masked")))?
        } else if level == 0 {
            let data = std::fs::read(format!("{index}.witness")).map_err(|e| e.to_string())?;
            leaf_from_bytes(&data)?
        } else {
            let left = load(&format!("{}-{}.imt", level - 1, 2 * index))?;
            let right = load(&format!("{}-{}.imt", level - 1, 2 * index + 1))?;
            if left.claim.count != 1 << (level - 1) || right.claim.count != left.claim.count {
                return Err("unexpected child counts".into());
            }
            merge(&left, &right, MERGE_LOG_INV_RATE, Transcript::Recursive)?
        };
        let prove_ms = start.elapsed().as_secs_f64() * 1000.;
        let t = Instant::now();
        if !verify(&node.proof, node.claim) {
            return Err("generated node failed native verification".into());
        }
        let verify_ms = t.elapsed().as_secs_f64() * 1000.;
        let path = format!("{level}-{index}.imt");
        save(std::path::Path::new(&path), &node)?;
        writeln!(
            replies,
            "{} {} {} {}",
            hex(&node.claim.digest),
            node.proof.to_bytes().len(),
            prove_ms,
            verify_ms
        )
        .and_then(|()| replies.flush())
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn leaf_from_bytes(data: &[u8]) -> Result<Node, String> {
    if data.len() != 32 + 4 + 32 * 32 {
        return Err("expected a preimage, little-endian u32 index and 32 siblings".into());
    }
    let index = u32::from_le_bytes(data[32..36].try_into().unwrap());
    let path = data[36..].as_chunks::<32>().0.try_into().unwrap();
    leaf(data[..32].try_into().unwrap(), index, path)
}

pub fn run(args: &[String]) -> Result<(), String> {
    use std::path::Path;
    let threads = match std::env::var("IMT_THREADS") {
        Ok(value) => value.parse::<usize>().map_err(|e| e.to_string())?,
        Err(std::env::VarError::NotPresent) => 5,
        Err(e) => return Err(e.to_string()),
    };
    P::set_num_threads(threads);
    P::init();
    if args != ["worker"] {
        eprintln!(
            "Experimental LeanVM profile with non-hiding proofs and a {}-bit per-round target.",
            verifier::SECURITY_BITS,
        );
    }
    let rate = |s: &str, max: usize| {
        s.parse::<usize>()
            .ok()
            .filter(|v| (verifier::MIN_LOG_INV_RATE..=max).contains(v))
            .ok_or_else(|| format!("root log inverse rate must be 1..{max}"))
    };
    match args {
        [cmd] if cmd == "worker" => worker(),
        [cmd] if cmd == "benchmark" => benchmark(BENCHMARK_LEAVES, MERGE_LOG_INV_RATE, None),
        [cmd,input,output] if cmd=="masked-leaf" && MASKED_CLIENT => {
            let t=Instant::now();
            let node=masked_leaf(Path::new(input))?;
            if !verify(&node.proof,node.claim) {return Err("invalid masked leaf execution proof".into());}
            save(Path::new(output),&node)?;
            println!("masked_leaf_s={:.3} cycles={}",t.elapsed().as_secs_f64(),node.cycles);
            report(&node);
            Ok(())
        }
        [cmd, flag, dir] if cmd == "benchmark" && flag == "--out" => {
            benchmark(BENCHMARK_LEAVES, MERGE_LOG_INV_RATE, Some(Path::new(dir)))
        }
        [cmd, batch, r, rest @ ..] if cmd == "benchmark" && rest.len() <= 1 => {
            let batch = batch.parse::<usize>().map_err(|e| e.to_string())?;
            benchmark(batch, rate(r, verifier::MAX_LOG_INV_RATE)?, rest.first().map(Path::new))
        }
        [cmd, input, output] if cmd == "leaf" => {
            let data = std::fs::read(input).map_err(|e| e.to_string())?;
            let node = leaf_from_bytes(&data)?;
            if !verify(&node.proof, node.claim) {
                return Err("invalid generated leaf".into());
            }
            save(Path::new(output), &node)?;
            report(&node);
            Ok(())
        }
        [cmd, left, right, r @ .., output] if matches!(cmd.as_str(), "merge" | "terminal-merge") && r.len() <= 1 => {
            let (transcript, default_rate, max_rate) = if cmd == "terminal-merge" {
                (Transcript::Terminal, 4, 5)
            } else {
                (Transcript::Recursive, MERGE_LOG_INV_RATE, verifier::MAX_LOG_INV_RATE)
            };
            let log_inv_rate = r.first().map(|s| rate(s, max_rate)).transpose()?.unwrap_or(default_rate);
            let a = load(left)?;
            let b = load(right)?;
            if a.claim.count != b.claim.count || a.claim.count > 32 {
                return Err("incompatible child counts".into());
            }
            if !verify(&a.proof, a.claim) || !verify(&b.proof, b.claim) {
                return Err("invalid child proof".into());
            }
            let t = Instant::now();
            let node = merge(&a, &b, log_inv_rate, transcript)?;
            println!("parent_s={:.3} cycles={}", t.elapsed().as_secs_f64(), node.cycles);
            if !verify_with_transcript(&node.proof, node.claim, transcript) {
                return Err("invalid generated parent".into());
            }
            save(Path::new(output), &node)?;
            report(&node);
            Ok(())
        }
        [cmd, file, digest, count] if matches!(cmd.as_str(), "verify" | "verify-terminal") => {
            let node = load(file)?;
            if digest != &hex(&node.claim.digest) || count != &node.claim.count.to_string() {
                return Err("unexpected IMT statement".into());
            }
            let transcript = if cmd == "verify-terminal" { Transcript::Terminal } else { Transcript::Recursive };
            if !verify_with_transcript(&node.proof, node.claim, transcript) {
                return Err("invalid proof".into());
            }
            report(&node);
            Ok(())
        }
        _ => Err("expected benchmark [--out NEW_DIR | COUNT ROOT_LOG_INV_RATE [NEW_DIR]], leaf WITNESS BUNDLE, (merge | terminal-merge) LEFT RIGHT [ROOT_LOG_INV_RATE] BUNDLE, or (verify | verify-terminal) BUNDLE EXPECTED_DIGEST COUNT".into()),
    }
}
