use std::panic::{AssertUnwindSafe, catch_unwind};

use anyhow::Result;
use p3_air::{Air, AirBuilder, AirLayout, BaseAir, WindowAccess, get_symbolic_constraints};
use p3_challenger::{CanObserve, CanSample, CanSampleBits};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakBinaryAir, generate_binary_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    rounds::AirDegrees,
    zerocheck::{AirZerocheck, transcript::ZerocheckShape},
};
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::layout::Table;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::{NativeAirProgram, NativeProverContext, NativeVerifierContext, Operation};
use crate::binary::veil::{
    E, F,
    compiler::{MaskedProver, MaskedReader},
    constraints::{ExperimentalProof, Linear, Relation},
    parameters::Parameters,
};

struct BooleanAir;

struct TestContext {
    rng: StdRng,
    public: Vec<F>,
    messages: Vec<Vec<E>>,
    challenges: Vec<E>,
    cursor: [usize; 3],
}

impl<F: PrimeCharacteristicRing> BaseAir<F> for BooleanAir {
    fn width(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for BooleanAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        builder.assert_bool(main.current_slice()[0]);
    }
}

impl TestContext {
    fn new() -> Self {
        Self {
            rng: StdRng::seed_from_u64(0x7e57),
            public: vec![],
            messages: vec![],
            challenges: vec![],
            cursor: [0; 3],
        }
    }
}

impl NativeProverContext for TestContext {
    fn public(&mut self, value: F) -> Result<()> {
        self.public.push(value);
        Ok(())
    }
    fn message(&mut self, values: &[E]) -> Result<()> {
        self.messages.push(values.to_vec());
        Ok(())
    }
    fn challenge(&mut self) -> Result<E> {
        let r: E = self.rng.random();
        assert!(r != E::ZERO && r != E::ONE);
        self.challenges.push(r);
        Ok(r)
    }
}

impl NativeVerifierContext for TestContext {
    type Hidden = Linear;
    fn public(&mut self, value: F) -> Result<()> {
        assert_eq!(value, self.public[self.cursor[0]]);
        self.cursor[0] += 1;
        Ok(())
    }
    fn message(&mut self, count: usize) -> Result<Vec<Linear>> {
        let values = &self.messages[self.cursor[1]];
        assert_eq!(count, values.len());
        self.cursor[1] += 1;
        Ok(values.iter().copied().map(Linear::constant).collect())
    }
    fn challenge(&mut self) -> Result<E> {
        let r = self.challenges[self.cursor[2]];
        self.cursor[2] += 1;
        Ok(r)
    }
}

fn shape(rounds: usize, degree: usize) -> ZerocheckShape {
    ZerocheckShape::new(
        &[AirDegrees {
            constraints: degree,
            interactions: 0,
        }],
        rounds,
        0,
        0,
    )
}

fn boolean_relation(
    program: &NativeAirProgram,
    values: &[F],
    reader: &mut MaskedReader<'_>,
) -> Result<Relation> {
    let replay = program.replay(reader)?;
    let reduction = program.reduce(replay)?;
    let table: Vec<E> = values.iter().copied().map(E::from).collect();
    let x = Poly::new(table).eval_ext::<F>(&Point::new(reduction.point.clone()));
    let expected = Point::eval_eq(&reduction.tau, &reduction.point) * (x * x + x);
    let mut claim = reduction.claim;
    claim.constant += expected;
    Ok(Relation {
        variables: program.message_count(),
        public_wires: vec![],
        linear: vec![claim],
        products: vec![],
    })
}

#[test]
fn actual_native_air_rounds_use_online_masks_and_verify_as_algebra() -> Result<()> {
    let parameters = Parameters::default();
    let program = NativeAirProgram::new(shape(5, 2))?;
    let values: Vec<F> = (0..32).map(|i| F::from_bool(i % 3 == 0)).collect();
    // This regression has PUBLIC trace values; it isolates the transcript and
    // verifier algebra from private PCS and AIR endpoint integration.
    let binding = postcard::to_allocvec(&(
        b"native-boolean-public-fixture",
        program.binding()?,
        &values,
    ))?;
    let mut rng = StdRng::seed_from_u64(133);
    let mut ctx = MaskedProver::new(&parameters, &binding, program.message_count(), &mut rng)?;
    let mut native = program.prover(&mut ctx);
    let table = Table::new(RowMajorMatrix::new(values.clone(), values.len()));
    let airs = [&BooleanAir];
    let _private_native_proof =
        AirZerocheck::new(&airs, 0).prove::<F, E, _>(&[None], &[&table], &[&[]], &mut native);
    native.finish()?;
    let proof = ctx.finish(
        |reader| boolean_relation(&program, &values, reader),
        &mut rng,
    )?;
    let proof = ExperimentalProof::from_bytes(&proof.to_bytes()?)?;
    let mut reader = MaskedReader::new(
        &parameters,
        &binding,
        program.message_count(),
        &proof.masks.root,
        &proof.masked,
    )?;
    let relation = boolean_relation(&program, &values, &mut reader)?;
    reader.verify(&parameters, &proof, &relation)?;

    // Forge a real proof attempt with an incorrect native round, bypassing the
    // prover's relation check. The serialized algebraic verifier must reject it.
    let mut rng = StdRng::seed_from_u64(134);
    let mut ctx = MaskedProver::new(&parameters, &binding, program.message_count(), &mut rng)?;
    for op in &program.operations {
        match *op {
            Operation::Public(value) => NativeProverContext::public(&mut ctx, value)?,
            Operation::Message(count) => {
                NativeProverContext::message(&mut ctx, &vec![E::ONE; count])?
            }
            Operation::Challenge => {
                let _ = NativeProverContext::challenge(&mut ctx)?;
            }
        }
    }
    let forged = ctx.finish_unchecked(
        |reader| boolean_relation(&program, &values, reader),
        &mut rng,
    )?;
    let mut reader = MaskedReader::new(
        &parameters,
        &binding,
        program.message_count(),
        &forged.masks.root,
        &forged.masked,
    )?;
    let relation = boolean_relation(&program, &values, &mut reader)?;
    assert!(reader.verify(&parameters, &forged, &relation).is_err());
    Ok(())
}

#[test]
fn native_keccak_air_and_compiled_reduction_agree() -> Result<()> {
    let air = KeccakBinaryAir::default();
    let constraints = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
    let degree = constraints
        .iter()
        .map(|e| e.poly_degree(2, &[]))
        .max()
        .unwrap();
    let trace = generate_binary_trace_rows::<F>(vec![[0x5a5a5a5a5a5a5a5a; 25]], 0);
    let table = Table::new(trace.transpose());
    let rounds = table.num_variables();
    let program = NativeAirProgram::new(shape(rounds, degree))?;
    let airs = [&air];
    let zerocheck = AirZerocheck::new(&airs, 0);
    let mut prover = TestContext::new();
    let mut channel = program.prover(&mut prover);
    let (proof, point) = zerocheck.prove::<F, E, _>(&[None], &[&table], &[&[]], &mut channel);
    channel.finish()?;
    assert_eq!(prover.messages, proof.sumcheck.round_polys);
    let reduction = program.reduce(program.replay(&mut prover)?)?;
    assert_eq!(reduction.point, point.as_slice());
    let mut verifier = TestContext::new();
    let mut channel = program.prover(&mut verifier);
    let verified_point = zerocheck
        .verify::<F, E, _>(&proof, &[rounds], &[&[]], &mut channel)
        .unwrap();
    channel.finish()?;
    assert_eq!(verified_point, point);
    assert_eq!(prover.public, verifier.public);
    assert_eq!(prover.messages, verifier.messages);
    assert_eq!(prover.challenges, verifier.challenges);
    let mut verifier = TestContext::new();
    let mut channel = program.prover(&mut verifier);
    let native = zerocheck
        .verify_reduction::<F, E, _>(&proof.sumcheck, &[rounds], &[&[]], &mut channel)
        .unwrap();
    channel.finish()?;
    assert_eq!(reduction.claim.evaluate(&[]), native.final_sum);
    Ok(())
}

#[test]
fn unsupported_shapes_and_native_schedule_drift_fail_closed() -> Result<()> {
    let mut unsupported = shape(5, 2);
    unsupported.pow_bits = 1;
    assert!(NativeAirProgram::new(unsupported).is_err());
    assert!(NativeAirProgram::new(shape(5, 2).with_bus(3)).is_err());
    assert!(NativeAirProgram::new(shape(0, 2)).is_err());
    let program = NativeAirProgram::new(shape(5, 2))?;
    let mut ctx = TestContext::new();
    assert!(program.prover(&mut ctx).finish().is_err());
    let Some(Operation::Public(first)) = program.operations.first() else {
        panic!("missing native framing")
    };
    for action in 0..3 {
        let mut channel = program.prover(&mut ctx);
        assert!(
            catch_unwind(AssertUnwindSafe(|| match action {
                0 => channel.observe(*first + F::ONE),
                1 => {
                    let _ = channel.sample();
                }
                _ => {
                    let _ = channel.sample_bits(1);
                }
            }))
            .is_err()
        );
    }
    Ok(())
}
