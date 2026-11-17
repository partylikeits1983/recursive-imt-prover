//! Joint algebraic-view coupling for fixed verifier coins and paired queries.
//! This checks a privacy proof obligation, not the Fiat–Shamir/ROM compiler.
use p3_field::{Field, PrimeCharacteristicRing};
use p3_multilinear_util::{point::Point, poly::Poly};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use recursive_imt_prover::binary::veil::{E, F, code::BinaryCode};

fn dot(a: &[E], b: &[E]) -> E {
    a.iter().zip(b).map(|(&x, &y)| x * y).sum()
}

fn powers(x: E, n: usize) -> Vec<E> {
    (0..n).map(|i| x.exp_u64(i as u64)).collect()
}

fn random_vector(n: usize, rng: &mut StdRng) -> Vec<E> {
    (0..n).map(|_| rng.random()).collect()
}

#[test]
fn oracle_retargeting_preserves_the_entire_whir_input_and_two_masked_evaluations() {
    let code = BinaryCode::new(4, 5, 2).unwrap();
    let queries = [0, 3, 3, 7, 15];
    let mut rng = StdRng::seed_from_u64(0x6f7261636c65);
    let alpha = E::from(F::new(19));
    let scale = E::from(F::new(23));
    for _ in 0..8 {
        let a = random_vector(code.input_len, &mut rng);
        let b = random_vector(code.input_len, &mut rng);
        let mask = random_vector(code.input_len, &mut rng);
        let next_a = retarget(
            &code,
            &a,
            &a[..4].iter().map(|&v| v * scale).collect::<Vec<_>>(),
            &queries,
        );
        let next_b = retarget(
            &code,
            &b,
            &b[..4].iter().map(|&v| v / scale).collect::<Vec<_>>(),
            &queries,
        );
        assert_eq!(dot(&a[..4], &b[..4]), dot(&next_a[..4], &next_b[..4]));
        let blend: Vec<E> = (0..code.input_len)
            .map(|i| a[i] + alpha * b[i] + alpha.square() * mask[i])
            .collect();
        let next_mask: Vec<E> = (0..code.input_len)
            .map(|i| (blend[i] + next_a[i] + alpha * next_b[i]) / alpha.square())
            .collect();
        // Preserve the COMPLETE WHIR input, not only the values checked by our
        // application. Every WHIR fold, OOD value and final polynomial is then
        // identical for fixed transcript coins.
        for i in 0..code.input_len {
            assert_eq!(
                blend[i],
                next_a[i] + alpha * next_b[i] + alpha.square() * next_mask[i]
            );
        }
        for (old, new) in [(&a, &next_a), (&b, &next_b), (&mask, &next_mask)] {
            let before = code.encode(old).unwrap();
            let after = code.encode(new).unwrap();
            for q in queries {
                assert_eq!(before[q], after[q]);
            }
        }
        for _ in 0..2 {
            let point = Point::new(random_vector(2, &mut rng));
            let before = [&a, &b, &mask].map(|v| Poly::new(&v[..4]).eval_ext::<F>(&point));
            let after =
                [&next_a, &next_b, &next_mask].map(|v| Poly::new(&v[..4]).eval_ext::<F>(&point));
            assert_eq!(
                before[0] + alpha * before[1] + alpha.square() * before[2],
                after[0] + alpha * after[1] + alpha.square() * after[2]
            );
            let pads: [E; 3] = rng.random();
            for j in 0..3 {
                let translated = pads[j] + before[j] + after[j];
                assert_eq!(before[j] + pads[j], after[j] + translated);
            }
        }
    }
}

/// Translate selected padding coordinates to preserve every opened row when
/// changing the message. A Cauchy minor makes this a bijection on randomness.
fn retarget(code: &BinaryCode, before: &[E], message: &[E], queries: &[usize]) -> Vec<E> {
    let mut indices = queries.to_vec();
    indices.sort_unstable();
    indices.dedup();
    let q = indices.len();
    assert!(q <= code.queries);
    assert_eq!(message.len(), code.message_len);
    let mut after = before.to_vec();
    after[..message.len()].copy_from_slice(message);
    let mut matrix = Vec::new();
    let mut rhs = Vec::new();
    for index in indices {
        let row = code.generator_row(index).unwrap();
        rhs.push(
            row.iter()
                .zip(before.iter().zip(&after))
                .map(|(&c, (&a, &b))| (a + b) * c)
                .sum::<E>(),
        );
        matrix.push(row[code.message_len..code.message_len + q].to_vec());
    }
    for i in 0..q {
        let pivot = (i..q).find(|&j| matrix[j][i] != F::ZERO).unwrap();
        matrix.swap(i, pivot);
        rhs.swap(i, pivot);
        let inverse = matrix[i][i].inverse();
        for value in &mut matrix[i] {
            *value *= inverse;
        }
        rhs[i] *= inverse;
        for j in 0..q {
            if j == i {
                continue;
            }
            let factor = matrix[j][i];
            let pivot = matrix[i].clone();
            for (entry, &value) in matrix[j][i..].iter_mut().zip(&pivot[i..]) {
                *entry += value * factor;
            }
            let value = rhs[i];
            rhs[j] += value * factor;
        }
    }
    for (i, delta) in rhs.into_iter().enumerate() {
        after[code.message_len + i] += delta;
    }
    after
}

#[test]
fn two_valid_witnesses_have_identical_joint_algebraic_views_after_bijective_mask_transport() {
    let code = BinaryCode::new(4, 5, 2).unwrap();
    let mask_code = BinaryCode::new(12, 5, 2).unwrap();
    // Include a repeated query: it must give the same answer, not fresh entropy.
    let queries = [0, 3, 3, 7, 15];
    let mask_queries = [0, 1, 3, 3, 7];
    let mut rng = StdRng::seed_from_u64(0x7665696c);
    for _ in 0..8 {
        let link = E::from(F::new(13));
        let weights = powers(link, 4);
        let r: E = rng.random();
        let s: E = rng.random();
        let t: E = rng.random();
        let a = vec![E::from(F::new(7)), E::from(F::new(11)), r, r + E::ONE];
        let b = vec![E::from(F::new(9)), E::from(F::new(17)), s, t];
        let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
        let columns = [a, b, c];
        let claims = columns.each_ref().map(|v| dot(&weights, v));
        let mut other = [vec![E::ZERO; 4], vec![E::ZERO; 4], vec![E::ZERO; 4]];
        other[0][0] = E::from(F::new(3));
        other[0][1] = E::from(F::new(5));
        for i in 0..2 {
            other[2][i] = columns[2][i];
            other[1][i] = other[2][i] / other[0][i];
        }
        let desired: Vec<_> = (0..3)
            .map(|j| claims[j] + dot(&weights[..2], &other[j][..2]))
            .collect();
        let a = weights[2];
        let b = weights[3];
        let r = (desired[0] + b) / (a + b);
        let s = ((r + E::ONE) * desired[1] + desired[2]) / a;
        let t = (desired[2] + r * desired[1]) / b;
        other[0][2..].copy_from_slice(&[r, r + E::ONE]);
        other[1][2..].copy_from_slice(&[s, t]);
        other[2][2..].copy_from_slice(&[r * s, (r + E::ONE) * t]);
        for j in 0..3 {
            assert_eq!(dot(&weights, &other[j]), claims[j]);
        }
        for ((&a, &b), &c) in other[0].iter().zip(&other[1]).zip(&other[2]) {
            assert_eq!(a * b, c);
        }

        let padded: Vec<_> = columns
            .iter()
            .map(|v| {
                let mut result = v.clone();
                result.extend(random_vector(code.input_len - v.len(), &mut rng));
                result
            })
            .collect();
        let changed: Vec<_> = (0..3)
            .map(|j| retarget(&code, &padded[j], &other[j], &queries))
            .collect();
        let rho = E::from(F::new(19));
        let sigma = E::from(F::new(23));
        let aux = random_vector(code.input_len, &mut rng);
        let product_mask = random_vector(2 * code.input_len, &mut rng);
        let blend: Vec<_> = (0..code.input_len)
            .map(|i| {
                padded[0][i]
                    + rho * padded[1][i]
                    + rho.square() * padded[2][i]
                    + rho.exp_u64(3) * aux[i]
            })
            .collect();
        let aux_new: Vec<_> = (0..code.input_len)
            .map(|i| {
                (blend[i] + changed[0][i] + rho * changed[1][i] + rho.square() * changed[2][i])
                    / rho.exp_u64(3)
            })
            .collect();
        assert_eq!(dot(&weights, &aux[..4]), dot(&weights, &aux_new[..4]));
        let extended: Vec<_> = padded.iter().map(|v| code.to_product(v).unwrap()).collect();
        let ext_new: Vec<_> = changed
            .iter()
            .map(|v| code.to_product(v).unwrap())
            .collect();
        let phi: Vec<_> = (0..product_mask.len())
            .map(|i| extended[0][i] * extended[1][i] + extended[2][i] + sigma * product_mask[i])
            .collect();
        let product_new: Vec<_> = (0..product_mask.len())
            .map(|i| (phi[i] + ext_new[0][i] * ext_new[1][i] + ext_new[2][i]) / sigma)
            .collect();
        let gamma_weights = powers(E::from(F::new(31)), 4);
        assert_eq!(
            dot(&gamma_weights, &product_mask[..4]),
            dot(&gamma_weights, &product_new[..4])
        );
        for (old, new) in padded.iter().zip(&changed).chain([(&aux, &aux_new)]) {
            let old = code.encode(old).unwrap();
            let new = code.encode(new).unwrap();
            for i in queries {
                assert_eq!(old[i], new[i]);
            }
        }
        let old = code.encode_product(&product_mask).unwrap();
        let new = code.encode_product(&product_new).unwrap();
        for i in queries {
            assert_eq!(old[i], new[i]);
        }

        // The transcript masks are correlated with the product vectors. Retarget
        // their commitment too, preserving the masked witness AND all messages.
        let witness: Vec<_> = (0..4)
            .flat_map(|i| columns.iter().map(move |v| v[i]))
            .collect();
        let other_witness: Vec<_> = (0..4)
            .flat_map(|i| other.iter().map(move |v| v[i]))
            .collect();
        let coefficients: [E; 3] = rng.random();
        let mut linear: Vec<_> = weights
            .iter()
            .flat_map(|&w| coefficients.map(|c| w * c))
            .collect();
        linear[2] += E::ONE;
        linear[5] += link;
        assert_eq!(dot(&linear, &witness), dot(&linear, &other_witness));
        let mask = random_vector(mask_code.input_len, &mut rng);
        let masked: Vec<_> = witness.iter().zip(&mask).map(|(&w, &m)| w + m).collect();
        let new_message: Vec<_> = masked
            .iter()
            .zip(&other_witness)
            .map(|(&w, &m)| w + m)
            .collect();
        let mask_new = retarget(&mask_code, &mask, &new_message, &mask_queries);
        assert_eq!(dot(&linear, &mask[..12]), dot(&linear, &mask_new[..12]));
        let aux = random_vector(mask_code.input_len, &mut rng);
        let aux_new: Vec<_> = (0..mask.len())
            .map(|i| aux[i] + (mask[i] + mask_new[i]) / rho)
            .collect();
        assert_eq!(dot(&linear, &aux[..12]), dot(&linear, &aux_new[..12]));
        for i in 0..mask.len() {
            assert_eq!(mask[i] + rho * aux[i], mask_new[i] + rho * aux_new[i]);
        }
        for (old, new) in [(&mask, &mask_new), (&aux, &aux_new)] {
            let old = mask_code.encode(old).unwrap();
            let new = mask_code.encode(new).unwrap();
            for i in mask_queries {
                assert_eq!(old[i], new[i]);
            }
        }
    }
}
