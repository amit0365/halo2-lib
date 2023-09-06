use super::{
    circuit::leaf::{KeccakCoprocessorLeafCircuit, KeccakCoprocessorLeafCircuitParams},
    output::multi_inputs_to_circuit_outputs,
};

use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use itertools::Itertools;

#[cfg(test)]
mod output;

#[test]
fn test_mock_leaf_circuit() {
    let k: usize = 18;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = true;

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), params.clone());
    let circuit_outputs = multi_inputs_to_circuit_outputs::<Fr>(&inputs, params.capacity());

    let instances = vec![
        circuit_outputs.iter().map(|o| o.key).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_lo).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_hi).collect_vec(),
    ];

    let prover = MockProver::<Fr>::run(k as u32, &circuit, instances).unwrap();
    prover.assert_satisfied();
}
