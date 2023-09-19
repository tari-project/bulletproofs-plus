#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_bulletproofs_plus::ristretto::RistrettoRangeProof;

// Test basic deserialization and canonical serialization
fuzz_target!(|data: &[u8]| {
	// If deserialization succeeds, serialization should be canonical
	if let Ok(proof) = RistrettoRangeProof::from_bytes(data) {
		assert_eq!(&proof.to_bytes(), data);
	}
});
