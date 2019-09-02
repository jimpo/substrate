use codec::{Decode, Encode};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use node_executor::Executor;
use node_primitives::{Hash, BlockNumber};
use node_runtime::{
	Block, BuildStorage, Call, CheckedExtrinsic, Header, UncheckedExtrinsic,
	constants::currency::*
};
use node_testing::keyring::*;
use primitives::{Blake2Hasher, NativeOrEncoded, NeverNativeValue};
use runtime_support::Hashable;
use state_machine::{CodeExecutor, TestExternalities as CoreTestExternalities};

criterion_group!(benches, wasm_execute_block);
criterion_main!(benches);

/// The wasm runtime code.
const COMPACT_CODE: &[u8] = node_runtime::WASM_BINARY;

const GENESIS_HASH: [u8; 32] = [69u8; 32];

const VERSION: u32 = node_runtime::VERSION.spec_version;

type TestExternalities<H> = CoreTestExternalities<H, u64>;

fn sign(xt: CheckedExtrinsic) -> UncheckedExtrinsic {
	node_testing::keyring::sign(xt, VERSION, GENESIS_HASH)
}

fn new_test_ext(code: &[u8], support_changes_trie: bool) -> TestExternalities<Blake2Hasher> {
	let mut ext = TestExternalities::new_with_code(
		code,
		node_testing::genesis::config(support_changes_trie, Some(code)).build_storage().unwrap(),
	);
	ext.changes_trie_storage().insert(0, GENESIS_HASH.into(), Default::default());
	ext
}

// block 1 and 2 must be created together to ensure transactions are only signed once (since they
// are not guaranteed to be deterministic) and to ensure that the correct state is propagated
// from block1's execution to block2 to derive the correct storage_root.
fn blocks() -> ((Vec<u8>, Hash), (Vec<u8>, Hash)) {
	let mut t = new_test_ext(COMPACT_CODE, false);
	let block1 = construct_block(
		&mut t,
		1,
		GENESIS_HASH.into(),
		vec![
			CheckedExtrinsic {
				signed: None,
				function: Call::Timestamp(timestamp::Call::set(42 * 1000)),
			},
			CheckedExtrinsic {
				signed: Some((alice(), signed_extra(0, 0))),
				function: Call::Balances(balances::Call::transfer(bob().into(), 69 * DOLLARS)),
			},
		]
	);
	let block2 = construct_block(
		&mut t,
		2,
		block1.1.clone(),
		vec![
			CheckedExtrinsic {
				signed: None,
				function: Call::Timestamp(timestamp::Call::set(52 * 1000)),
			},
			CheckedExtrinsic {
				signed: Some((bob(), signed_extra(0, 0))),
				function: Call::Balances(balances::Call::transfer(alice().into(), 5 * DOLLARS)),
			},
			CheckedExtrinsic {
				signed: Some((alice(), signed_extra(1, 0))),
				function: Call::Balances(balances::Call::transfer(bob().into(), 15 * DOLLARS)),
			}
		]
	);

	// session change => consensus authorities change => authorities change digest item appears
	let digest = Header::decode(&mut &block2.0[..]).unwrap().digest;
	assert_eq!(digest.logs().len(), 0);

	(block1, block2)
}

fn construct_block(
	env: &mut TestExternalities<Blake2Hasher>,
	number: BlockNumber,
	parent_hash: Hash,
	extrinsics: Vec<CheckedExtrinsic>,
) -> (Vec<u8>, Hash) {
	use trie::{TrieConfiguration, trie_types::Layout};

	// sign extrinsics.
	let extrinsics = extrinsics.into_iter().map(sign).collect::<Vec<_>>();

	// calculate the header fields that we can.
	let extrinsics_root = Layout::<Blake2Hasher>::ordered_trie_root(
		extrinsics.iter().map(Encode::encode)
	).to_fixed_bytes()
		.into();

	let header = Header {
		parent_hash,
		number,
		extrinsics_root,
		state_root: Default::default(),
		digest: Default::default(),
	};

	// execute the block to get the real header.
	executor().call::<_, NeverNativeValue, fn() -> _>(
		env,
		"Core_initialize_block",
		&header.encode(),
		true,
		None,
	).0.unwrap();

	for i in extrinsics.iter() {
		executor().call::<_, NeverNativeValue, fn() -> _>(
			env,
			"BlockBuilder_apply_extrinsic",
			&i.encode(),
			true,
			None,
		).0.unwrap();
	}

	let header = match executor().call::<_, NeverNativeValue, fn() -> _>(
		env,
		"BlockBuilder_finalize_block",
		&[0u8;0],
		true,
		None,
	).0.unwrap() {
		NativeOrEncoded::Native(_) => unreachable!(),
		NativeOrEncoded::Encoded(h) => Header::decode(&mut &h[..]).unwrap(),
	};

	let hash = header.blake2_256();
	(Block { header, extrinsics }.encode(), hash.into())
}

fn executor() -> ::substrate_executor::NativeExecutor<Executor> {
	substrate_executor::NativeExecutor::new(None)
}

fn wasm_execute_block(c: &mut Criterion) {
	c.bench_function(
		"execute blocks with Wasm executor",
		|b| {
			let (block1, block2) = blocks();

			b.iter_batched_ref(
				|| new_test_ext(COMPACT_CODE, false),
				|ext| {
					executor().call::<_, NeverNativeValue, fn() -> _>(
						ext,
						"Core_execute_block",
						&block1.0,
						false,
						None,
					).0.unwrap();
					executor().call::<_, NeverNativeValue, fn() -> _>(
						ext,
						"Core_execute_block",
						&block2.0,
						false,
						None,
					).0.unwrap();
				},
				BatchSize::LargeInput,
			);
		}
	);
}
