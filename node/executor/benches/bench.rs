// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

use codec::{Decode, Encode};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use node_executor::Executor;
use node_primitives::{Hash, BlockNumber};
use node_runtime::{
	Block, BuildStorage, Call, CheckedExtrinsic, Header, UncheckedExtrinsic,
	constants::currency::*
};
use node_testing::keyring::*;
use primitives::{Blake2Hasher, NativeOrEncoded, NeverNativeValue, traits::CodeExecutor};
use runtime_support::Hashable;
use state_machine::{TestExternalities as CoreTestExternalities};
use substrate_executor::{NativeExecutor, RuntimeInfo, WasmExecutionMethod};

criterion_group!(benches, bench_execute_block);
criterion_main!(benches);

/// The wasm runtime code.
const COMPACT_CODE: &[u8] = node_runtime::WASM_BINARY;

const GENESIS_HASH: [u8; 32] = [69u8; 32];

const VERSION: u32 = node_runtime::VERSION.spec_version;

/// The number of Wasm pages to allocate for block execution.
const HEAP_PAGES: u64 = 20;

type TestExternalities<H> = CoreTestExternalities<H, u64>;

fn sign(xt: CheckedExtrinsic) -> UncheckedExtrinsic {
	node_testing::keyring::sign(xt, VERSION, GENESIS_HASH)
}

fn new_test_ext(code: &[u8]) -> TestExternalities<Blake2Hasher> {
	TestExternalities::new_with_code(
		code,
		node_testing::genesis::config(false, Some(code)).build_storage().unwrap(),
	)
}

fn construct_block(
	executor: &NativeExecutor<Executor>,
	env: &mut TestExternalities<Blake2Hasher>,
	number: BlockNumber,
	parent_hash: Hash,
	extrinsics: Vec<CheckedExtrinsic>,
) -> (Vec<u8>, Hash) {
	use trie::{TrieConfiguration, trie_types::Layout};

	let mut ext = env.ext();

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
	executor.call::<_, NeverNativeValue, fn() -> _>(
		&mut ext,
		"Core_initialize_block",
		&header.encode(),
		true,
		None,
	).0.unwrap();

	for i in extrinsics.iter() {
		executor.call::<_, NeverNativeValue, fn() -> _>(
			&mut ext,
			"BlockBuilder_apply_extrinsic",
			&i.encode(),
			true,
			None,
		).0.unwrap();
	}

	let header = match executor.call::<_, NeverNativeValue, fn() -> _>(
		&mut ext,
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

// block 1 and 2 must be created together to ensure transactions are only signed once (since they
// are not guaranteed to be deterministic) and to ensure that the correct state is propagated
// from block1's execution to block2 to derive the correct storage_root.
fn blocks(executor: &NativeExecutor<Executor>) -> ((Vec<u8>, Hash), (Vec<u8>, Hash)) {
	let mut t = new_test_ext(COMPACT_CODE);

	let mut block1_extrinsics = vec![
		CheckedExtrinsic {
			signed: None,
			function: Call::Timestamp(timestamp::Call::set(42 * 1000)),
		},
	];
	block1_extrinsics.extend((0..20).map(|i| {
		CheckedExtrinsic {
			signed: Some((alice(), signed_extra(i, 0))),
			function: Call::Balances(balances::Call::transfer(bob().into(), 1 * DOLLARS)),
		}
	}));
	let block1 = construct_block(
		executor,
		&mut t,
		1,
		GENESIS_HASH.into(),
		block1_extrinsics,
	);

	let block2_extrinsics = vec![
		CheckedExtrinsic {
			signed: None,
			function: Call::Timestamp(timestamp::Call::set(52 * 1000)),
		},
	];
	let block2 = construct_block(
		executor,
		&mut t,
		2,
		block1.1.clone(),
		block2_extrinsics,
	);

	// session change => consensus authorities change => authorities change digest item appears
	let digest = Header::decode(&mut &block2.0[..]).unwrap().digest;
	assert_eq!(digest.logs().len(), 0);

	(block1, block2)
}

#[derive(Debug, Clone, Copy)]
enum ExecutionMethod {
	Native,
	Wasm(WasmExecutionMethod),
}

fn bench_execute_block(c: &mut Criterion) {
	c.bench_function_over_inputs(
		"execute blocks",
		|b, strategy| {
			let (use_native, wasm_method) = match strategy {
				ExecutionMethod::Native => (true, WasmExecutionMethod::Interpreted),
				ExecutionMethod::Wasm(wasm_method) => (false, wasm_method.clone()),
			};
			let executor = NativeExecutor::new(wasm_method, Some(HEAP_PAGES));

			let (block1, block2) = blocks(&executor);

			// Just execute something to initialize the runtime cache.
			{
				let mut ext = new_test_ext(COMPACT_CODE);
				executor.runtime_version(&mut ext.ext());
			}

			b.iter_batched_ref(
				|| new_test_ext(COMPACT_CODE),
				|ext| {
					// Benchmark the first block.
					let mut ext = ext.ext();
					executor.call::<_, NeverNativeValue, fn() -> _>(
						&mut ext,
						"Core_execute_block",
						&block1.0,
						use_native,
						None,
					).0.unwrap();
				},
				BatchSize::LargeInput,
			);
		},
		vec![
			ExecutionMethod::Native,
			ExecutionMethod::Wasm(WasmExecutionMethod::Interpreted),
		]
	);
}
