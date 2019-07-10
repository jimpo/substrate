// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use criterion::{BatchSize, Criterion};
use hash_db::{AsHashDB, HashDB, Hasher};
use itertools::iproduct;
use kvdb::{DBTransaction, DBValue, KeyValueDB};
use kvdb_rocksdb as rocks;
use memory_db::{self, MemoryDB, prefixed_key};
use rand::{thread_rng, RngCore};
use tempdir::TempDir;
use trie_db::{self, Trie, TrieMut, TrieDB, TrieDBMut, NodeCodec};

use std::io;
use std::marker::PhantomData;
use std::sync::Arc;


// Copy of private trie_db::nibbleslice::EMPTY_ENCODED.
pub const TRIE_ROOT_PREFIX: &[u8] = &[0];


pub fn benchmark_write_by_value_size(c: &mut Criterion) {
	benchmark_write_by_value_size_rocksdb::<
		substrate_primitives::Blake2Hasher,
		substrate_trie::NodeCodec<substrate_primitives::Blake2Hasher>,
	>(c, "substrate-blake2");
	benchmark_write_by_value_size_memorydb::<
		substrate_primitives::Blake2Hasher,
		substrate_trie::NodeCodec<substrate_primitives::Blake2Hasher>,
	>(c, "substrate-blake2");
}

pub fn benchmark_read_by_value_size(c: &mut Criterion) {
	benchmark_read_by_value_size_rocksdb::<
		substrate_primitives::Blake2Hasher,
		substrate_trie::NodeCodec<substrate_primitives::Blake2Hasher>,
	>(c, "substrate-blake2");
}

/// Benchmark trie write times backed by RocksDB on a sequence of value sizes.
fn benchmark_write_by_value_size_rocksdb<H, N>(c: &mut Criterion, name: &str)
	where
		H: Hasher,
		N: NodeCodec<H>,
{
	c.bench_function_over_inputs(
        &format!("RocksDB shared prefix keys: {}", name),
        |b, value_size| b.iter_batched_ref(
			|| {
				let mut db_config = rocks::DatabaseConfig::default();
				// db_config.memory_budget = config.cache_size;
				TempRocksDB::new("substrate-trie-bench", &db_config).unwrap()
			},
			|db| {
				let mut root = H::Out::default();
				{
					let mut hashdb = KVBackedHashDB::<H, PrefixedKey<H>>::new(db, None);
					hashdb.insert(TRIE_ROOT_PREFIX, &N::empty_node()[..]);

					let mut triedb = TrieDBMut::<H, N>::new(&mut hashdb, &mut root);
                    populate_trie(&mut triedb, **value_size, 1).unwrap();
				}
				db.flush().unwrap();
			},
			BatchSize::PerIteration
		),
		&[1, 16, 64, 256, 1024, 4096, 16384, 65536, 262144]  // Value sizes in bytes
    );
}

/// Benchmark trie write times backed by MemoryDB on a sequence of value sizes.
fn benchmark_write_by_value_size_memorydb<H, N>(c: &mut Criterion, name: &str)
	where
		H: Hasher,
		N: NodeCodec<H>,
{
	c.bench_function_over_inputs(
        &format!("MemoryDB shared prefix keys: {}", name),
        |b, value_size| b.iter_batched_ref(
			|| MemoryDB::<H, memory_db::PrefixedKey<H>, DBValue>::new(&N::empty_node()[..]),
			|hashdb| {
				let mut root = H::Out::default();
				{
					let mut triedb = TrieDBMut::<H, N>::new(hashdb, &mut root);
                    populate_trie(&mut triedb, **value_size, 1).unwrap();
				}
			},
			BatchSize::PerIteration
		),
		&[1, 16, 64, 256, 1024, 4096, 16384, 65536, 262144]  // Value sizes in bytes
    );
}

/// Benchmark trie read times backed by RocksDB on a sequence of value sizes.
fn benchmark_read_by_value_size_rocksdb<H, N>(c: &mut Criterion, name: &str)
	where
		H: Hasher,
		N: NodeCodec<H>,
{
	let value_sizes = [1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144];
    let branches = [1, 2, 4, 8, 16, 32, 64];

	c.bench_function_over_inputs(
        &format!("RocksDB trie read: {}", name),
        |b, (value_size, branches)| {
			assert!(*branches > 0 && 256 % *branches == 0);

			let mut db_config = rocks::DatabaseConfig::default();
			// db_config.memory_budget = config.cache_size;
			let db = TempRocksDB::new("substrate-trie-bench", &db_config).unwrap();
			let mut hashdb = KVBackedHashDB::<H, PrefixedKey<H>>::new(&db, None);
			hashdb.insert(TRIE_ROOT_PREFIX, &N::empty_node()[..]);

			let mut root = H::Out::default();
			let item_key = [0u8; 32];
			{
				let mut triedb = TrieDBMut::<H, N>::new(&mut hashdb, &mut root);
				populate_trie(&mut triedb, 32, 256 / *branches).unwrap();

				// Generate a random value so that it cannot be compressed.
				let mut value = vec![0u8; *value_size];
				thread_rng().fill_bytes(&mut value[..]);
				triedb.insert(&item_key, &value).unwrap();
			}
			db.flush().unwrap();

			let hashdb_ref: &dyn HashDB<_, _> = &hashdb;
			let triedb = TrieDB::<H, N>::new(&hashdb_ref, &root).unwrap();

			b.iter(|| {
				triedb.get(&item_key).unwrap().unwrap()
			})
		},
		iproduct!(value_sizes.iter().cloned(), branches.iter().cloned())
    );
}

fn populate_trie<H, C, T>(trie: &mut T, value_size: usize, bit_dist: usize)
	-> trie_db::Result<(), H::Out, C::Error>
	where
		H: Hasher,
		C: NodeCodec<H>,
		T: TrieMut<H, C>,
{
	assert!(bit_dist > 0 && 256 % bit_dist == 0);

	let value = vec![0u8; value_size];
	for i in 0..(256 / bit_dist) {
		let byte_index = (i * bit_dist) / 8;
		let bit_index  = (i * bit_dist) % 8;

		let mut key = [0u8; 32];
        key[byte_index] |= (1 << (7 - bit_index)) as u8;

		trie.insert(&key, &value)?;
	}
	Ok(())
}

struct TempRocksDBInner {
	_tempdir: TempDir,
	db: rocks::Database,
}

impl TempRocksDBInner {
	fn new(prefix: &str, config: &rocks::DatabaseConfig) -> Result<Self, String> {
		let tempdir = TempDir::new(prefix)
			.map_err(|e| e.to_string())?;
		let path = tempdir.path().to_str()
			.ok_or_else(|| format!("temp directory with prefix {} is invalid", prefix))?;
		let db = rocks::Database::open(config, path)
			.map_err(|e| e.to_string())?;
		Ok(TempRocksDBInner { _tempdir: tempdir, db })
	}
}

/// A KeyValueDB implementation that is backed by RocksDB in a temporary directory. A new temp
/// directory is created on construction and deleted on drop.
///
/// This is only meant for usage in tests/benchmarks.
struct TempRocksDB(Arc<TempRocksDBInner>);

impl TempRocksDB {
	fn new(prefix: &str, config: &rocks::DatabaseConfig) -> Result<Self, String> {
        TempRocksDBInner::new(prefix, config)
			.map(|inner| TempRocksDB(Arc::new(inner)))
    }
}

impl KeyValueDB for TempRocksDB {
	fn get(&self, col: Option<u32>, key: &[u8]) -> io::Result<Option<DBValue>> {
		KeyValueDB::get(&self.0.db, col, key)
	}

	fn get_by_prefix(&self, col: Option<u32>, prefix: &[u8]) -> Option<Box<[u8]>> {
		KeyValueDB::get_by_prefix(&self.0.db, col, prefix)
	}

	fn write_buffered(&self, transaction: DBTransaction) {
		self.0.db.write_buffered(transaction)
	}

	fn flush(&self) -> io::Result<()> {
		KeyValueDB::flush(&self.0.db)
	}

	fn iter<'a>(&'a self, col: Option<u32>) -> Box<Iterator<Item=(Box<[u8]>, Box<[u8]>)> + 'a> {
		KeyValueDB::iter(&self.0.db, col)
	}

	fn iter_from_prefix<'a>(&'a self, col: Option<u32>, prefix: &'a [u8])
		-> Box<Iterator<Item=(Box<[u8]>, Box<[u8]>)> + 'a>
	{
		KeyValueDB::iter_from_prefix(&self.0.db, col, prefix)
	}

	fn restore(&self, new_db: &str) -> io::Result<()> {
		KeyValueDB::restore(&self.0.db, new_db)
	}
}

// Based on memory_db::KeyFunction, but the key is a byte buffer.
trait KeyFunction<H: Hasher>: Send + Sync {
	type Key: AsRef<[u8]>;

	fn key(hash: &H::Out, prefix: &[u8]) -> Self::Key;
}

// Based on memory_db::PrefixedKey.
pub struct PrefixedKey<H: Hasher>(PhantomData<H>);

impl<H: Hasher> KeyFunction<H> for PrefixedKey<H> {
	type Key = Vec<u8>;

	fn key(hash: &H::Out, prefix: &[u8]) -> Vec<u8> {
		prefixed_key::<H>(hash, prefix)
	}
}

/// Simple HashDB implementation backed by a generic KeyValueDB. Any IO errors occurring during
/// reads from the DB cause a panic. All writes are buffered and must be flushed by the caller.
///
/// This is only meant for usage in tests/benchmarks.
struct KVBackedHashDB<'a, H, KF>
	where
		H: Hasher,
		KF: KeyFunction<H>,
{
	db: &'a dyn KeyValueDB,
	col: Option<u32>,
	_marker_h: PhantomData<H>,
	_marker_kf: PhantomData<KF>,
}

impl<'a, H, KF> KVBackedHashDB<'a, H, KF>
	where H: Hasher,
		  KF: KeyFunction<H>,
{
	fn new(db: &'a dyn KeyValueDB, col: Option<u32>) -> Self {
		KVBackedHashDB {
			db,
			col,
			_marker_h: Default::default(),
			_marker_kf: Default::default(),
		}
	}
}

impl<'a, H, KF> AsHashDB<H, DBValue> for KVBackedHashDB<'a, H, KF>
	where
		H: Hasher,
		KF: KeyFunction<H>,
{
	fn as_hash_db(&self) -> &HashDB<H, DBValue> {
		self
	}

	fn as_hash_db_mut(&mut self) -> &mut HashDB<H, DBValue> {
		self
	}
}

impl<'a, H, KF> HashDB<H, DBValue> for KVBackedHashDB<'a, H, KF>
	where
		H: Hasher,
		KF: KeyFunction<H>,
{
	fn get(&self, key: &H::Out, prefix: &[u8]) -> Option<DBValue> {
		let db_key = KF::key(key, prefix);
		self.db.get(self.col, db_key.as_ref()).unwrap()
	}

	fn contains(&self, key: &H::Out, prefix: &[u8]) -> bool {
		self.get(key, prefix).is_some()
	}

	fn insert(&mut self, prefix: &[u8], value: &[u8]) -> H::Out {
		let key = H::hash(value);
        let db_key = KF::key(&key, prefix);

		let mut transaction = DBTransaction::new();
		transaction.put(self.col, db_key.as_ref(), value);

		self.db.write_buffered(transaction);
		key
	}

	fn emplace(&mut self, key: H::Out, prefix: &[u8], value: DBValue) {
		let db_key = KF::key(&key, prefix);

		let mut transaction = DBTransaction::new();
		transaction.put(self.col, db_key.as_ref(), &value[..]);

        self.db.write_buffered(transaction);
	}

	fn remove(&mut self, key: &H::Out, prefix: &[u8]) {
		let db_key = KF::key(key, prefix);

		let mut transaction = DBTransaction::new();
		transaction.delete(self.col, db_key.as_ref());

		self.db.write_buffered(transaction);
	}
}
