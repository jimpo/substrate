use crate::allocator::OtherAllocator;
use crate::error::{Error, Result};
use crate::wasm_env::StateMachineContext;

use cranelift_codegen::{settings, ir, ir::types, isa};
use cranelift_entity::PrimaryMap;
use cranelift_wasm::DefinedFuncIndex;
use primitives::{Blake2Hasher, storage::well_known_keys};
use state_machine::Externalities;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem;
use std::rc::Rc;
use target_lexicon::HOST;
use wasmtime_environ::{translate_signature, Module};
use wasmtime_jit::{ActionOutcome, Context, Features, RuntimeValue};
use wasmtime_runtime::{Export, Imports, InstanceHandle, VMContext, VMFunctionBody};

pub struct WasmtimeExecutor;

impl WasmtimeExecutor {
	pub fn call_with_code_in_storage<E: Externalities<Blake2Hasher>>(
		ext: &mut E,
		method: &str,
		data: &[u8],
	) -> Result<Vec<u8>> {
		let code = ext
			.original_storage(well_known_keys::CODE)
			.ok_or(Error::InvalidCode("`CODE` not found in storage.".into()))?;
		Self::call(ext, &code, method, data)
	}

	/// Call a given method in the given code.
	///
	/// Signature of this method needs to be `(I32, I32) -> I64`.
	pub fn call<E: Externalities<Blake2Hasher>>(
		ext: &mut E,
		code: &[u8],
		method: &str,
		data: &[u8],
	) -> Result<Vec<u8>> {
		let code = ext
			.original_storage(well_known_keys::CODE)
			.ok_or(Error::InvalidCode("`CODE` not found in storage.".into()))?;

		let isa_builder = cranelift_native::builder().unwrap_or_else(|reason| {
			panic!("host machine is not a supported target: {}", reason);
		});
		let mut flag_builder = cranelift_codegen::settings::builder();
		let mut features: Features = Default::default();

		let isa = isa_builder.finish(settings::Flags::new(flag_builder));
		let mut context = Context::with_isa(isa).with_features(features);

		// Enable/disable producing of debug info.
		context.set_debug_info(true);

		let global_exports = context.get_global_exports();

		context.name_instance(
			"env".to_owned(),
			instantiate_env_module(global_exports, ext)?
		);

		// Compile and instantiating a wasm module.
		let mut instance = context
			.instantiate_module(None, &code)
			.map_err(Error::WasmtimeAction)?;

		// Allocate input data.
		let data_len = data.len() as u32;
		let data_ptr = {
			let env_instance = context.get_instance("env")
				.expect("context has instance with name \"env\"");
			let state = env_instance.host_state().downcast_mut::<StateMachineContext>()
				.expect("host_state of env instance is a StateMachineContext");
			let heap_base = get_heap_base(&mut instance)?;
			let memory = get_memory(&mut instance);
			let heap = &mut memory[(heap_base as usize)..];

			let data_offset = state.allocator.allocate(heap, data_len)?;
			heap[(data_offset as usize)..((data_offset + data_len) as usize)].copy_from_slice(data);
			heap_base + data_offset
		};
		let args = [RuntimeValue::I32(data_ptr as i32), RuntimeValue::I32(data_len as i32)];

		// If a function to invoke was given, invoke it.
		let outcome = context
			.invoke(&mut instance, method, &args[..])
			.map_err(Error::WasmtimeAction)?;
		let (output_offset, output_len) = match outcome {
			ActionOutcome::Returned { values } => {
				if values.len()	!= 1 {
					return Err(Error::InvalidReturn);
				}
				if let RuntimeValue::I64(val) = values[0] {
					(val as u32, ((val as u64) >> 32) as u32)
				} else {
					return Err(Error::InvalidReturn);
				}
			}
			ActionOutcome::Trapped { message } =>
				return Err(Error::WasmtimeTrap(message)),
		};

		let memory = get_memory(&mut instance);
		let output = &memory[(output_offset as usize)..((output_offset + output_len) as usize)];
		Ok(output.to_vec())
	}
}

// TODO: It would be safer to return a value with 'a
fn instantiate_env_module<E: Externalities<Blake2Hasher>>(
	global_exports: Rc<RefCell<HashMap<String, Option<Export>>>>,
	ext: &mut E,
	// preopened_dirs: &[(String, File)],
	// argv: &[String],
	// environ: &[(String, String)],
) -> Result<InstanceHandle> {
	let pointer_type = types::Type::triple_pointer_type(&HOST);
	let mut module = Module::new();
	let mut finished_functions: PrimaryMap<DefinedFuncIndex, *const VMFunctionBody> =
		PrimaryMap::new();
	let call_conv = isa::CallConv::triple_default(&HOST);

	macro_rules! signature {
        ($name:ident) => {{
            let sig = module.signatures.push(translate_signature(
                ir::Signature {
                    params: syscalls::$name::params()
                        .into_iter()
                        .map(ir::AbiParam::new)
                        .collect(),
                    returns: syscalls::$name::results()
                        .into_iter()
                        .map(ir::AbiParam::new)
                        .collect(),
                    call_conv,
                },
                pointer_type,
            ));
            let func = module.functions.push(sig);
            module.exports.insert(
                stringify!($name).to_owned(),
                wasmtime_environ::Export::Function(func),
            );
            finished_functions.push(syscalls::$name::SHIM as *const VMFunctionBody);
        }};
    }

	signature!(ext_print_utf8);
	signature!(ext_print_hex);
	signature!(ext_print_num);
	signature!(ext_malloc);
	signature!(ext_free);
	signature!(ext_set_storage);
	signature!(ext_set_child_storage);
	signature!(ext_clear_child_storage);
	signature!(ext_clear_storage);
	signature!(ext_exists_storage);
	signature!(ext_clear_prefix);
	signature!(ext_clear_child_prefix);
	signature!(ext_kill_child_storage);
	signature!(ext_get_allocated_storage);
	signature!(ext_get_allocated_child_storage);
	signature!(ext_get_storage_into);
	signature!(ext_get_child_storage_into);
	signature!(ext_storage_root);
	signature!(ext_child_storage_root);
	signature!(ext_storage_changes_root);
	signature!(ext_blake2_256_enumerated_trie_root);
	signature!(ext_chain_id);
	signature!(ext_twox_64);
	signature!(ext_twox_128);
	signature!(ext_twox_256);
	signature!(ext_blake2_128);
	signature!(ext_blake2_256);
	signature!(ext_keccak_256);
	signature!(ext_ed25519_public_keys);
	signature!(ext_ed25519_verify);
	signature!(ext_ed25519_generate);
	signature!(ext_ed25519_sign);
	signature!(ext_sr25519_public_keys);
	signature!(ext_sr25519_verify);
	signature!(ext_sr25519_generate);
	signature!(ext_sr25519_sign);
	signature!(ext_secp256k1_ecdsa_recover);
	signature!(ext_is_validator);
	signature!(ext_submit_transaction);
	signature!(ext_network_state);
	signature!(ext_timestamp);
	signature!(ext_sleep_until);
	signature!(ext_random_seed);
	signature!(ext_local_storage_set);
	signature!(ext_local_storage_get);
	signature!(ext_local_storage_compare_and_set);
	signature!(ext_http_request_start);
	signature!(ext_http_request_add_header);
	signature!(ext_http_request_write_body);
	signature!(ext_http_response_wait);
	signature!(ext_http_response_headers);
	signature!(ext_http_response_read_body);
	signature!(ext_sandbox_instantiate);
	signature!(ext_sandbox_instance_teardown);
	signature!(ext_sandbox_invoke);
	signature!(ext_sandbox_memory_new);
	signature!(ext_sandbox_memory_get);
	signature!(ext_sandbox_memory_set);
	signature!(ext_sandbox_memory_teardown);

	let imports = Imports::none();
	let data_initializers = Vec::new();
	let signatures = PrimaryMap::new();

	let ext: &mut dyn Externalities<Blake2Hasher> = ext;

	// Use unsafe to extend lifetime of ext reference. This is OK because the context only lives as
	// long as the instance.
	let host_state = unsafe {
		Box::new(StateMachineContext {
			ext: mem::transmute::<_, &'static mut dyn Externalities<Blake2Hasher>>(ext),
			allocator: OtherAllocator::new(),
			hash_lookup: HashMap::new(),
		})
	};

	let result = InstanceHandle::new(
		Rc::new(module),
		global_exports,
		finished_functions.into_boxed_slice(),
		imports,
		&data_initializers,
		signatures.into_boxed_slice(),
		None,
		host_state,
	);
	result.map_err(Error::WasmtimeInstantiation)
}

mod syscalls {
	use super::StateMachineContext;
	use crate::def_syscalls;
	use crate::error::{Error, Result};
	use crate::wasm_env::{EnvContext, Wasm32Ptr, Wasm32Size};
	use crate::wasmtime_utils::{AbiParam, AbiRet};

	use codec::Encode;
	use cranelift_codegen::ir::types::Type;
	use log::trace;
	use primitives::{
		blake2_128, blake2_256, twox_64, twox_128, twox_256, ed25519, sr25519, Pair, crypto::KeyTypeId,
		offchain, hexdisplay::HexDisplay, sandbox as sandbox_primitives, H256, Blake2Hasher,
	};
	use state_machine::ChildStorageKey;
	use std::convert::{TryFrom, TryInto};
	use trie::{TrieConfiguration, trie_types::Layout};
	use wasmtime_runtime::{Export, VMContext};

	#[cfg(feature="wasm-extern-trace")]
	macro_rules! debug_trace {
		( $( $x:tt )* ) => ( trace!( $( $x )* ) )
	}
	#[cfg(not(feature="wasm-extern-trace"))]
	macro_rules! debug_trace {
		( $( $x:tt )* ) => ()
	}

	def_syscalls! {
		ext_print_utf8(&this, utf8_data: Wasm32Ptr, utf8_len: Wasm32Size) -> Result<()> {
			if let Ok(utf8) = this.memory.read(utf8_data, utf8_len) {
				if let Ok(message) = std::str::from_utf8(utf8) {
					println!("{}", message);
				}
			}
			Ok(())
		}

		ext_print_hex(&this, data: Wasm32Ptr, len: Wasm32Size) -> Result<()> {
			if let Ok(hex) = this.memory.read(data, len) {
				println!("{}", HexDisplay::from(&hex));
			}
			Ok(())
		}

		ext_print_num(&_this, number: u64) -> Result<()> {
			println!("{}", number);
			Ok(())
		}

		ext_malloc(&this, size: Wasm32Size) -> Result<Wasm32Ptr> {
			let ptr = this.memory.allocate(size)?;
			debug_trace!(target: "sr-io", "malloc {} bytes at {}", size, ptr);
			Ok(ptr)
		}

		ext_free(&this, ptr: Wasm32Ptr) -> Result<()> {
			this.memory.deallocate(ptr)?;
			debug_trace!(target: "sr-io", "free {}", ptr);
			Ok(())
		}

		ext_set_storage(
			&this,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			value_data: Wasm32Ptr,
			value_len: Wasm32Size,
		) -> Result<()> {
			let key = this.memory.read(key_data, key_len)?.to_vec();
			let value = this.memory.read(value_data, value_len)?.to_vec();
			debug_trace!(
				target: "wasm-trace",
				"*** Setting storage: %{} -> {}   [k={}]",
				this.formatter.key(&key),
				HexDisplay::from(&value),
				HexDisplay::from(&key),
			);
			this.ext.set_storage(key.to_vec(), value.to_vec());
			Ok(())
		}

		ext_set_child_storage(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			value_data: Wasm32Ptr,
			value_len: Wasm32Size,
		) -> Result<()> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let key = this.memory.read(key_data, key_len)?;
			let value = this.memory.read(value_data, value_len)?;
			debug_trace!(
				target: "wasm-trace", "*** Setting child storage: {} -> %{} -> {}   [k={}]",
				primitives::hexdisplay::ascii_format(storage_key),
				this.formatter.key(key),
				HexDisplay::from(value),
				HexDisplay::from(key)
			);
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| "ext_set_child_storage: child storage key is invalid")?;
			this.ext.set_child_storage(storage_key, key.to_vec(), value.to_vec());
			Ok(())
		}

		ext_clear_child_storage(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
		) -> Result<()> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let key = this.memory.read(key_data, key_len)?;
			debug_trace!(
				target: "wasm-trace", "*** Clearing child storage: {} -> {}   [k={}]",
				primitives::hexdisplay::ascii_format(&storage_key),
				this.formatter.key(key),
				HexDisplay::from(&key)
			);
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| "ext_clear_child_storage: child storage key is not valid")?;

			this.ext.clear_child_storage(storage_key, key);
			Ok(())
		}

		ext_clear_storage(&this, key_data: Wasm32Ptr, key_len: Wasm32Size) -> Result<()> {
			let key = this.memory.read(key_data, key_len)?;
			debug_trace!(
				target: "wasm-trace", "*** Clearing storage: {}   [k={}]",
				this.formatter.key(key),
				HexDisplay::from(key)
			);
			this.ext.clear_storage(key);
			Ok(())
		}

		ext_exists_storage(&this, key_data: Wasm32Ptr, key_len: Wasm32Size) -> Result<u32> {
			let key = this.memory.read(key_data, key_len)?;
			Ok(if this.ext.exists_storage(&key) { 1 } else { 0 })
		}

		ext_exists_child_storage(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
		) -> Result<u32> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let key = this.memory.read(key_data, key_len)?;
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| "ext_exists_child_storage: child storage key is not valid")?;
			Ok(if this.ext.exists_child_storage(storage_key, &key) { 1 } else { 0 })
		}

		ext_clear_prefix(&this, prefix_data: Wasm32Ptr, prefix_len: Wasm32Size) -> Result<()> {
			let prefix = this.memory.read(prefix_data, prefix_len)?;
			this.ext.clear_prefix(&prefix);
			Ok(())
		}

		ext_clear_child_prefix(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			prefix_data: Wasm32Ptr,
			prefix_len: Wasm32Size,
		) -> Result<()> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| "ext_clear_child_prefix: child storage key is not valid")?;
			let prefix = this.memory.read(prefix_data, prefix_len)?;
			this.ext.clear_child_prefix(storage_key, prefix);
			Ok(())
		}

		ext_kill_child_storage(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
		) -> Result<()> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| "ext_exists_child_storage: child storage key is not valid")?;
			this.ext.kill_child_storage(storage_key);
			Ok(())
		}

		// return 0 and place u32::max_value() into written_out if no value exists for the key.
		ext_get_allocated_storage(
			&this,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			written_out: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let key = this.memory.read(key_data, key_len)?;
			let maybe_value = this.ext.storage(&key);

			debug_trace!(
				target: "wasm-trace", "*** Getting storage: {} == {}   [k={}]",
				this.formatter.key(key),
				if let Some(ref b) = maybe_value {
					&format!("{}", HexDisplay::from(b))
				} else {
					"<empty>"
				},
				HexDisplay::from(&key),
			);

			if let Some(value) = maybe_value {
				let ptr = this.memory.allocate(value.len() as Wasm32Size)?;
				this.memory.write(ptr, &value)?;
				this.memory.write_u32(written_out, value.len() as u32)?;
				Ok(ptr)
			} else {
				this.memory.write_u32(written_out, u32::max_value())?;
				Ok(0)
			}
		}

		// return 0 and place u32::max_value() into written_out if no value exists for the key.
		ext_get_allocated_child_storage(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			written_out: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let key = this.memory.read(key_data, key_len)?;

			let maybe_value = {
				let storage_key = ChildStorageKey::from_slice(storage_key)
					.ok_or_else(|| "ext_get_allocated_child_storage: child storage key is not valid")?;
				this.ext.child_storage(storage_key, key)
			};

			debug_trace!(
				target: "wasm-trace", "*** Getting child storage: {} -> {} == {}   [k={}]",
				primitives::hexdisplay::ascii_format(storage_key),
				this.formatter.key(key),
				this.formatter.value(&maybe_value),
				HexDisplay::from(&key),
			);

			if let Some(value) = maybe_value {
				let ptr = this.memory.allocate(value.len() as u32)?;
				this.memory.write(ptr, &value)?;
				this.memory.write_u32(written_out, value.len() as u32)?;
				Ok(ptr)
			} else {
				this.memory.write_u32(written_out, u32::max_value())?;
				Ok(0)
			}
		}

		// return u32::max_value() if no value exists for the key.
		ext_get_storage_into(
			&this,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			value_data: Wasm32Ptr,
			value_len: Wasm32Size,
			value_offset: Wasm32Size,
		) -> Result<u32> {
			let key = this.memory.read(key_data, key_len)?;
			let maybe_value = this.ext.storage(key);
			debug_trace!(
				target: "wasm-trace", "*** Getting storage: {} == {}   [k={}]",
				this.formatter.key(key),
				this.formatter.value(&maybe_value),
				HexDisplay::from(&key),
			);

			if let Some(value) = maybe_value {
				let value = &value[value_offset as usize..];
				let written = std::cmp::min(value_len as usize, value.len());
				this.memory.write(value_data, &value[..written])?;
				Ok(value.len() as u32)
			} else {
				Ok(u32::max_value())
			}
		}

		// return u32::max_value() if no value exists for the key.
		ext_get_child_storage_into(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			key_data: Wasm32Ptr,
			key_len: Wasm32Size,
			value_data: Wasm32Ptr,
			value_len: Wasm32Size,
			value_offset: Wasm32Size,
		) -> Result<u32> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let key = this.memory.read(key_data, key_len)?;

			let maybe_value = {
				let storage_key = ChildStorageKey::from_slice(storage_key)
					.ok_or_else(|| "ext_get_child_storage_into: child storage key is not valid")?;
				this.ext.child_storage(storage_key, key)
			};
			debug_trace!(
				target: "wasm-trace", "*** Getting storage: {} -> {} == {}   [k={}]",
				primitives::hexdisplay::ascii_format(&storage_key),
				this.formatter.key(key),
				this.formatter.value(&maybe_value),
				HexDisplay::from(&key),
			);

			if let Some(value) = maybe_value {
				let value = &value[value_offset as usize..];
				let written = std::cmp::min(value_len as usize, value.len());
				this.memory.write(value_data, &value[..written])?;
				Ok(value.len() as u32)
			} else {
				Ok(u32::max_value())
			}
		}

		ext_storage_root(&this, result: Wasm32Ptr) -> Result<()> {
			let r = this.ext.storage_root();
			this.memory.write(result, r.as_ref())?;
			Ok(())
		}

		ext_child_storage_root(
			&this,
			storage_key_data: Wasm32Ptr,
			storage_key_len: Wasm32Size,
			written_out: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let storage_key = this.memory.read(storage_key_data, storage_key_len)?;
			let storage_key = ChildStorageKey::from_slice(storage_key)
				.ok_or_else(|| Error::EnvModule("ext_child_storage_root: child storage key is not valid".into()))?;
			let value = this.ext.child_storage_root(storage_key);

			let ptr = this.memory.allocate(value.len() as Wasm32Size)?;
			this.memory.write(ptr, &value)?;
			this.memory.write_u32(written_out, value.len() as u32)?;
			Ok(ptr)
		}

		ext_storage_changes_root(
			&this,
			parent_hash_data: Wasm32Ptr,
			parent_hash_len: Wasm32Size,
			result: Wasm32Ptr,
		) -> Result<u32> {
			let mut parent_hash = H256::default();
			if parent_hash_len != parent_hash.as_ref().len() as Wasm32Size {
				return Err(Error::EnvModule("Invalid parent_hash_len in ext_storage_changes_root".into()));
			}
			let raw_parent_hash = this.memory.read(parent_hash_data, parent_hash_len)?;
			parent_hash.as_mut().copy_from_slice(&raw_parent_hash[..]);
			let r = this.ext.storage_changes_root(parent_hash)
				.map_err(|_| Error::EnvModule("Invaid parent_hash passed to ext_storage_changes_root".into()))?;
			if let Some(r) = r {
				this.memory.write(result, &r[..])?;
				Ok(1)
			} else {
				Ok(0)
			}
		}

		ext_blake2_256_enumerated_trie_root(
			&this,
			values_data: Wasm32Ptr,
			lens_data: Wasm32Ptr,
			lens_len: u32,
			result: Wasm32Ptr,
		) -> Result<()> {
			let values = (0..lens_len)
				.map(|i| this.memory.read_u32(lens_data + i * 4))
				.collect::<Result<Vec<u32>>>()?
				.into_iter()
				.scan(0u32, |acc, v| { let o = *acc; *acc += v; Some((o, v)) })
				.map(|(offset, len)| this.memory.read(values_data + offset, len))
				.collect::<Result<Vec<_>>>()?;
			let r = Layout::<Blake2Hasher>::ordered_trie_root(values.into_iter());
			this.memory.write(result, &r[..])?;
			Ok(())
		}

		ext_chain_id(&this) -> Result<u64> {
			Ok(this.ext.chain_id())
		}

		ext_twox_64(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 8] = if len == 0 {
				let hashed = twox_64(&[0u8; 0]);
				debug_trace!(target: "xxhash", "XXhash: '' -> {}", HexDisplay::from(&hashed));
				this.formatter.record_hash_preimage(hashed.to_vec(), vec![]);
				hashed
			} else {
				let key = this.memory.read(data, len)?;
				let hashed_key = twox_64(&key);

				debug_trace!(
					target: "xxhash", "XXhash: {} -> {}",
					if let Ok(_skey) = str::from_utf8(&key) {
						_skey
					} else {
						&format!("{}", HexDisplay::from(&key))
					},
					HexDisplay::from(&hashed_key),
				);

				this.formatter.record_hash_preimage(hashed_key.to_vec(), key.to_vec());
				hashed_key
			};

			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_twox_128(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 16] = if len == 0 {
				let hashed = twox_128(&[0u8; 0]);
				debug_trace!(target: "xxhash", "XXhash: '' -> {}", HexDisplay::from(&hashed));
				this.formatter.record_hash_preimage(hashed.to_vec(), vec![]);
				hashed
			} else {
				let key = this.memory.read(data, len)?;
				let hashed_key = twox_128(&key);
				debug_trace!(
					target: "xxhash", "XXhash: {} -> {}",
					&if let Ok(_skey) = str::from_utf8(&key) {
						*_skey
					} else {
						format!("{}", HexDisplay::from(&key))
					},
					HexDisplay::from(&hashed_key),
				);
				this.formatter.record_hash_preimage(hashed_key.to_vec(), key.to_vec());
				hashed_key
			};

			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_twox_256(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 32] = if len == 0 {
				twox_256(&[0u8; 0])
			} else {
				let mem = this.memory.read(data, len)?;
				twox_256(&mem)
			};
			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_blake2_128(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 16] = if len == 0 {
				let hashed = blake2_128(&[0u8; 0]);
				this.formatter.record_hash_preimage(hashed.to_vec(), vec![]);
				hashed
			} else {
				let key = this.memory.read(data, len)?;
				let hashed_key = blake2_128(&key);
				this.formatter.record_hash_preimage(hashed_key.to_vec(), key.to_vec());
				hashed_key
			};

			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_blake2_256(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 32] = if len == 0 {
				blake2_256(&[0u8; 0])
			} else {
				let mem = this.memory.read(data, len)?;
				blake2_256(&mem)
			};
			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_keccak_256(&this, data: Wasm32Ptr, len: Wasm32Size, out: Wasm32Ptr) -> Result<()> {
			let result: [u8; 32] = if len == 0 {
				tiny_keccak::keccak256(&[0u8; 0])
			} else {
				let mem = this.memory.read(data, len)?;
				tiny_keccak::keccak256(&mem)
			};
			this.memory.write(out, &result)?;
			Ok(())
		}

		ext_ed25519_public_keys(
			&this,
			id_data: Wasm32Ptr,
			result_len: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let id: [u8; 4] = this.memory.read(id_data, 4)?.try_into().unwrap();
			let key_type = KeyTypeId(id);

			let keys = runtime_io::ed25519_public_keys(key_type).encode();

			let len = keys.len() as Wasm32Size;
			let ptr = this.memory.allocate(len)?;

			this.memory.write(ptr, keys.as_ref())?;
			this.memory.write_u32(result_len, len)?;

			Ok(ptr)
		}

		ext_ed25519_verify(
			&this,
			msg_data: Wasm32Ptr,
			msg_len: Wasm32Size,
			sig_data: Wasm32Ptr,
			pubkey_data: Wasm32Ptr,
		) -> Result<u32> {
			let mut sig = [0u8; 64];
			sig[..].copy_from_slice(this.memory.read(sig_data, 64)?);
			let pubkey: [u8; 32] = this.memory.read(pubkey_data, 32)?.try_into().unwrap();
			let msg = this.memory.read(msg_data, msg_len)?;

			Ok(if ed25519::Pair::verify_weak(&sig, &msg, &pubkey) {
				0
			} else {
				5
			})
		}

		ext_ed25519_generate(
			&this,
			id_data: Wasm32Ptr,
			seed: Wasm32Ptr,
			seed_len: Wasm32Size,
			out: Wasm32Ptr,
		) -> Result<()> {
			let mut id = [0u8; 4];
			this.memory.read_into(id_data, &mut id[..])
				.map_err(|_| "Invalid attempt to get id in ext_ed25519_generate")?;
			let key_type = KeyTypeId(id);

			let seed = if seed_len == 0 {
				None
			} else {
				Some(
					this.memory.read(seed, seed_len)
						.map_err(|_| "Invalid attempt to get seed in ext_ed25519_generate")?
				)
			};

			let seed = seed.as_ref()
				.map(|seed|
					std::str::from_utf8(&seed)
						.map_err(|_| "Seed not a valid utf8 string in ext_sr25119_generate")
				).transpose()?;

			let pubkey = runtime_io::ed25519_generate(key_type, seed);

			this.memory.write(out, pubkey.as_ref())
				.map_err(|_| "Invalid attempt to set out in ext_ed25519_generate".into())
		}

		ext_ed25519_sign(
			&this,
			id_data: Wasm32Ptr,
			pubkey_data: Wasm32Ptr,
			msg_data: Wasm32Ptr,
			msg_len: Wasm32Size,
			out: Wasm32Ptr,
		) -> Result<u32> {
			let mut id = [0u8; 4];
			this.memory.read_into(id_data, &mut id[..])
				.map_err(|_| "Invalid attempt to get id in ext_ed25519_sign")?;
			let key_type = KeyTypeId(id);

			let mut pubkey = [0u8; 32];
			this.memory.read_into(pubkey_data, &mut pubkey[..])
				.map_err(|_| "Invalid attempt to get pubkey in ext_ed25519_sign")?;

			let msg = this.memory.read(msg_data, msg_len)
				.map_err(|_| "Invalid attempt to get message in ext_ed25519_sign")?;

			let signature = runtime_io::ed25519_sign(key_type, &ed25519::Public(pubkey), &msg);

			match signature {
				Some(signature) => {
					this.memory
						.write(out, signature.as_ref())
						.map_err(|_| "Invalid attempt to set out in ext_ed25519_sign")?;
					Ok(0)
				},
				None => Ok(1),
			}
		}

		ext_sr25519_public_keys(
			&this,
			id_data: Wasm32Ptr,
			result_len: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let mut id = [0u8; 4];
			this.memory.read_into(id_data, &mut id[..])
				.map_err(|_| "Invalid attempt to get id in ext_sr25519_public_keys")?;
			let key_type = KeyTypeId(id);

			let keys = runtime_io::sr25519_public_keys(key_type).encode();

			let len = keys.len() as u32;
			let offset = this.memory.allocate(len)?;

			this.memory.write(offset, keys.as_ref())?;
			this.memory.write_u32(result_len, len)?;

			Ok(offset)
		}

		ext_sr25519_verify(
			&this,
			msg_data: Wasm32Ptr,
			msg_len: Wasm32Size,
			sig_data: Wasm32Ptr,
			pubkey_data: Wasm32Ptr,
		) -> Result<u32> {
			let mut sig = [0u8; 64];
			this.memory.read_into(sig_data, &mut sig[..])
				.map_err(|_| "Invalid attempt to get signature in ext_sr25519_verify")?;
			let mut pubkey = [0u8; 32];
			this.memory.read_into(pubkey_data, &mut pubkey[..])
				.map_err(|_| "Invalid attempt to get pubkey in ext_sr25519_verify")?;
			let msg = this.memory.read(msg_data, msg_len)
				.map_err(|_| "Invalid attempt to get message in ext_sr25519_verify")?;

			Ok(if sr25519::Pair::verify_weak(&sig, msg, &pubkey) {
				0
			} else {
				5
			})
		}

		ext_sr25519_generate(
			&this,
			id_data: Wasm32Ptr,
			seed: Wasm32Ptr,
			seed_len: Wasm32Size,
			out: Wasm32Ptr,
		) -> Result<()> {
			let mut id = [0u8; 4];
			this.memory.read_into(id_data, &mut id[..])
				.map_err(|_| "Invalid attempt to get id in ext_sr25519_generate")?;
			let key_type = KeyTypeId(id);
			let seed = if seed_len == 0 {
				None
			} else {
				Some(
					this.memory.read(seed, seed_len)
						.map_err(|_| "Invalid attempt to get seed in ext_sr25519_generate")?
				)
			};

			let seed = seed.as_ref()
				.map(|seed|
					std::str::from_utf8(&seed)
						.map_err(|_| "Seed not a valid utf8 string in ext_sr25119_generate")
				)
				.transpose()?;

			let pubkey = runtime_io::sr25519_generate(key_type, seed);

			this.memory.write(out, pubkey.as_ref())
				.map_err(|_| "Invalid attempt to set out in ext_sr25519_generate".into())
		}

		ext_sr25519_sign(
			&this,
			id_data: Wasm32Ptr,
			pubkey_data: Wasm32Ptr,
			msg_data: Wasm32Ptr,
			msg_len: Wasm32Size,
			out: Wasm32Ptr,
		) -> Result<u32> {
			let mut id = [0u8; 4];
			this.memory.read_into(id_data, &mut id[..])
				.map_err(|_| "Invalid attempt to get id in ext_sr25519_sign")?;
			let key_type = KeyTypeId(id);

			let mut pubkey = [0u8; 32];
			this.memory.read_into(pubkey_data, &mut pubkey[..])
				.map_err(|_| "Invalid attempt to get pubkey in ext_sr25519_sign")?;

			let msg = this.memory.read(msg_data, msg_len)
				.map_err(|_| "Invalid attempt to get message in ext_sr25519_sign")?;

			let signature = runtime_io::sr25519_sign(key_type, &sr25519::Public(pubkey), &msg);

			match signature {
				Some(signature) => {
					this.memory.write(out, signature.as_ref())
						.map_err(|_| "Invalid attempt to set out in ext_sr25519_sign")?;
					Ok(0)
				},
				None => Ok(1),
			}
		}

		ext_secp256k1_ecdsa_recover(
			&this,
			msg_data: Wasm32Ptr,
			sig_data: Wasm32Ptr,
			pubkey_data: Wasm32Ptr,
		) -> Result<u32> {
			let mut sig = [0u8; 65];
			this.memory.read_into(sig_data, &mut sig[..])
				.map_err(|_| "Invalid attempt to get signature in ext_secp256k1_ecdsa_recover")?;
			let rs = match secp256k1::Signature::parse_slice(&sig[0..64]) {
				Ok(rs) => rs,
				_ => return Ok(1),
			};
			let v = match secp256k1::RecoveryId::parse(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8) {
				Ok(v) => v,
				_ => return Ok(2),
			};


			let mut msg = [0u8; 32];
			this.memory.read_into(msg_data, &mut msg[..])
				.map_err(|_| "Invalid attempt to get message in ext_secp256k1_ecdsa_recover")?;

			let pubkey = match secp256k1::recover(&secp256k1::Message::parse(&msg), &rs, &v) {
				Ok(pk) => pk,
				_ => return Ok(3),
			};

			this.memory.write(pubkey_data, &pubkey.serialize()[1..65])
				.map_err(|_| "Invalid attempt to set pubkey in ext_secp256k1_ecdsa_recover")?;

			Ok(0)
		}

		ext_is_validator(&this) -> Result<u32> {
			Ok(if runtime_io::is_validator() {
				1
			} else {
				0
			})
		}

		ext_submit_transaction(&this, msg_data: Wasm32Ptr, len: Wasm32Size) -> Result<u32> {
			let extrinsic = this.memory.read(msg_data, len)
				.map_err(|_| "OOB while ext_submit_transaction: wasm")?;

			let res = this.ext.offchain()
				.map(|api| api.submit_transaction(extrinsic.to_vec()))
				.ok_or_else(|| "Calling unavailable API ext_submit_transaction: wasm")?;

			Ok(if res.is_ok() { 0 } else { 1 })
		}

		ext_network_state(&this, written_out: Wasm32Ptr) -> Result<Wasm32Ptr> {
			let res = this.ext.offchain()
				.map(|api| api.network_state())
				.ok_or_else(|| "Calling unavailable API ext_network_state: wasm")?;

			let encoded = res.encode();
			let offset = this.memory.allocate(encoded.len() as Wasm32Size)?;
			this.memory.write(offset, &encoded)
				.map_err(|_| "Invalid attempt to set memory in ext_network_state")?;

			this.memory.write_u32(written_out, encoded.len() as u32)
				.map_err(|_| "Invalid attempt to write written_out in ext_network_state")?;

			Ok(offset)
		}

		ext_timestamp(&this) -> Result<u64> {
			let timestamp = this.ext.offchain()
				.map(|api| api.timestamp())
				.ok_or_else(|| "Calling unavailable API ext_timestamp: wasm")?;
			Ok(timestamp.unix_millis())
		}

		ext_sleep_until(&this, deadline: u64) -> Result<()> {
			this.ext.offchain()
				.map(|api| api.sleep_until(offchain::Timestamp::from_unix_millis(deadline)))
				.ok_or_else(|| "Calling unavailable API ext_sleep_until: wasm")?;
			Ok(())
		}

		ext_random_seed(&this, seed_data: Wasm32Ptr) -> Result<()> {
			// NOTE the runtime as assumptions about seed size.
			let seed: [u8; 32] = this.ext.offchain()
				.map(|api| api.random_seed())
				.ok_or_else(|| "Calling unavailable API ext_random_seed: wasm")?;

			this.memory.write(seed_data, &seed)
				.map_err(|_| "Invalid attempt to set value in ext_random_seed")?;
			Ok(())
		}

		ext_local_storage_set(
			&this,
			kind: u32,
			key: Wasm32Ptr,
			key_len: Wasm32Size,
			value: Wasm32Ptr,
			value_len: Wasm32Size,
		) -> Result<()> {
			let kind = offchain::StorageKind::try_from(kind)
				.map_err(|_| "storage kind OOB while ext_local_storage_set: wasm")?;
			let key = this.memory.read(key, key_len)
				.map_err(|_| "OOB while ext_local_storage_set: wasm")?;
			let value = this.memory.read(value, value_len)
				.map_err(|_| "OOB while ext_local_storage_set: wasm")?;

			this.ext.offchain()
				.map(|api| api.local_storage_set(kind, &key, &value))
				.ok_or_else(|| "Calling unavailable API ext_local_storage_set: wasm")?;

			Ok(())
		}

		ext_local_storage_get(
			&this,
			kind: u32,
			key: Wasm32Ptr,
			key_len: Wasm32Size,
			value_len: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			let kind = offchain::StorageKind::try_from(kind)
				.map_err(|_| "storage kind OOB while ext_local_storage_get: wasm")?;
			let key = this.memory.read(key, key_len)
				.map_err(|_| "OOB while ext_local_storage_get: wasm")?;

			let maybe_value = this.ext.offchain()
				.map(|api| api.local_storage_get(kind, &key))
				.ok_or_else(|| "Calling unavailable API ext_local_storage_get: wasm")?;

			let (offset, len) = if let Some(value) = maybe_value {
				let offset = this.memory.allocate(value.len() as Wasm32Size)?;
				this.memory.write(offset, &value)
					.map_err(|_| "Invalid attempt to set memory in ext_local_storage_get")?;
				(offset, value.len() as u32)
			} else {
				(0, u32::max_value())
			};

			this.memory.write_u32(value_len, len)
				.map_err(|_| "Invalid attempt to write value_len in ext_local_storage_get")?;

			Ok(offset)
		}

		ext_local_storage_compare_and_set(
			&this,
			kind: u32,
			key: Wasm32Ptr,
			key_len: Wasm32Size,
			old_value: Wasm32Ptr,
			old_value_len: Wasm32Size,
			new_value: Wasm32Ptr,
			new_value_len: Wasm32Size,
		) -> Result<u32> {
			let kind = offchain::StorageKind::try_from(kind)
				.map_err(|_| "storage kind OOB while ext_local_storage_compare_and_set: wasm")?;
			let key = this.memory.read(key, key_len)
				.map_err(|_| "OOB while ext_local_storage_compare_and_set: wasm")?;
			let new_value = this.memory.read(new_value, new_value_len)
				.map_err(|_| "OOB while ext_local_storage_compare_and_set: wasm")?;

			let res = {
				if old_value == u32::max_value() {
					this.ext.offchain()
						.map(|api| api.local_storage_compare_and_set(kind, &key, None, &new_value))
						.ok_or_else(|| "Calling unavailable API ext_local_storage_compare_and_set: wasm")?
				} else {
					let v = this.memory.read(old_value, old_value_len)
						.map_err(|_| "OOB while ext_local_storage_compare_and_set: wasm")?;
					this.ext.offchain()
						.map(|api| api.local_storage_compare_and_set(kind, &key, Some(v), &new_value))
						.ok_or_else(|| "Calling unavailable API ext_local_storage_compare_and_set: wasm")?
				}
			};

			Ok(if res { 0 } else { 1 })
		}

		ext_http_request_start(
			&this,
			method: Wasm32Ptr,
			method_len: Wasm32Size,
			url: Wasm32Ptr,
			url_len: Wasm32Size,
			meta: Wasm32Ptr,
			meta_len: Wasm32Size,
		) -> Result<u32> {
			let method = this.memory.read(method, method_len)
				.map_err(|_| "OOB while ext_http_request_start: wasm")?;
			let url = this.memory.read(url, url_len)
				.map_err(|_| "OOB while ext_http_request_start: wasm")?;
			let meta = this.memory.read(meta, meta_len)
				.map_err(|_| "OOB while ext_http_request_start: wasm")?;

			let method_str = std::str::from_utf8(method)
				.map_err(|_| "invalid str while ext_http_request_start: wasm")?;
			let url_str = std::str::from_utf8(url)
				.map_err(|_| "invalid str while ext_http_request_start: wasm")?;

			let id = this.ext.offchain()
				.map(|api| api.http_request_start(method_str, url_str, &*meta))
				.ok_or_else(|| "Calling unavailable API ext_http_request_start: wasm")?;

			if let Ok(id) = id {
				Ok(id.into())
			} else {
				Ok(u32::max_value())
			}
		}

		ext_http_request_add_header(
			&this,
			request_id: u32,
			name: Wasm32Ptr,
			name_len: Wasm32Size,
			value: Wasm32Ptr,
			value_len: Wasm32Size,
		) -> Result<u32> {
			let name = this.memory.read(name, name_len)
				.map_err(|_| "OOB while ext_http_request_add_header: wasm")?;
			let value = this.memory.read(value, value_len)
				.map_err(|_| "OOB while ext_http_request_add_header: wasm")?;

			let name_str = std::str::from_utf8(&name)
				.map_err(|_| "Invalid str while ext_http_request_add_header: wasm")?;
			let value_str = std::str::from_utf8(&value)
				.map_err(|_| "Invalid str while ext_http_request_add_header: wasm")?;

			let res = this.ext.offchain()
				.map(|api| api.http_request_add_header(
					offchain::HttpRequestId(request_id as u16),
					&name_str,
					&value_str,
				))
				.ok_or_else(|| "Calling unavailable API ext_http_request_add_header: wasm")?;

			Ok(if res.is_ok() { 0 } else { 1 })
		}

		ext_http_request_write_body(
			&this,
			request_id: u32,
			chunk: Wasm32Ptr,
			chunk_len: Wasm32Size,
			deadline: u64
		) -> Result<u32> {
			let chunk = this.memory.read(chunk, chunk_len)
				.map_err(|_| "OOB while ext_http_request_write_body: wasm")?;

			let res = this.ext.offchain()
				.map(|api| api.http_request_write_body(
					offchain::HttpRequestId(request_id as u16),
					&chunk,
					deadline_to_timestamp(deadline)
				))
				.ok_or_else(|| "Calling unavailable API ext_http_request_write_body: wasm")?;

			Ok(match res {
				Ok(()) => 0,
				Err(e) => e.into(),
			})
		}

		ext_http_response_wait(
			&this,
			ids: Wasm32Ptr,
			ids_len: Wasm32Size,
			statuses: Wasm32Ptr,
			deadline: u64
		) -> Result<()> {
			let ids = (0..ids_len)
				.map(|i|
					 this.memory.read_u32(ids + i * 4)
						.map(|id: u32| offchain::HttpRequestId(id as u16))
						.map_err(|_| "OOB while ext_http_response_wait: wasm")
				)
				.collect::<::std::result::Result<Vec<_>, _>>()?;

			let res = this.ext.offchain()
				.map(|api| api.http_response_wait(&ids, deadline_to_timestamp(deadline)))
				.ok_or_else(|| "Calling unavailable API ext_http_response_wait: wasm")?
				.into_iter()
				.map(|status| status.into())
				.enumerate()
				// make sure to take up to `ids_len` to avoid exceeding the mem.
				.take(ids_len as usize);

			for (i, status) in res {
				this.memory.write_u32(statuses + i as u32 * 4, status)
					.map_err(|_| "Invalid attempt to set memory in ext_http_response_wait")?;
			}

			Ok(())
		}

		ext_http_response_headers(
			&this,
			request_id: u32,
			written_out: Wasm32Ptr,
		) -> Result<Wasm32Ptr> {
			use codec::Encode;

			let headers = this.ext.offchain()
				.map(|api| api.http_response_headers(offchain::HttpRequestId(request_id as u16)))
				.ok_or_else(|| "Calling unavailable API ext_http_response_headers: wasm")?;

			let encoded = headers.encode();
			let len = encoded.len() as u32;
			let ptr = this.memory.allocate(encoded.len() as Wasm32Size)?;
			this.memory.write(ptr, &encoded)
				.map_err(|_| "Invalid attempt to set memory in ext_http_response_headers")?;
			this.memory.write_u32(written_out, encoded.len() as u32)
				.map_err(|_| "Invalid attempt to write written_out in ext_http_response_headers")?;

			Ok(ptr)
		}

		ext_http_response_read_body(
			&this,
			request_id: u32,
			buffer: Wasm32Ptr,
			buffer_len: Wasm32Size,
			deadline: u64
		) -> Result<u32> {
			let mut internal_buffer = Vec::with_capacity(buffer_len as usize);
			internal_buffer.resize(buffer_len as usize, 0);

			let res = this.ext.offchain()
				.map(|api| api.http_response_read_body(
					offchain::HttpRequestId(request_id as u16),
					&mut internal_buffer,
					deadline_to_timestamp(deadline),
				))
				.ok_or_else(|| "Calling unavailable API ext_http_response_read_body: wasm")?;

			Ok(match res {
				Ok(read) => {
					this.memory.write(buffer, &internal_buffer[..read])
						.map_err(|_| "Invalid attempt to set memory in ext_http_response_read_body")?;

					read as u32
				},
				Err(err) => {
					u32::max_value() - u32::from(err) + 1
				}
			})
		}

		ext_sandbox_instantiate(
			&this,
			dispatch_thunk_idx: u32,
			wasm_ptr: Wasm32Ptr,
			wasm_len: Wasm32Size,
			imports_ptr: Wasm32Ptr,
			imports_len: Wasm32Size,
			state: u32,
		) -> Result<u32> {
			Err("Unimplemented".into())
		}

		ext_sandbox_instance_teardown(&this, instance_idx: u32) -> Result<()> {
			Err("Unimplemented".into())
		}

		ext_sandbox_invoke(
			&this,
			instance_idx: u32,
			export_ptr: Wasm32Ptr,
			export_len: Wasm32Size,
			args_ptr: Wasm32Ptr,
			args_len: Wasm32Size,
			return_val_ptr: Wasm32Ptr,
			return_val_len: Wasm32Size,
			state: u32,
		) -> Result<u32> {
			Err("Unimplemented".into())
		}

		ext_sandbox_memory_new(&this, initial: u32, maximum: u32) -> Result<u32> {
			Err("Unimplemented".into())
		}

		ext_sandbox_memory_get(
			&this,
			memory_idx: u32,
			offset: u32,
			buf_ptr: Wasm32Ptr,
			buf_len: Wasm32Size,
		) -> Result<u32> {
			Err("Unimplemented".into())
		}

		ext_sandbox_memory_set(
			&this,
			memory_idx: u32,
			offset: u32,
			val_ptr: Wasm32Ptr,
			val_len: Wasm32Size,
		) -> Result<u32> {
			Err("Unimplemented".into())
		}

		ext_sandbox_memory_teardown(&this, memory_idx: u32) -> Result<()> {
			Err("Unimplemented".into())
		}
	}

	fn deadline_to_timestamp(deadline: u64) -> Option<offchain::Timestamp> {
		if deadline == 0 {
			None
		} else {
			Some(offchain::Timestamp::from_unix_millis(deadline))
		}
	}
}

fn get_memory(instance: &mut InstanceHandle) -> &mut [u8] {
	// TODO: Make sure panicking is handled in an OK way.
	match instance.lookup("memory") {
		Some(Export::Memory { definition, vmctx: _, memory: _ }) => unsafe {
			std::slice::from_raw_parts_mut(
				(*definition).base,
				(*definition).current_length,
			)
		},
		_ => panic!("memory export is checked by validation (probably)"),
	}
}

fn get_heap_base(instance: &mut InstanceHandle) -> Result<u32> {
	match instance.lookup("__heap_base") {
		Some(Export::Global { definition, vmctx: _, global: _ }) => unsafe {
			Ok(*(*definition).as_u32())
		},
		_ => return Err(Error::HeapBaseNotFoundOrInvalid),
	}
}
