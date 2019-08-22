use crate::allocator::{LinearMemory, FreeingBumpHeapAllocator};
use crate::error::{Error, Result};

use codec::{Decode, Encode};
use hex;
use lucet_runtime_internals::{
	alloc::{Alloc, Limits},
	instance::{InstanceInternal, RunResult},
	module::{DlModule, Module},
	region::{Region, mmap::MmapRegion},
	val::Val,
};
use primitives::{
	Blake2Hasher, H256, NativeOrEncoded,
	storage::well_known_keys,
};
use state_machine::{CodeExecutor, Externalities};
use std::mem::size_of;
use std::panic::UnwindSafe;
use std::path::Path;
use std::result;
use std::sync::Arc;

struct MyContext<'a, E>
	where E: Externalities<Blake2Hasher>,
{
	ext: &'a mut E,
}

pub struct CompiledWasmExecutor<'a> {
	shared_object_dir: &'a Path,
}

impl<'a> CompiledWasmExecutor<'a> {
	fn read_shared_object(&self, code_hash: &H256) -> Result<Arc<DlModule>> {
		let file_name = format!("{}.so", hex::encode(code_hash.as_ref()));
		let shared_object_path = self.shared_object_dir.join(file_name);
		DlModule::load(shared_object_path).map_err(Error::CompiledWasmLoad)
	}

	fn limits(&self, initial_globals_size: usize) -> Limits {
		let globals_size = ((initial_globals_size + 4096 - 1) / 4096) * 4096;
		Limits {
			globals_size,
			..Limits::default()
		}
	}

	fn call_wasm<E, R>(
		&self,
		ext: &mut E,
		method: &str,
		data: &[u8],
	) -> Result<NativeOrEncoded<R>>
		where
			E: Externalities<Blake2Hasher>,
			R: Decode + Encode + PartialEq,
	{
		let code_hash = ext
			.original_storage_hash(well_known_keys::CODE)
			.ok_or(Error::InvalidCode("`CODE` not found in storage.".into()))?;

		// lucet_wasi::hostcalls::ensure_linked();

		// TODO: cache these in memory
		let module = self.read_shared_object(&code_hash)?;

		let limits = self.limits(module.initial_globals_size());

		let region = MmapRegion::create(1, &limits)
			.map_err(Error::CompiledWasmInstantiate)?;

//		let mut ctx = WasiCtxBuilder::new()
//			.args(&args)
//			.inherit_stdio()
//			.inherit_env();
//		for (dir, guest_path) in config.preopen_dirs {
//			ctx = ctx.preopened_dir(dir, guest_path);
//		}
		let mut inst = region
			.new_instance_builder(module as Arc<dyn Module>)
			.with_embed_ctx(MyContext { ext })
			.build()
			.map_err(Error::CompiledWasmInstantiate)?;

		// TODO: figure out how to get this from shared object ideally.
		let heap_base = 0; // Self::get_heap_base(module_instance)?;

		// Construct args.
		let args = {
			let alignment = 8;
			let ceil_aligned_data_len = (data.len() + alignment - 1) / alignment * alignment;

			// Build allocator.
			let offset = {
				// TODO: Don't drop the allocator -- it's stateful.
				let mut heap = FreeingBumpHeapAllocator::new(inst.alloc(), heap_base);
				heap.allocate(ceil_aligned_data_len as u32)?
			};

			unsafe { write_to_heap(inst.alloc(), offset, data) };

			[Val::GuestPtr(offset), Val::U32(data.len() as u32)]
		};

		let return_data = match inst.run(method, &args[..]) {
			// normal termination implies 0 exit code
			Ok(RunResult::Returned(untyped_retval)) => {
				let retval: u64 = untyped_retval.into();
				let offset = retval as u32;
				let length = (retval >> 32) as usize;

				unsafe { read_from_heap(inst.alloc(), offset, length) }
			},
			// none of the WASI hostcalls use yield yet, so this shouldn't happen
			// TODO: Return an error instead of panicking
			Ok(RunResult::Yielded(_)) => panic!("module unexpectedly yielded"),
//			Err(lucet_runtime::Error::RuntimeTerminated(
//					lucet_runtime::TerminationDetails::Provided(any),
//				)) => *any
//				.downcast_ref::<lucet_wasi::host::__wasi_exitcode_t>()
//				.expect("termination yields an exitcode"),

			// TODO: Return an error instead of panicking
			Err(e) => panic!("module runtime error: {}", e),
		};

		Ok(NativeOrEncoded::Encoded(return_data))
	}
}

impl<'a> LinearMemory for &'a Alloc {
	fn len(&self) -> u32 {
		self.heap_len() as u32
	}

	fn read_i64_le(&self, offset: u32) -> Result<i64> {
		if offset % 8 != 0 {
			return Err(Error::InvalidMemoryReference);
		}
		if offset >= self.len() {
			return Err(Error::InvalidMemoryReference);
		}
		Ok(unsafe {
			let ptr = self.slot().heap.offset(offset as isize);
			i64::from_le((ptr as *const i64).read())
		})
	}

	fn write_i64_le(&self, offset: u32, value: i64) -> Result<()> {
		if offset % 8 != 0 {
			return Err(Error::InvalidMemoryReference);
		}
		if offset >= self.len() {
			return Err(Error::InvalidMemoryReference);
		}
		Ok(unsafe {
			let ptr = self.slot().heap.offset(offset as isize);
			(ptr as *mut i64).write(value.to_le())
		})
	}
}

impl<'a> CodeExecutor<Blake2Hasher> for CompiledWasmExecutor<'a> {
	type Error = Error;

	fn call<E, R, NC>(
		&self,
		ext: &mut E,
		method: &str,
		data: &[u8],
		_use_native: bool,
		_native_call: Option<NC>,
	) -> (Result<NativeOrEncoded<R>>, bool)
		where
			E: Externalities<Blake2Hasher>,
			R: Decode + Encode + PartialEq,
			NC: FnOnce() -> result::Result<R, &'static str> + UnwindSafe
	{
		let result = self.call_wasm(ext, method, data);
		(result, false)
	}
}

unsafe fn read_from_heap(alloc: &Alloc, offset: u32, length: usize) -> Vec<u8> {
	let alignment = 8;
	let ceil_aligned_data_len = length / alignment * alignment;

	let mut result = vec![0u8; ceil_aligned_data_len];

	let heap_ptr = alloc.slot().heap;
	let data_ptr = heap_ptr.offset(offset as isize) as *const u8;
	result.as_mut_ptr().copy_from_nonoverlapping(data_ptr, ceil_aligned_data_len);

	result.truncate(length);
	result
}

unsafe fn write_to_heap(alloc: &Alloc, offset: u32, data: &[u8]) {
	let alignment = 8;
	let floor_aligned_data_len = data.len() / alignment * alignment;

	let heap_ptr = alloc.slot().heap;
	let data_ptr = heap_ptr.offset(offset as isize) as *mut u8;
	data_ptr.copy_from_nonoverlapping(data.as_ptr(), floor_aligned_data_len);

	if floor_aligned_data_len != data.len() {
		let mut last_word = [0u8; 8];
		last_word.copy_from_slice(&data[floor_aligned_data_len..]);
		let last_word_ptr = data_ptr.offset(floor_aligned_data_len as isize);
		last_word_ptr.copy_from_nonoverlapping(last_word.as_ptr(), last_word.len());
	}
}
