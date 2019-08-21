use crate::allocator::LinearMemory;
use crate::error::{Error, Result};

use codec::{Decode, Encode};
use hex;
use lucet_runtime_internals::{
	alloc::{Alloc, Limits},
	module::{DlModule, Module},
	region::mmap::MmapRegion,
};
use primitives::{Blake2Hasher, NativeOrEncoded};
use state_machine::{CodeExecutor, Externalities};
use std::fs::File;
use std::io;
use std::panic::UnwindSafe;
use std::path::Path;
use std::result;
use std::sync::Arc;

pub struct CompiledWasmExecutor<'a> {
	shared_object_dir: &'a Path,
}

impl CompiledWasmExecutor {
	fn read_shared_object(&self, code_hash: &H256) -> Result<Arc<DlModule>, Error> {
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
}

impl<'a> LinearMemory for &'a Alloc {
	fn len(&self) -> u32 {
		self.heap_len() as u32
	}

	fn read(&self, offset: u32, target: &mut [u8]) -> Result<()> {
		unsafe {
			self.slot().heap.offset(offset as isize)
		}
		unimplemented!()
	}

	fn write(&self, offset: u32, value: &[u8]) -> Result<()> {
		unimplemented!()
	}
}

impl CodeExecutor<Blake2Hasher> for CompiledWasmExecutor {
	type Error = ();

	fn call
	<
		E: Externalities<Blake2Hasher>,
		R: Decode + Encode + PartialEq,
		NC: FnOnce() -> result::Result<R, &'static str> + UnwindSafe
	>(
		&self,
		ext: &mut E,
		method: &str,
		data: &[u8],
		use_native: bool,
		native_call: Option<NC>,
	) -> (Result<NativeOrEncoded<R>>, bool) {
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
			// .with_embed_ctx(ctx.build().expect("WASI ctx can be created"))
			.build()
			.map_err(Error::CompiledWasmInstantiate)?;

		// Construct args.

		// Build allocator.
		let heap = unsafe { inst.alloc.heap() };

		let heap_base = Self::get_heap_base(module_instance)?;
		let parameters = {
			let offset = fec.heap.allocate(data.len() as u32);
			memory.set(offset, &data)?;
			vec![I32(offset as i32), I32(data.len() as i32)]
		};

		match inst.run(method, &[]) {
			// normal termination implies 0 exit code
			Ok(RunResult::Returned(_)) => 0,
			// none of the WASI hostcalls use yield yet, so this shouldn't happen
			Ok(RunResult::Yielded(_)) => panic!("lucet-wasi unexpectedly yielded"),
			Err(lucet_runtime::Error::RuntimeTerminated(
					lucet_runtime::TerminationDetails::Provided(any),
				)) => *any
				.downcast_ref::<lucet_wasi::host::__wasi_exitcode_t>()
				.expect("termination yields an exitcode"),
			Err(e) => panic!("lucet-wasi runtime error: {}", e),
		}

		self.fallback
			.call_in_wasm_module(ext, module, method, data)
			.map(NativeOrEncoded::Encoded)
	}
}
