use crate::error::{Error, Result};

use cranelift_codegen::{settings, ir, ir::types, isa};
use cranelift_entity::PrimaryMap;
use cranelift_wasm::DefinedFuncIndex;
use primitives::Blake2Hasher;
use state_machine::Externalities;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem;
use std::rc::Rc;
use target_lexicon::HOST;
use wasmtime_environ::{translate_signature, Module};
use wasmtime_jit::{ActionOutcome, Context, Features};
use wasmtime_runtime::{Export, Imports, InstanceHandle, VMContext, VMFunctionBody};

struct StateMachineContext {
	ext: &'static mut dyn Externalities<Blake2Hasher>,
	// allocator
}

struct WasmtimeExecutor;

impl WasmtimeExecutor {
	/// Call a given method in the given code.
	///
	/// Signature of this method needs to be `(I32, I32) -> I64`.
	pub fn call<E: Externalities<Blake2Hasher>>(
		&self,
		ext: &mut E,
		heap_pages: usize,
		code: &[u8],
		method: &str,
		data: &[u8],
	) -> Result<Vec<u8>> {
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

		// If a function to invoke was given, invoke it.
		let outcome = context
			.invoke(&mut instance, method, &[])
			.map_err(Error::WasmtimeAction)?;
		match outcome {
			ActionOutcome::Returned { .. } => {}
			ActionOutcome::Trapped { message } =>
				return Err(Error::WasmtimeTrap(message)),
		}

		Ok(vec![])
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

	signature!(ext_print_hex);

	let imports = Imports::none();
	let data_initializers = Vec::new();
	let signatures = PrimaryMap::new();

	let ext: &mut dyn Externalities<Blake2Hasher> = ext;

	// Use unsafe to extend lifetime. This is OK because the context only lives as long as the
	// instance.
	let host_state = unsafe {
		Box::new(StateMachineContext {
			ext: mem::transmute::<_, &'static mut dyn Externalities<Blake2Hasher>>(ext),
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
	use crate::wasmtime_utils::{AbiParam, AbiRet};

	use cranelift_codegen::ir::types::Type;
	use primitives::hexdisplay::HexDisplay;
	use wasmtime_runtime::{Export, VMContext};

	def_syscalls! {
		pub unsafe extern "C" fn ext_print_hex(
			vmctx: *mut VMContext,
			data: u32, //wasm32::uintptr_t,
			len: u32,
		) -> () {
			let memory = get_memory(&mut *vmctx);

			let start = data as usize;
			let end = start + len as usize;

			if end <= memory.len() {
				println!("{}", HexDisplay::from(&&memory[start..end]));
			}
		}
	}

	fn get_state_machine_ctx(vmctx: &mut VMContext) -> &mut StateMachineContext {
		unsafe {
			vmctx.host_state().downcast_mut::<StateMachineContext>()
				.expect("!!! no host state named StateMachineContext available")
		}
	}

	fn get_memory(vmctx: &mut VMContext) -> &mut [u8] {
		unsafe {
			// TODO: Make sure panicking is handled in an OK way.
			match vmctx.lookup_global_export("memory") {
				Some(Export::Memory { definition, vmctx: _, memory: _ }) =>
					std::slice::from_raw_parts_mut(
						(*definition).base,
						(*definition).current_length,
					),
				_ => panic!("memory export is checked by validation (probably)"),
			}
		}
	}
}
