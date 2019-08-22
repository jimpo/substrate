use crate::error::{Error, Result};

use cranelift_codegen::settings;
use cranelift_entity::PrimaryMap;
use cranelift_wasm::DefinedFuncIndex;
use primitives::Blake2Hasher;
use state_machine::Externalities;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem;
use std::rc::Rc;
use wasmtime_environ::{translate_signature, Module};
use wasmtime_jit::{ActionOutcome, Context, Features};
use wasmtime_runtime::{Imports, InstanceHandle, VMFunctionBody};

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

fn instantiate_env_module<E: Externalities<Blake2Hasher>>(
	// prefix: &str,
	global_exports: Rc<RefCell<HashMap<String, Option<wasmtime_runtime::Export>>>>,
	ext: &mut E,
	// preopened_dirs: &[(String, File)],
	// argv: &[String],
	// environ: &[(String, String)],
) -> Result<InstanceHandle> {
	// let pointer_type = types::Type::triple_pointer_type(&HOST);
	let mut module = Module::new();
	let mut finished_functions: PrimaryMap<DefinedFuncIndex, *const VMFunctionBody> =
		PrimaryMap::new();
	// let call_conv = isa::CallConv::triple_default(&HOST);

//	macro_rules! signature {
//        ($name:ident) => {{
//            let sig = module.signatures.push(translate_signature(
//                ir::Signature {
//                    params: syscalls::$name::params()
//                        .into_iter()
//                        .map(ir::AbiParam::new)
//                        .collect(),
//                    returns: syscalls::$name::results()
//                        .into_iter()
//                        .map(ir::AbiParam::new)
//                        .collect(),
//                    call_conv,
//                },
//                pointer_type,
//            ));
//            let func = module.functions.push(sig);
//            module.exports.insert(
//                prefix.to_owned() + stringify!($name),
//                Export::Function(func),
//            );
//            finished_functions.push(syscalls::$name::SHIM as *const VMFunctionBody);
//        }};
//    }
//
//	signature!(args_get);

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

}
