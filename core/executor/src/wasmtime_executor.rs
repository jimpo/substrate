// Copyright 2019 Parity Technologies (UK) Ltd.
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

use crate::allocator::FreeingBumpHeapAllocator;
use crate::error::{Error, Result};
use crate::wasm_externals::SubstrateExternals;
use crate::sandbox;

use cranelift_codegen::ir::types;
use cranelift_codegen::{ir, isa};
use cranelift_entity::PrimaryMap;
use cranelift_wasm::{DefinedFuncIndex, TableIndex};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use target_lexicon::HOST;
use wasm_interface::{Signature, ValueType};
use wasmtime_jit::{CompiledModule, Context, Features, SetupError};
use wasmtime_environ::{translate_signature, Module};
use wasmtime_runtime::{Export, Imports, InstanceHandle, VMFunctionBody};

struct ExecutorState {
	sandbox_store: sandbox::Store<TableIndex>,
	heap: FreeingBumpHeapAllocator,
}

pub fn create_compiled_unit(code: &[u8])
	-> std::result::Result<(CompiledModule, Context), SetupError>
{
	let isa_builder = cranelift_native::builder().unwrap_or_else(|reason| {
		panic!("host machine is not a supported target: {}", reason);
	});
	let mut flag_builder = cranelift_codegen::settings::builder();
	let mut features = Features::default();

	let isa = isa_builder.finish(settings::Flags::new(flag_builder));
	let mut context = Context::with_isa(isa).with_features(features);

	// Enable/disable producing of debug info.
	context.set_debug_info(false);

	let global_exports = context.get_global_exports();

	let env_module = instantiate_env_module(global_exports)?;
	context.name_instance("env".to_owned(), env_module);

	// Compile and instantiating a wasm module.
	let module = context.compile(&code)?;
	Ok((module, context))
}

/// The implementation is based on wasmtime_wasi::instantiate_wasi.
fn instantiate_env_module(global_exports: Rc<RefCell<HashMap<String, Option<Export>>>>)
	-> std::result::Result<InstanceHandle, SetupError>
{
	let pointer_type = types::Type::triple_pointer_type(&HOST);
	let mut module = Module::new();
	let mut finished_functions = <PrimaryMap<DefinedFuncIndex, *const VMFunctionBody>>::new();
	let call_conv = isa::CallConv::triple_default(&HOST);

	for function in SubstrateExternals::functions().iter() {
		let sig = module.signatures.push(
			translate_signature(
				cranelift_ir_signature(function.signature(), &call_conv),
				pointer_type
			)
		);
		let func_index = module.functions.push(sig);
		module.exports.insert(function.name(), wasmtime_environ::Export::Function(func_index));
		finished_functions.push(function::SHIM as *const VMFunctionBody);
	}

	let imports = Imports::none();
	let data_initializers = Vec::new();
	let signatures = PrimaryMap::new();
	let host_state = <Box<Option<ExecutorState>>>::new(None);

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
	result.map_err(|e| SetupError::Instantiate(e))
}

/// Convert a wasm_interface Signature into a cranelift_codegen Signature.
fn cranelift_ir_signature(signature: Signature, call_conv: &isa::CallConv) -> ir::Signature {
	ir::Signature {
		params: signature.args.iter()
			.map(cranelift_ir_type)
			.map(ir::AbiParam::new)
			.collect(),
		returns: signature.return_value.iter()
			.map(cranelift_ir_type)
			.map(ir::AbiParam::new)
			.collect(),
		call_conv: call_conv.clone(),
	}
}

/// Convert a wasm_interface ValueType into a cranelift_codegen Type.
fn cranelift_ir_type(value_type: ValueType) -> types::Type {
	match value_type {
		ValueType::I32 => types::I32,
		ValueType::I64 => types::I64,
		ValueType::F32 => types::F32,
		ValueType::F64 => types::F64,
	}
}
