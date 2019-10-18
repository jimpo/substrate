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

use crate::error::{Error, Result, WasmError};
use crate::host_interface::SubstrateExternals;
use crate::wasm_runtime::WasmRuntime;
use crate::wasmtime::code_memory::CodeMemory;
use crate::wasmtime::function_executor::{FunctionExecutorState, write_memory_from, read_memory_into};
use crate::wasmtime::trampoline::{TrampolineState, make_trampoline};
use crate::{Externalities, RuntimeVersion};

use cranelift_codegen::ir::types;
use cranelift_codegen::isa::TargetIsa;
use cranelift_codegen::{ir, isa};
use cranelift_entity::{EntityRef, PrimaryMap};
use cranelift_frontend::FunctionBuilderContext;
use cranelift_wasm::DefinedFuncIndex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::mem;
use std::rc::Rc;
use wasm_interface::{
	Function, FunctionContext, HostFunctions, Pointer, Signature, ValueType, WordSize,
};
use wasmtime_environ::{translate_signature, Module, WASM_PAGE_SIZE};
use wasmtime_jit::{
	ActionOutcome, ActionError, CompilationStrategy, CompiledModule, Compiler, Context, Features,
	SetupError, RuntimeValue,
};
use wasmtime_runtime::{Export, Imports, InstanceHandle, VMFunctionBody};

struct WasmtimeRuntime {
	module: CompiledModule,
	context: Context,
	min_heap_pages: u32,
	heap_pages: u32,
	version: Option<RuntimeVersion>,
}

impl WasmtimeRuntime {
	fn clear_globals(&mut self) {
		let mut global_exports = self.context.get_global_exports();
		let mut global_exports = global_exports.borrow_mut();
	}
}

impl WasmRuntime for WasmtimeRuntime {
	fn update_heap_pages(&mut self, heap_pages: u64) -> bool {
		let heap_pages = match u32::try_from(heap_pages) {
			Ok(heap_pages) => heap_pages,
			Err(_) => return false,
		};
		if heap_pages < self.min_heap_pages {
			return false;
		}
		self.heap_pages = heap_pages;
		true
	}

	fn call(&mut self, ext: &mut dyn Externalities, method: &str, data: &[u8]) -> Result<Vec<u8>> {
		clear_globals(&mut *self.context.get_global_exports().borrow_mut());

		let mut instance = self.module.instantiate()
			.map_err(SetupError::Instantiate)
			.map_err(ActionError::Setup)
			.map_err(Error::Wasmtime)?;

		let args = unsafe {
			// TODO: Ideally there would be a way to set the heap pages during instantiation rather
			// that growing the memory after the fact, as this way may require an additional mmap
			// and copy. However, the wasmtime API doesn't support that at this time.
			grow_memory(&mut instance, self.heap_pages)?;

			// Initialize the function executor state.
			let executor_state = FunctionExecutorState::new(
				mem::transmute::<_, &'static mut Compiler>(self.context.compiler()),
				get_heap_base(&instance)?,
			);
			reset_host_state(&mut self.context, Some(executor_state))?;

			// Write the input data into guest memory.
			let (data_ptr, data_len) = inject_input_data(&mut self.context, &mut instance, data)?;
			[RuntimeValue::I32(u32::from(data_ptr) as i32), RuntimeValue::I32(data_len as i32)]
		};

		// Invoke the function in the runtime.
		let outcome = externalities::set_and_run_with_externalities(ext, || {
			self.context
				.invoke(&mut instance, method, &args[..])
				.map_err(Error::Wasmtime)
		})?;
		let trap_message = reset_host_state(&mut self.context, None)?;
		let (output_ptr, output_len) = match outcome {
			ActionOutcome::Returned { values } => {
				if values.len()	!= 1 {
					return Err(Error::InvalidReturn);
				}
				if let RuntimeValue::I64(val) = values[0] {
					let output_ptr = <Pointer<u8>>::new(val as u32);
					let output_len = ((val as u64) >> 32) as usize;
					(output_ptr, output_len)
				} else {
					return Err(Error::InvalidReturn);
				}
			}
			ActionOutcome::Trapped { message } =>
				return Err(Error::FunctionExecution(trap_message.unwrap_or(message))),
		};

		// Read the output data from guest memory.
		let mut output = vec![0; output_len];
		let memory = unsafe { get_memory_mut(&mut instance)? };
		read_memory_into(memory, output_ptr, &mut output);
		Ok(output)
	}

	fn version(&self) -> Option<RuntimeVersion> {
		self.version.clone()
	}
}

pub fn create_compiled_unit(code: &[u8])
	-> std::result::Result<(CompiledModule, Context), WasmError>
{
	let isa = target_isa()?;
	let mut context = Context::with_isa(isa, CompilationStrategy::Cranelift);

	// Enable/disable producing of debug info.
	context.set_debug_info(false);

	let global_exports = context.get_global_exports();

	let env_module = instantiate_env_module(global_exports)?;
	context.name_instance("env".to_owned(), env_module);

	// Compile the wasm module.
	let module = context.compile_module(&code)
		.map_err(WasmError::WasmtimeSetup)?;
	Ok((module, context))
}

/// The implementation is based on wasmtime_wasi::instantiate_wasi.
fn instantiate_env_module(global_exports: Rc<RefCell<HashMap<String, Option<Export>>>>)
	-> std::result::Result<InstanceHandle, WasmError>
{
	let isa = target_isa()?;
	let pointer_type = isa.pointer_type();
	let call_conv = isa.default_call_conv();

	let mut fn_builder_ctx = FunctionBuilderContext::new();
	let mut module = Module::new();
	let mut finished_functions = <PrimaryMap<DefinedFuncIndex, *const VMFunctionBody>>::new();
	let mut code_memory = CodeMemory::new();

	for function in SubstrateExternals::functions().iter() {
		let sig = translate_signature(
			cranelift_ir_signature(function.signature(), &call_conv),
			pointer_type
		);
		let sig_id = module.signatures.push(sig.clone());
		let func_id = module.functions.push(sig_id);
		module
			.exports
			.insert(function.name().to_string(), wasmtime_environ::Export::Function(func_id));

		let trampoline = make_trampoline(
			isa.as_ref(),
			&mut code_memory,
			&mut fn_builder_ctx,
			func_id.index() as u32,
			&sig,
		);
		finished_functions.push(trampoline);
	}

	code_memory.publish();

	let imports = Imports::none();
	let data_initializers = Vec::new();
	let signatures = PrimaryMap::new();
	let host_state = TrampolineState::new::<SubstrateExternals>(code_memory);

	let result = InstanceHandle::new(
		Rc::new(module),
		global_exports,
		finished_functions.into_boxed_slice(),
		imports,
		&data_initializers,
		signatures.into_boxed_slice(),
		None,
		Box::new(host_state),
	);
	result.map_err(|e| WasmError::WasmtimeSetup(SetupError::Instantiate(e)))
}

/// Build a new TargetIsa for the host machine.
fn target_isa() -> std::result::Result<Box<dyn TargetIsa>, WasmError> {
	let isa_builder = cranelift_native::builder()
		.map_err(WasmError::MissingCompilerSupport)?;
	let flag_builder = cranelift_codegen::settings::builder();
	Ok(isa_builder.finish(cranelift_codegen::settings::Flags::new(flag_builder)))
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
fn cranelift_ir_type(value_type: &ValueType) -> types::Type {
	match value_type {
		ValueType::I32 => types::I32,
		ValueType::I64 => types::I64,
		ValueType::F32 => types::F32,
		ValueType::F64 => types::F64,
	}
}

// Old exports get clobbered if we don't explicitly remove them first.
// TODO: open an issue on wasmtime and reference it here
fn clear_globals(global_exports: &mut HashMap<String, Option<Export>>) {
	global_exports.remove("memory");
	global_exports.remove("__heap_base");
	global_exports.remove("__indirect_function_table");
}

unsafe fn grow_memory(instance: &mut InstanceHandle, pages: u32) -> Result<()> {
	let (memory_index, current_pages) = match instance.lookup_immutable("memory") {
		Some(Export::Memory { definition, vmctx: _, memory }) => {
			let definition = &*definition;
			assert_eq!(
				memory.memory.minimum.checked_mul(WASM_PAGE_SIZE),
				Some(definition.current_length as u32)
			);
			let index = instance.memory_index(definition);
			(index, memory.memory.minimum)
		}
		_ => return Err(Error::InvalidMemoryReference),
	};
	if current_pages < pages {
		instance.memory_grow(memory_index, pages - current_pages);
	}
	Ok(())
}

fn get_host_state(context: &mut Context) -> Result<&mut TrampolineState> {
	let env_instance = context.get_instance("env")
		.map_err(|err| format!("cannot find \"env\" module: {}", err))?;
	env_instance
		.host_state()
		.downcast_mut::<TrampolineState>()
		.ok_or_else(|| "cannot get \"env\" module host state".into())
}

fn reset_host_state(context: &mut Context, executor_state: Option<FunctionExecutorState>)
	-> Result<Option<String>>
{
	let trampoline_state = get_host_state(context)?;
	trampoline_state.executor_state = executor_state;
	Ok(trampoline_state.reset_trap())
}

unsafe fn inject_input_data(
	context: &mut Context,
	instance: &mut InstanceHandle,
	data: &[u8],
) -> Result<(Pointer<u8>, WordSize)> {
	let trampoline_state = get_host_state(context)?;
	let executor_state = trampoline_state.executor_state
		.ok_or_else(|| "cannot get \"env\" module executor state")?;

	let memory = get_memory_mut(instance)?;

	let data_len = data.len() as WordSize;
	let data_ptr = executor_state.heap.allocate_memory(memory, data_len)?;
	write_memory_from(memory, data_ptr, data)?;
	Ok((data_ptr, data_len))
}

unsafe fn get_heap_base(instance: &InstanceHandle) -> Result<u32> {
	match instance.lookup_immutable("__heap_base") {
		Some(Export::Global { definition, vmctx: _, global: _ }) => unsafe {
			Ok(*(*definition).as_u32())
		}
		_ => return Err(Error::HeapBaseNotFoundOrInvalid),
	}
}

unsafe fn get_memory_mut(instance: &mut InstanceHandle) -> Result<&mut [u8]> {
	match instance.lookup("memory") {
		Some(Export::Memory { definition, vmctx: _, memory }) =>
			Ok(std::slice::from_raw_parts_mut(
				(*definition).base,
				(*definition).current_length,
			)),
		_ => Err(Error::InvalidMemoryReference),
	}
}
