use crate::allocator::FreeingBumpHeapAllocator;
use crate::error::{Error, Result};
use crate::sandbox::{self, SandboxCapabilities, SupervisorFuncIndex};
use crate::wasmtime::util::{cranelift_ir_signature, cranelift_ir_type};

use codec::{Decode, Encode};
use cranelift_codegen::ir;
use cranelift_codegen::isa::{CallConv, TargetFrontendConfig};
use log::trace;
use primitives::sandbox as sandbox_primitives;
use std::cmp;
use std::mem::size_of;
use std::ops::Range;
use std::ptr;
use wasmtime_environ::translate_signature;
use wasmtime_jit::{Compiler, ActionError};
use wasmtime_runtime::{Export, VMCallerCheckedAnyfunc, VMContext, wasmtime_call_trampoline};
use wasm_interface::{
	FunctionContext, MemoryId, Pointer, Result as WResult, Sandbox, Signature, Value, ValueType,
	WordSize,
};

/// Wrapper type for pointer to a Wasm table entry.
///
/// The wrapper type is used to ensure that the function reference is valid as it must be unsafely
/// dereferenced from within the safe method `<FunctionExecutor as SandboxCapabilities>::invoke`.
#[derive(Clone, Copy)]
pub struct SupervisorFuncRef(*const VMCallerCheckedAnyfunc);

pub struct FunctionExecutorState {
	compiler: &'static mut Compiler,
	sandbox_store: sandbox::Store<SupervisorFuncRef>,
	heap: FreeingBumpHeapAllocator,
}

impl FunctionExecutorState {
	pub fn new(compiler: &'static mut Compiler, heap_base: u32) -> Self {
		FunctionExecutorState {
			compiler,
			sandbox_store: sandbox::Store::new(),
			heap: FreeingBumpHeapAllocator::new(heap_base),
		}
	}

	pub fn heap(&mut self) -> &mut FreeingBumpHeapAllocator {
		&mut self.heap
	}
}

pub struct FunctionExecutor<'a> {
	compiler: &'a mut Compiler,
	sandbox_store: &'a mut sandbox::Store<SupervisorFuncRef>,
	heap: &'a mut FreeingBumpHeapAllocator,
	memory: &'a mut [u8],
	table: Option<&'a [VMCallerCheckedAnyfunc]>,
}

impl<'a> FunctionExecutor<'a> {
	pub unsafe fn new(vmctx: *mut VMContext, state: &'a mut FunctionExecutorState)
		-> Result<Self>
	{
		let memory = match (*vmctx).lookup_global_export("memory") {
			Some(Export::Memory { definition, vmctx: _, memory: _ }) =>
				std::slice::from_raw_parts_mut(
					(*definition).base,
					(*definition).current_length,
				),
			_ => return Err(Error::InvalidMemoryReference),
		};
		let table = match (*vmctx).lookup_global_export("__indirect_function_table") {
			Some(Export::Table { definition, vmctx: _, table: _ }) =>
				Some(std::slice::from_raw_parts(
					(*definition).base as *const VMCallerCheckedAnyfunc,
					(*definition).current_elements as usize,
				)),
			_ => None,
		};
		Ok(FunctionExecutor {
			compiler: &mut state.compiler,
			sandbox_store: &mut state.sandbox_store,
			heap: &mut state.heap,
			memory,
			table,
		})
	}
}

impl<'a> SandboxCapabilities for FunctionExecutor<'a> {
	type SupervisorFuncRef = SupervisorFuncRef;

	fn store(&self) -> &sandbox::Store<Self::SupervisorFuncRef> {
		&self.sandbox_store
	}

	fn store_mut(&mut self) -> &mut sandbox::Store<Self::SupervisorFuncRef> {
		&mut self.sandbox_store
	}

	fn allocate(&mut self, len: WordSize) -> Result<Pointer<u8>> {
		self.heap.allocate(self.memory, len)
	}

	fn deallocate(&mut self, ptr: Pointer<u8>) -> Result<()> {
		self.heap.deallocate(self.memory, ptr)
	}

	fn write_memory(&mut self, ptr: Pointer<u8>, data: &[u8]) -> Result<()> {
		write_memory_from(self.memory, ptr, data)
	}

	fn read_memory(&self, ptr: Pointer<u8>, len: WordSize) -> Result<Vec<u8>> {
		let mut output = vec![0; len as usize];
		read_memory_into(self.memory, ptr, output.as_mut())?;
		Ok(output)
	}

	fn invoke(
		&mut self,
		dispatch_thunk: &Self::SupervisorFuncRef,
		invoke_args_ptr: Pointer<u8>,
		invoke_args_len: WordSize,
		state: u32,
		func_idx: SupervisorFuncIndex,
	) -> Result<i64>
	{
		let func_ptr = unsafe { (*dispatch_thunk.0).func_ptr };
		let vmctx = unsafe { (*dispatch_thunk.0).vmctx };

		// The following code is based on the wasmtime_jit::Context::invoke.
		let value_size = size_of::<VMInvokeArgument>();
		let (signature, mut values_vec) = generate_signature_and_args(
			&[
				Value::I32(u32::from(invoke_args_ptr) as i32),
				Value::I32(invoke_args_len as i32),
				Value::I32(state as i32),
				Value::I32(usize::from(func_idx) as i32),
			],
			Some(ValueType::I64),
			self.compiler.frontend_config(),
		);

		// Get the trampoline to call for this function.
		let exec_code_buf = self.compiler
			.get_published_trampoline(func_ptr, &signature, value_size)
			.map_err(ActionError::Setup)
			.map_err(Error::Wasmtime)?;

		// Call the trampoline.
		if let Err(message) = unsafe {
			wasmtime_call_trampoline(
				vmctx,
				exec_code_buf,
				values_vec.as_mut_ptr() as *mut u8,
			)
		} {
			return Err(Error::FunctionExecution(message));
		}

		// Load the return value out of `values_vec`.
		Ok(unsafe { ptr::read(values_vec.as_ptr() as *const i64) })
	}
}

impl<'a> FunctionContext for FunctionExecutor<'a> {
	fn read_memory_into(&self, address: Pointer<u8>, dest: &mut [u8]) -> WResult<()> {
		read_memory_into(self.memory, address, dest).map_err(|e| e.to_string())
	}

	fn write_memory(&mut self, address: Pointer<u8>, data: &[u8]) -> WResult<()> {
		write_memory_from(self.memory, address, data).map_err(|e| e.to_string())
	}

	fn allocate_memory(&mut self, size: WordSize) -> WResult<Pointer<u8>> {
		self.heap.allocate(self.memory, size).map_err(|e| e.to_string())
	}

	fn deallocate_memory(&mut self, ptr: Pointer<u8>) -> WResult<()> {
		self.heap.deallocate(self.memory, ptr).map_err(|e| e.to_string())
	}

	fn sandbox(&mut self) -> &mut dyn Sandbox {
		self
	}
}

impl<'a> Sandbox for FunctionExecutor<'a> {
	fn memory_get(
		&mut self,
		memory_id: MemoryId,
		offset: WordSize,
		buf_ptr: Pointer<u8>,
		buf_len: WordSize,
	) -> WResult<u32>
	{
		let sandboxed_memory = self.sandbox_store.memory(memory_id)
			.map_err(|e| e.to_string())?;
		sandboxed_memory.with_direct_access(|memory| {
			let len = buf_len as usize;
			let src_range = match checked_range(offset as usize, len, memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			let dst_range = match checked_range(buf_ptr.into(), len, self.memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			&mut self.memory[dst_range].copy_from_slice(&memory[src_range]);
			Ok(sandbox_primitives::ERR_OK)
		})
	}

	fn memory_set(
		&mut self,
		memory_id: MemoryId,
		offset: WordSize,
		val_ptr: Pointer<u8>,
		val_len: WordSize,
	) -> WResult<u32>
	{
		let sandboxed_memory = self.sandbox_store.memory(memory_id)
			.map_err(|e| e.to_string())?;
		sandboxed_memory.with_direct_access_mut(|memory| {
			let len = val_len as usize;
			let src_range = match checked_range(val_ptr.into(), len, self.memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			let dst_range = match checked_range(offset as usize, len, memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			&mut memory[dst_range].copy_from_slice(&self.memory[src_range]);
			Ok(sandbox_primitives::ERR_OK)
		})
	}

	fn memory_teardown(&mut self, memory_id: MemoryId)
		-> WResult<()>
	{
		self.sandbox_store.memory_teardown(memory_id).map_err(|e| e.to_string())
	}

	fn memory_new(&mut self, initial: u32, maximum: MemoryId) -> WResult<u32> {
		self.sandbox_store.new_memory(initial, maximum).map_err(|e| e.to_string())
	}

	fn invoke(
		&mut self,
		instance_id: u32,
		export_name: &str,
		args: &[u8],
		return_val: Pointer<u8>,
		return_val_len: u32,
		state: u32,
	) -> WResult<u32> {
		trace!(target: "sr-sandbox", "invoke, instance_idx={}", instance_id);

		// Deserialize arguments and convert them into wasmi types.
		let args = Vec::<sandbox_primitives::TypedValue>::decode(&mut &args[..])
			.map_err(|_| "Can't decode serialized arguments for the invocation")?
			.into_iter()
			.map(Into::into)
			.collect::<Vec<_>>();

		let instance = self.sandbox_store.instance(instance_id).map_err(|e| e.to_string())?;
		let result = instance.invoke(export_name, &args, self, state);

		match result {
			Ok(None) => Ok(sandbox_primitives::ERR_OK),
			Ok(Some(val)) => {
				// Serialize return value and write it back into the memory.
				sandbox_primitives::ReturnValue::Value(val.into()).using_encoded(|val| {
					if val.len() > return_val_len as usize {
						Err("Return value buffer is too small")?;
					}
					FunctionContext::write_memory(self, return_val, val)?;
					Ok(sandbox_primitives::ERR_OK)
				})
			}
			Err(_) => Ok(sandbox_primitives::ERR_EXECUTION),
		}
	}

	fn instance_teardown(&mut self, instance_id: u32) -> WResult<()> {
		self.sandbox_store.instance_teardown(instance_id).map_err(|e| e.to_string())
	}

	fn instance_new(&mut self, dispatch_thunk_id: u32, wasm: &[u8], raw_env_def: &[u8], state: u32)
		-> WResult<u32>
	{
		// Extract a dispatch thunk from instance's table by the specified index.
		let dispatch_thunk = {
			let table = self.table.as_ref()
				.ok_or_else(|| "Runtime doesn't have a table; sandbox is unavailable")?;
			let func_ref = table.get(dispatch_thunk_id as usize)
				.ok_or_else(|| "dispatch_thunk_idx is out of the table bounds")?;
			SupervisorFuncRef(func_ref)
		};

		let instance_idx_or_err_code =
			match sandbox::instantiate(self, dispatch_thunk, wasm, raw_env_def, state) {
				Ok(instance_idx) => instance_idx,
				Err(sandbox::InstantiationError::StartTrapped) =>
					sandbox_primitives::ERR_EXECUTION,
				Err(_) => sandbox_primitives::ERR_MODULE,
			};

		Ok(instance_idx_or_err_code as u32)
	}
}

pub fn read_memory_into(memory: &[u8], address: Pointer<u8>, dest: &mut [u8]) -> Result<()> {
	let range = checked_range(address.into(), dest.len(), memory.len())
		.ok_or_else(|| Error::Other("memory read is out of bounds".into()))?;
	dest.copy_from_slice(&memory[range]);
	Ok(())
}

pub fn write_memory_from(memory: &mut [u8], address: Pointer<u8>, data: &[u8]) -> Result<()> {
	let range = checked_range(address.into(), data.len(), memory.len())
		.ok_or_else(|| Error::Other("memory write is out of bounds".into()))?;
	&mut memory[range].copy_from_slice(data);
	Ok(())
}

fn checked_range(offset: usize, len: usize, max: usize) -> Option<Range<usize>> {
	let end = offset.checked_add(len)?;
	if end <= max {
		Some(offset..end)
	} else {
		None
	}
}

// The storage for a Wasmtime invocation argument.
#[derive(Debug, Default, Copy, Clone)]
#[repr(C, align(8))]
struct VMInvokeArgument([u8; 8]);

fn generate_signature_and_args(
	args: &[Value],
	result_type: Option<ValueType>,
	frontend_config: TargetFrontendConfig,
) -> (ir::Signature, Vec<VMInvokeArgument>)
{
	// This code is based on the wasmtime_jit::Context::invoke.

	let param_types = args.iter()
		.map(|arg| arg.value_type())
		.collect::<Vec<_>>();
	let signature = translate_signature(
		cranelift_ir_signature(
			Signature::new(param_types, result_type),
			&frontend_config.default_call_conv
		),
		frontend_config.pointer_type()
	);

	let mut values_vec = vec![
		VMInvokeArgument::default();
		cmp::max(args.len(), result_type.iter().len())
	];

	// Store the argument values into `values_vec`.
	for (index, arg) in args.iter().enumerate() {
		unsafe {
			let ptr = values_vec.as_mut_ptr().add(index);

			match arg {
				Value::I32(x) => ptr::write(ptr as *mut i32, *x),
				Value::I64(x) => ptr::write(ptr as *mut i64, *x),
				Value::F32(x) => ptr::write(ptr as *mut u32, *x),
				Value::F64(x) => ptr::write(ptr as *mut u64, *x),
			}
		}
	}

	(signature, values_vec)
}
