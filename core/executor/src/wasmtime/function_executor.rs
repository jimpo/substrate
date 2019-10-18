use crate::allocator::FreeingBumpHeapAllocator;
use crate::error::{Error, Result};
use crate::sandbox;

use cranelift_wasm::{DefinedFuncIndex, TableIndex};
use primitives::sandbox as sandbox_primitives;
use std::ops::Range;
use wasmtime_jit::{Compiler, InstanceHandle};
use wasmtime_runtime::{Export, VMCallerCheckedAnyfunc, VMContext};
use wasm_interface::{FunctionContext, Pointer, MemoryId, WordSize, Result as WResult, Sandbox};

pub struct FunctionExecutorState {
	compiler: &'static mut Compiler,
	sandbox_store: sandbox::Store<*const VMCallerCheckedAnyfunc>,
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
}

pub struct FunctionExecutor<'a> {
	compiler: &'a mut Compiler,
	sandbox_store: &'a mut sandbox::Store<*const VMCallerCheckedAnyfunc>,
	heap: &'a mut FreeingBumpHeapAllocator,
	memory: &'a mut [u8],
	table: Option<&'a [VMCallerCheckedAnyfunc]>,
}

impl<'a> FunctionExecutor<'a> {
	pub unsafe fn new(vmctx: *mut VMContext, state: &mut FunctionExecutorState)
		-> Result<Self>
	{
		let memory = match (*vmctx).lookup_global_export("memory") {
			Some(Export::Memory { definition, vmctx: _, memory }) =>
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
					(*definition).current_elements,
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
		&self,
		memory_id: MemoryId,
		offset: WordSize,
		buf_ptr: Pointer<u8>,
		buf_len: WordSize,
	) -> WResult<u32>
	{
		let sandboxed_memory = self.sandbox_store.memory(memory_id)?;
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
		let sandboxed_memory = self.sandbox_store.memory(memory_id)?;
		sandboxed_memory.with_direct_access(|mut memory| {
			let len = val_len as usize;
			let src_range = match checked_range(val_ptr.into(), len, self.memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			let dst_range = match checked_range(offset as usize, len, memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			&mut memory[dst_range].copy_from_slice(&self.memory[dst_range]);
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
		unimplemented!()
	}

	fn instance_teardown(&mut self, instance_id: u32) -> WResult<()> {
		unimplemented!()
	}

	fn instance_new(&mut self, dispatch_thunk_id: u32, wasm: &[u8], raw_env_def: &[u8], state: u32)
		-> WResult<u32>
	{
		unimplemented!()
	}
}

pub fn read_memory_into(memory: &[u8], address: Pointer<u8>, dest: &mut [u8]) -> Result<()> {
	let range = checked_range(address.into(), dest.len(), memory.len())
		.ok_or_else(|| "memory read is out of bounds".into())?;
	dest.copy_from_slice(&memory[range]);
	Ok(())
}

pub fn write_memory_from(memory: &mut [u8], address: Pointer<u8>, data: &[u8]) -> Result<()> {
	let range = checked_range(address.into(), data.len(), memory.len())
		.ok_or_else(|| "memory write is out of bounds".into())?;
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
