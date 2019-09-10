use crate::allocator::OtherAllocator;
use crate::error::{Error, Result};
use crate::sandbox;

use byteorder::{ByteOrder, LittleEndian};
use cranelift_codegen::{ir, ir::types};
use primitives::{Blake2Hasher, hexdisplay::HexDisplay};
use state_machine::Externalities;
use std::borrow::Cow;
use std::cmp;
use std::collections::HashMap;
use std::mem::size_of;
use wasmtime_runtime::{
	wasmtime_call_trampoline,
	Export, VMContext, InstanceHandle, VMCallerCheckedAnyfunc, VMFunctionBody,
};
use wasmi::{RuntimeValue, ValueType};
use wasmtime_jit::Compiler;
use cranelift_codegen::isa::CallConv;
use std::ptr;
use std::sync::Arc;
use cranelift_codegen::ir::ArgumentPurpose;

pub type Wasm32Ptr = u32;
pub type Wasm32Size = u32;

pub struct StateMachineContext {
	pub ext: &'static mut dyn Externalities<Blake2Hasher>,
	pub error: Option<Error>,
	pub allocator: OtherAllocator,
	pub hash_lookup: HashMap<Vec<u8>, Vec<u8>>,
	pub sandbox_store: sandbox::Store<*const VMCallerCheckedAnyfunc>,
	pub compiler: &'static mut Compiler,
}

pub struct EnvContext<'a> {
	pub vmctx: *mut VMContext,
	pub ext: &'a mut dyn Externalities<Blake2Hasher>,
	pub error: &'a mut Option<Error>,
	pub memory: EnvMemory<'a>,
	pub formatter: EnvFormatter<'a>,
	pub indirect_table: &'a [VMCallerCheckedAnyfunc],
	pub sandbox_store: &'a mut sandbox::Store<*const VMCallerCheckedAnyfunc>,
	pub compiler: &'a mut Compiler,
}

pub struct EnvMemory<'a> {
	mem: &'a mut [u8],
	allocator: &'a mut OtherAllocator,
	heap_base: Wasm32Ptr,
}

pub struct EnvFormatter<'a> {
	hash_lookup: &'a mut HashMap<Vec<u8>, Vec<u8>>,
}

impl<'a> EnvContext<'a> {
	pub unsafe fn new(vmctx: *mut VMContext) -> Result<Self> {
		let mem = match (*vmctx).lookup_global_export("memory") {
			Some(Export::Memory { definition, vmctx: _, memory }) =>
				std::slice::from_raw_parts_mut(
					(*definition).base,
					(*definition).current_length,
				),
			_ => return Err(Error::InvalidWasmContext),
		};
		let state = (*vmctx).host_state().downcast_mut::<Option<StateMachineContext>>()
			.and_then(|maybe_ctx| maybe_ctx.as_mut())
			.ok_or_else(|| Error::InvalidWasmContext)?;
		let heap_base = match (*vmctx).lookup_global_export("__heap_base") {
			Some(Export::Global { definition, vmctx: _, global: _ }) =>
				*(*definition).as_u32(),
			_ => return Err(Error::HeapBaseNotFoundOrInvalid),
		};
		let indirect_table = match (*vmctx).lookup_global_export("__indirect_function_table") {
			Some(Export::Table { definition, vmctx: _, table: _ }) =>
				std::slice::from_raw_parts(
					(*definition).base as *const VMCallerCheckedAnyfunc,
					(*definition).current_elements,
				),
			_ => return Err(Error::IndirectTableNotFoundOrInvalid),
		};
		let memory = EnvMemory {
			mem,
			allocator: &mut state.allocator,
			heap_base,
		};
		let formatter = EnvFormatter {
			hash_lookup: &mut state.hash_lookup,
		};
		Ok(EnvContext {
			vmctx,
			ext: state.ext,
			error: &mut state.error,
			memory,
			formatter,
			indirect_table,
			sandbox_store: &mut state.sandbox_store,
			compiler: state.compiler,
		})
	}

//	pub fn from_instance(instance: InstanceHandle) -> Result<Self> {
//		match instance.lookup("memory") {
//			Some(Export::Memory { definition, vmctx: _, memory: _ }) => unsafe {
//				std::slice::from_raw_parts_mut(
//					(*definition).base,
//					(*definition).current_length,
//				)
//			},
//			_ => return Err(Error::InvalidWasmContext),
//		}
//		Ok(EnvContext {
//			ext: state.ext,
//		})
//	}
}

impl<'a> EnvMemory<'a> {
	pub fn read(&self, ptr: Wasm32Ptr, len: Wasm32Size) -> Result<&[u8]> {
		let start = ptr as usize;
		let end = (ptr + len) as usize;
		if end > self.mem.len() {
			return Err(Error::InvalidMemoryReference);
		}
		Ok(&self.mem[start..end])
	}

	pub fn read_into(&self, ptr: Wasm32Ptr, buffer: &mut [u8]) -> Result<()> {
		let start = ptr as usize;
		let end = start + buffer.len();
		if end > self.mem.len() {
			return Err(Error::InvalidMemoryReference);
		}
		buffer.copy_from_slice(&self.mem[start..end]);
		Ok(())
	}

	pub fn write(&mut self, ptr: Wasm32Ptr, val: &[u8]) -> Result<()> {
		let start = ptr as usize;
		let end = start + val.len();
		if end > self.mem.len() {
			return Err(Error::InvalidMemoryReference);
		}
		self.mem[start..end].copy_from_slice(val);
		Ok(())
	}

	pub fn read_u32(&self, ptr: Wasm32Ptr) -> Result<u32> {
		let bytes = self.read(ptr, size_of::<u32>() as Wasm32Size)?;
		Ok(LittleEndian::read_u32(bytes))
	}

	pub fn write_u32(&mut self, ptr: Wasm32Ptr, val: u32) -> Result<()> {
		let start = ptr as usize;
		let end = start + size_of::<u32>();
		if end > self.mem.len() {
			return Err(Error::InvalidMemoryReference);
		}
		LittleEndian::write_u32(&mut self.mem[start..end], val);
		Ok(())
	}

	pub fn allocate(&mut self, size: Wasm32Size) -> Result<Wasm32Ptr> {
		let heap = &mut self.mem[(self.heap_base as usize)..];

		let offset = self.allocator.allocate(heap, size)?;
		self.heap_base.checked_add(offset)
			.ok_or(Error::Allocator("allocator returned invalid offset"))
	}

	pub fn deallocate(&mut self, ptr: Wasm32Ptr) -> Result<()> {
		let heap = &mut self.mem[(self.heap_base as usize)..];

		let offset = ptr.checked_sub(self.heap_base)
			.ok_or(Error::InvalidMemoryReference)?;
		self.allocator.deallocate(heap, offset)
	}
}

impl<'a> EnvFormatter<'a> {
	pub fn key(&self, key: &[u8]) -> String {
		if let Some(preimage) = self.hash_lookup.get(&key.to_vec()) {
			format!("%{}", primitives::hexdisplay::ascii_format(&preimage))
		} else {
			format!(" {}", primitives::hexdisplay::ascii_format(key))
		}
	}

	pub fn value(&self, maybe_value: &Option<Vec<u8>>) -> Cow<str> {
		if let Some(ref b) = *maybe_value {
			format!("{}", HexDisplay::from(b)).into()
		} else {
			"<empty>".into()
		}
	}

	// TODO: This is all fucked up. Should at least make the hash fuction part of the key.
	pub fn record_hash_preimage(&mut self, key: Vec<u8>, value: Vec<u8>) {
		self.hash_lookup.insert(key, value);
	}
}

impl<'a> sandbox::SandboxCapabilities for EnvContext<'a> {
	type FunctionRef = *const VMCallerCheckedAnyfunc;

	fn store(&self) -> &sandbox::Store<Self::FunctionRef> {
		&self.sandbox_store
	}

	fn store_mut(&mut self) -> &mut sandbox::Store<Self::FunctionRef> {
		&mut self.sandbox_store
	}

	fn allocate(&mut self, len: u32) -> Result<u32> {
		self.memory.allocate(len as Wasm32Size)
	}

	fn deallocate(&mut self, ptr: u32) -> Result<()> {
		self.memory.deallocate(ptr as Wasm32Ptr)
	}

	fn write_memory(&mut self, ptr: u32, data: &[u8]) -> Result<()> {
		self.memory.write(ptr as Wasm32Ptr, data)
	}

	fn read_memory(&self, ptr: u32, len: u32) -> Result<Vec<u8>> {
		self.memory.read(ptr as Wasm32Ptr, len as Wasm32Size)
			.map(|data| data.to_vec())
	}

	fn invoke(
		&mut self,
		dispatch_thunk: Self::FunctionRef,
		invoke_args_ptr: Wasm32Ptr,
		invoke_args_len: Wasm32Size,
		state: Wasm32Ptr,
		func_idx: usize,
	) -> Result<i64>
	{
		let value_size = size_of::<u64>();
		let (signature, mut values_vec) = generate_signature_and_args(
			&[
				RuntimeValue::I32(invoke_args_ptr as i32),
				RuntimeValue::I32(invoke_args_len as i32),
				RuntimeValue::I32(state as i32),
				RuntimeValue::I32(func_idx as i32),
			],
			&[ValueType::I64],
			self.compiler.frontend_config().default_call_conv,
		);

		let func_ptr = unsafe { (*dispatch_thunk).func_ptr };
		let vmctx = unsafe { (*dispatch_thunk).vmctx };

		// Get the trampoline to call for this function.
		let exec_code_buf = self.compiler
			.get_published_trampoline(func_ptr, &signature, value_size)
			.map_err(|e| Error::WasmtimeSetup(Arc::new(e)))?;

		// Call the trampoline.
		if let Err(message) = unsafe {
			wasmtime_call_trampoline(
				vmctx,
				exec_code_buf,
				values_vec.as_mut_ptr() as *mut u8,
			)
		} {
			return Err(Error::WasmtimeTrap(message));
		}

		// Load the return value out of `values_vec`.
		Ok(unsafe { ptr::read(values_vec.as_ptr() as *const i64) })
	}
}

fn generate_signature_and_args(
	args: &[RuntimeValue],
	result_types: &[ValueType],
	call_conv: CallConv,
) -> (ir::Signature, Vec<u64>)
{
	let value_size = size_of::<u64>();
	let mut values_vec: Vec<u64> = vec![0; cmp::max(args.len(), result_types.len())];
	let mut signature = ir::Signature::new(call_conv);

	// let pointer_type = isa.pointer_type();
	signature.params.push(ir::AbiParam::special(types::I64, ArgumentPurpose::VMContext));

	// Store the argument values into `values_vec`.
	for (index, arg) in args.iter().enumerate() {
		match arg {
			RuntimeValue::I32(_) => signature.params.push(ir::AbiParam::new(types::I32)),
			RuntimeValue::I64(_) => signature.params.push(ir::AbiParam::new(types::I64)),
			RuntimeValue::F32(_) => signature.params.push(ir::AbiParam::new(types::F32)),
			RuntimeValue::F64(_) => signature.params.push(ir::AbiParam::new(types::F64)),
		}

		unsafe {
			let ptr = values_vec.as_mut_ptr().add(index);

			match arg {
				RuntimeValue::I32(x) => ptr::write(ptr as *mut i32, *x),
				RuntimeValue::I64(x) => ptr::write(ptr as *mut i64, *x),
				RuntimeValue::F32(x) => ptr::write(ptr as *mut u32, x.to_bits()),
				RuntimeValue::F64(x) => ptr::write(ptr as *mut u64, x.to_bits()),
			}
		}
	}

	signature.returns = result_types.iter()
		.map(|result_type| match result_type {
			ValueType::I32 => types::I32,
			ValueType::I64 => types::I64,
			ValueType::F32 => types::F32,
			ValueType::F64 => types::F64,
		})
		.map(ir::AbiParam::new)
		.collect();

	(signature, values_vec)
}
