use crate::allocator::OtherAllocator;
use crate::error::{Error, Result};

use byteorder::{ByteOrder, LittleEndian};
use primitives::{Blake2Hasher, hexdisplay::HexDisplay};
use state_machine::Externalities;
use std::borrow::Cow;
use std::collections::HashMap;
use std::mem::size_of;
use wasmtime_runtime::{Export, VMContext, InstanceHandle};

pub type Wasm32Ptr = u32;
pub type Wasm32Size = u32;

pub struct StateMachineContext {
	pub ext: &'static mut dyn Externalities<Blake2Hasher>,
	pub allocator: OtherAllocator,
	pub hash_lookup: HashMap<Vec<u8>, Vec<u8>>,
}

pub struct EnvContext<'a> {
	pub ext: &'a mut dyn Externalities<Blake2Hasher>,
	pub memory: EnvMemory<'a>,
	pub formatter: EnvFormatter<'a>,
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
		let memory = EnvMemory {
			mem,
			allocator: &mut state.allocator,
			heap_base,
		};
		let formatter = EnvFormatter {
			hash_lookup: &mut state.hash_lookup,
		};
		Ok(EnvContext {
			ext: state.ext,
			memory,
			formatter,
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