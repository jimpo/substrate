// Copyright 2017-2019 Parity Technologies (UK) Ltd.
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

//! Rust executor possible errors.

use serializer;
use state_machine;
use std::sync::Arc;
use wasmi;
use wasmtime_jit::{ActionError, SetupError};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum Error {
	/// Unserializable Data
	InvalidData(serializer::Error),
	/// Trap occured during execution
	Trap(wasmi::Trap),
	/// Wasmi loading/instantiating error
	Wasmi(wasmi::Error),
	/// Error in the API. Parameter is an error message.
	ApiError(String),
	/// Method is not found
	#[display(fmt="Method not found: '{}'", _0)]
	MethodNotFound(String),
	/// Code is invalid (expected single byte)
	#[display(fmt="Invalid Code: {}", _0)]
	InvalidCode(String),
	/// Could not get runtime version.
	#[display(fmt="On-chain runtime does not specify version")]
	VersionInvalid,
	/// Externalities have failed.
	#[display(fmt="Externalities error")]
	Externalities,
	/// Invalid index.
	#[display(fmt="Invalid index provided")]
	InvalidIndex,
	/// Invalid return type.
	#[display(fmt="Invalid type returned (should be u64)")]
	InvalidReturn,
	/// Runtime failed.
	#[display(fmt="Runtime error")]
	Runtime,
	/// Invalid memory reference.
	#[display(fmt="Invalid memory reference")]
	InvalidMemoryReference,
	/// The runtime must provide a global named `__heap_base` of type i32 for specifying where the
	/// allocator is allowed to place its data.
	#[display(fmt="The runtime doesn't provide a global named `__heap_base`")]
	HeapBaseNotFoundOrInvalid,
	#[display(fmt="The runtime doesn't provide a table named `__indirect_function_table`")]
	IndirectTableNotFoundOrInvalid,
	/// The runtime WebAssembly module is not allowed to have the `start` function.
	#[display(fmt="The runtime has the `start` function")]
	RuntimeHasStartFn,
	/// Some other error occurred
	Other(&'static str),
	/// Some error occurred in the allocator
	#[display(fmt="Error in allocator: {}", _0)]
	Allocator(&'static str),
	/// The allocator run out of space.
	#[display(fmt="Allocator run out of space")]
	AllocatorOutOfSpace,
	/// Someone tried to allocate more memory than the allowed maximum per allocation.
	#[display(fmt="Requested allocation size is too large")]
	RequestedAllocationTooLarge,
//	#[display(fmt="Error loading compiled shared object for Wasm runtime: {}", _0)]
//	CompiledWasmLoad(lucet_runtime_internals::error::Error),
//	#[display(fmt="Error instantiating module for Wasm runtime: {}", _0)]
//	CompiledWasmInstantiate(lucet_runtime_internals::error::Error)
	#[display(fmt="Wasmtime action error: {}", _0)]
	WasmtimeAction(ActionError),
	#[display(fmt="Wasmtime instantiation error: {}", _0)]
	WasmtimeSetup(Arc<SetupError>),
	#[display(fmt="Wasmtime trapped: {}", _0)]
	WasmtimeTrap(String),
	#[display(fmt="Wasmtime VM context is invalid")]
	InvalidWasmContext,
	#[display(fmt="Error in env module: {}", _0)]
	EnvModule(String),
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::InvalidData(ref err) => Some(err),
			Error::Trap(ref err) => Some(err),
			Error::Wasmi(ref err) => Some(err),
			// the trait `std::error::Error` is not implemented for `lucet_runtime_internals::error::Error`
			// Error::WasmtimeAction(ref err) => Some(err),
			// Error::WasmtimeInstantiation(ref err) => Some(err),
			// Error::CompiledWasmLoad(ref err) => Some(err),
			// Error::CompiledWasmInstantiate(ref err) => Some(err),
			_ => None,
		}
	}
}

impl state_machine::Error for Error {}

impl wasmi::HostError for Error {}

impl From<&'static str> for Error {
	fn from(err: &'static str) -> Error {
		Error::Other(err)
	}
}
