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

use std::{result, cell::RefCell, panic::UnwindSafe};
use crate::error::{Error, Result};
use state_machine::{CodeExecutor, Externalities};
use crate::wasmtime_executor::WasmtimeExecutor;
use crate::wasm_executor::WasmExecutor;
use runtime_version::{NativeVersion, RuntimeVersion};
use codec::{Decode, Encode};
use crate::RuntimeInfo;
use primitives::{Blake2Hasher, NativeOrEncoded};
use log::{trace, warn};
use std::convert::TryInto;

use crate::wasm_runtimes_cache::{CachedRuntime, RuntimesCache, InterpretedRuntime, JITRuntimeCache, WasmJITRuntime};
use crate::wasm_utils::WasmRuntime;

thread_local! {
	static RUNTIMES_CACHE: RefCell<RuntimesCache> = RefCell::new(RuntimesCache::new());
	static JIT_RUNTIMES_CACHE: RefCell<JITRuntimeCache> = RefCell::new(JITRuntimeCache::new());
}

fn safe_call<F, U>(f: F) -> Result<U>
	where F: UnwindSafe + FnOnce() -> U
{
	// Substrate uses custom panic hook that terminates process on panic. Disable termination for the native call.
	let _guard = panic_handler::AbortGuard::force_unwind();
	::std::panic::catch_unwind(f).map_err(|_| Error::Runtime)
}

/// Set up the externalities and safe calling environment to execute calls to a native runtime.
///
/// If the inner closure panics, it will be caught and return an error.
pub fn with_native_environment<F, U>(ext: &mut dyn Externalities<Blake2Hasher>, f: F) -> Result<U>
	where F: UnwindSafe + FnOnce() -> U
{
	::runtime_io::with_externalities(ext, move || safe_call(f))
}

/// Delegate for dispatching a CodeExecutor call to native code.
pub trait NativeExecutionDispatch: Send + Sync {
	/// Dispatch a method and input data to be executed natively.
	fn dispatch(ext: &mut dyn Externalities<Blake2Hasher>, method: &str, data: &[u8]) -> Result<Vec<u8>>;

	/// Provide native runtime version.
	fn native_version() -> NativeVersion;
}

/// A generic `CodeExecutor` implementation that uses a delegate to determine wasm code equivalence
/// and dispatch to native code when possible, falling back on `WasmExecutor` when not.
#[derive(Debug)]
pub struct NativeExecutor<D> {
	/// Dummy field to avoid the compiler complaining about us not using `D`.
	_dummy: ::std::marker::PhantomData<D>,
	/// Native runtime version info.
	native_version: NativeVersion,
	/// The number of 64KB pages to allocate for Wasm execution.
	default_heap_pages: Option<u64>,
	use_jit: bool,
}

impl<D: NativeExecutionDispatch> NativeExecutor<D> {
	/// Create new instance.
	pub fn new(default_heap_pages: Option<u64>) -> Self {
		NativeExecutor {
			_dummy: Default::default(),
			native_version: D::native_version(),
			default_heap_pages,
			use_jit: false,
		}
	}

	fn with_wasm_runtime<E, R>(
		&self,
		ext: &mut E,
		f: impl for<'a> FnOnce(Box<dyn WasmRuntime<E> + 'a>) -> Result<R>
	) -> Result<R>
		where
			E: Externalities<Blake2Hasher>,
	{
		if self.use_jit {
			with_wasm_jit_runtime(ext, self.default_heap_pages, |runtime| f(Box::new(runtime)))
		} else {
			with_wasmi_runtime(ext, self.default_heap_pages, |runtime| f(Box::new(runtime)))
		}
	}
}

impl<D: NativeExecutionDispatch> Clone for NativeExecutor<D> {
	fn clone(&self) -> Self {
		NativeExecutor {
			_dummy: Default::default(),
			native_version: D::native_version(),
			default_heap_pages: self.default_heap_pages,
			use_jit: self.use_jit,
		}
	}
}

impl<D: NativeExecutionDispatch> RuntimeInfo for NativeExecutor<D> {
	fn native_version(&self) -> &NativeVersion {
		&self.native_version
	}

	fn runtime_version<E: Externalities<Blake2Hasher>>(
		&self,
		ext: &mut E,
	) -> Option<RuntimeVersion> {
		match self.with_wasm_runtime(ext, |runtime| Ok(runtime.version())) {
			Ok(version) => version,
			Err(e) => {
				warn!(target: "executor", "Failed to fetch runtime: {:?}", e);
				None
			}
		}
	}
}

impl<D: NativeExecutionDispatch> CodeExecutor<Blake2Hasher> for NativeExecutor<D> {
	type Error = Error;

	fn call
	<
		E: Externalities<Blake2Hasher>,
		R:Decode + Encode + PartialEq,
		NC: FnOnce() -> result::Result<R, &'static str> + UnwindSafe
	>(
		&self,
		ext: &mut E,
		method: &str,
		data: &[u8],
		use_native: bool,
		native_call: Option<NC>,
	) -> (Result<NativeOrEncoded<R>>, bool){
		let mut used_native = false;
		let result = self.with_wasm_runtime(ext, |mut runtime| {
			let onchain_version = runtime.version();
			match (
				use_native,
				onchain_version
					.as_ref()
					.map_or(false, |v| v.can_call_with(&self.native_version.runtime_version)),
				native_call,
			) {
				(_, false, _) => {
					trace!(
						target: "executor",
						"Request for native execution failed (native: {}, chain: {})",
						self.native_version.runtime_version,
						onchain_version
							.as_ref()
							.map_or_else(||"<None>".into(), |v| format!("{}", v))
					);
					runtime.call(method, data).map(NativeOrEncoded::Encoded)
				}
				(false, _, _) => runtime.call(method, data).map(NativeOrEncoded::Encoded),
				(true, true, Some(call)) => {
					trace!(
						target: "executor",
						"Request for native execution with native call succeeded (native: {}, chain: {}).",
						self.native_version.runtime_version,
						onchain_version
							.as_ref()
							.map_or_else(||"<None>".into(), |v| format!("{}", v))
					);
					used_native = true;
					with_native_environment(runtime.ext(), move || (call)())
						.and_then(|r| r.map(NativeOrEncoded::Native).map_err(|s| Error::ApiError(s.to_string())))
				}
				_ => {
					trace!(
						target: "executor",
						"Request for native execution succeeded (native: {}, chain: {})",
						self.native_version.runtime_version,
						onchain_version.as_ref().map_or_else(||"<None>".into(), |v| format!("{}", v))
					);
					used_native = true;
					D::dispatch(runtime.ext(), method, data).map(NativeOrEncoded::Encoded)
				}
			}
		});
		(result, used_native)
	}
}

/// Implements a `NativeExecutionDispatch` for provided parameters.
#[macro_export]
macro_rules! native_executor_instance {
	( $pub:vis $name:ident, $dispatcher:path, $version:path $(,)?) => {
		/// A unit struct which implements `NativeExecutionDispatch` feeding in the hard-coded runtime.
		$pub struct $name;
		$crate::native_executor_instance!(IMPL $name, $dispatcher, $version);
	};
	(IMPL $name:ident, $dispatcher:path, $version:path) => {
		impl $crate::NativeExecutionDispatch for $name {
			fn dispatch(
				ext: &mut $crate::Externalities<$crate::Blake2Hasher>,
				method: &str,
				data: &[u8]
			) -> $crate::error::Result<Vec<u8>> {
				$crate::with_native_environment(ext, move || $dispatcher(method, data))?
					.ok_or_else(|| $crate::error::Error::MethodNotFound(method.to_owned()))
			}

			fn native_version() -> $crate::NativeVersion {
				$version()
			}
		}
	}
}

fn with_wasmi_runtime<E, R>(
	ext: &mut E,
	default_heap_pages: Option<u64>,
	f: impl for <'a> FnOnce(InterpretedRuntime<'a, E>) -> Result<R>,
) -> Result<R>
	where E: Externalities<Blake2Hasher>
{
	RUNTIMES_CACHE.with(|cache| {
		let mut cache = cache.borrow_mut();
		let runtime = cache.fetch_runtime(&WasmExecutor, ext, default_heap_pages)?;
		f(runtime)
	})
}

fn with_wasm_jit_runtime<E, R>(
	ext: &mut E,
	default_heap_pages: Option<u64>,
	f: impl for <'a> FnOnce(WasmJITRuntime<'a, E>) -> Result<R>,
) -> Result<R>
	where E: Externalities<Blake2Hasher>
{
	JIT_RUNTIMES_CACHE.with(|cache| {
		let mut cache = cache.borrow_mut();
		let runtime = cache.fetch_runtime(ext, default_heap_pages)?;
		f(runtime)
	})
}
