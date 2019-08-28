use crate::wasm_env::EnvContext;

use cranelift_codegen::ir::types::{Type, I32, I64};

pub trait AbiRet {
	type Abi;
	fn convert(self) -> Self::Abi;
	fn codegen_tys() -> Vec<Type>;
}

pub trait AbiParam {
	type Abi;
	fn convert(arg: Self::Abi) -> Self;
	fn codegen_ty() -> Type;
}

macro_rules! cast32 {
    ($($i:ident)*) => ($(
        impl AbiRet for $i {
            type Abi = i32;

            fn convert(self) -> Self::Abi {
                self as i32
            }

            fn codegen_tys() -> Vec<Type> { vec![I32] }
        }

        impl AbiParam for $i {
            type Abi = i32;

            fn convert(param: i32) -> Self {
                param as $i
            }

            fn codegen_ty() -> Type { I32 }
        }
    )*)
}

macro_rules! cast64 {
    ($($i:ident)*) => ($(
        impl AbiRet for $i {
            type Abi = i64;

            fn convert(self) -> Self::Abi {
                self as i64
            }

            fn codegen_tys() -> Vec<Type> { vec![I64] }
        }

        impl AbiParam for $i {
            type Abi = i64;

            fn convert(param: i64) -> Self {
                param as $i
            }

            fn codegen_ty() -> Type { I64 }
        }
    )*)
}

cast32!(i8 i16 i32 u8 u16 u32);
cast64!(i64 u64);

impl AbiRet for () {
	type Abi = ();
	fn convert(self) {}
	fn codegen_tys() -> Vec<Type> {
		Vec::new()
	}
}

#[macro_export]
macro_rules! def_syscalls {
    ($($name:ident(&$ctx:ident $(, $arg:ident: $ty:ty)* $(,)?) -> Result<$ret:ty> {
        $($body:tt)*
    })*) => ($(
        pub mod $name {
            use super::*;

            /// Returns the codegen types of all the parameters to the shim
            /// generated
            pub fn params() -> Vec<Type> {
                vec![$(<$ty as AbiParam>::codegen_ty()),*]
            }

            /// Returns the codegen types of all the results of the shim
            /// generated
            pub fn results() -> Vec<Type> {
                <$ret as AbiRet>::codegen_tys()
            }

            /// The actual function pointer to the shim for a syscall.
            ///
            /// NB: ideally we'd expose `shim` below, but it seems like there's
            /// a compiler bug which prvents that from being cast to a `usize`.
            pub static SHIM: unsafe extern "C" fn(
                *mut VMContext,
                $(<$ty as AbiParam>::Abi),*
            ) -> <$ret as AbiRet>::Abi = shim;

            unsafe extern "C" fn shim(
                vmctx: *mut VMContext,
                $($arg: <$ty as AbiParam>::Abi,)*
            ) -> <$ret as AbiRet>::Abi {
            	let $ctx = EnvContext::new(vmctx)
            		.expect("must be able to construct EnvContext from valid *mut VMContext");
                let r = super::$name($ctx, $(<$ty as AbiParam>::convert($arg),)*).unwrap();
                <$ret as AbiRet>::convert(r)
            }
        }

        pub unsafe fn $name(mut $ctx: EnvContext, $($arg: $ty,)*) -> Result<$ret> {
            $($body)*
        }
    )*)
}
// Maybe don't need  the extern "C" on the outer func?
