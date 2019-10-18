use cranelift_codegen::{ir, isa};
use wasm_interface::{Signature, ValueType};

/// Convert a wasm_interface Signature into a cranelift_codegen Signature.
pub fn cranelift_ir_signature(signature: Signature, call_conv: &isa::CallConv) -> ir::Signature {
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
pub fn cranelift_ir_type(value_type: &ValueType) -> ir::types::Type {
	match value_type {
		ValueType::I32 => ir::types::I32,
		ValueType::I64 => ir::types::I64,
		ValueType::F32 => ir::types::F32,
		ValueType::F64 => ir::types::F64,
	}
}
