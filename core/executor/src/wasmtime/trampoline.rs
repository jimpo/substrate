use cranelift_codegen::{Context, binemit, ir, isa};
use cranelift_codegen::ir::{StackSlotData, StackSlotKind, TrapCode};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use wasmtime_runtime::{VMContext, VMFunctionBody};
use wasm_interface::{HostFunctions, Function, Value, ValueType};
use std::{cmp, ptr};

use crate::error::{Error, Result};
use crate::wasmtime::code_memory::CodeMemory;
use crate::wasmtime::function_executor::{FunctionExecutorState, FunctionExecutor};
use crate::host_interface::SubstrateExternals;

pub struct TrampolineState {
	externals: &'static [&'static dyn Function],
	trap: Option<String>,
	executor_state: Option<FunctionExecutorState<'static>>,
	// The code memory must be kept around on the state to prevent it from being dropped.
	#[allow(dead_code)]
	code_memory: CodeMemory,
}

impl TrampolineState {
	pub fn new<HF: HostFunctions>(code_memory: CodeMemory) -> Self {
		TrampolineState {
			externals: HF::functions(),
			trap: None,
			executor_state: None,
			code_memory,
		}
	}
}

unsafe extern "C" fn stub_fn(vmctx: *mut VMContext, func_index: u32, values_vec: *mut i64) -> u32 {
	if let Some(state) = (*vmctx).host_state().downcast_mut::<TrampolineState>() {
		match stub_fn_delegate(
			vmctx: *mut VMContext,
			state.externals,
			call_id,
			&mut state.executor_state,
			values_vec
		) {
			Ok(()) => 0,
			Err(err) => {
				state.trap = Some(err);
				1
			}
		}
	} else {
		// Well, we can't even set an error message, so we'll just exit without one.
		1
	}
}

unsafe fn stub_fn_delegate(
	vmctx: *mut VMContext,
	externals: &[&dyn Function],
	func_index: u32,
	executor_state: &mut FunctionExecutorState,
	values_vec: *mut i64,
) -> Result<()>
{
	let func = externals.get(func_index)
		.ok_or_else(|| format!("call to undefined external function with index {}", func_index))?;

	let mut context = FunctionExecutor::new(vmctx, executor_state)?;

	let signature = func.signature();
	let mut args = signature.args.iter()
		.enumerate()
		.map(|(i, param)| read_value_from(values_vec.offset(i as isize - 1), param.value_type));

	let return_val = func.execute(&mut context, &mut args)?;
	if let Some(val) = return_val {
		write_value_to(values_vec, return_val);
	}
	Ok(())
}

/// Create a trampoline for invoking a host function.
pub fn make_trampoline(
	isa: &dyn isa::TargetIsa,
	code_memory: &mut CodeMemory,
	fn_builder_ctx: &mut FunctionBuilderContext,
	call_id: u32,
	signature: &ir::Signature,
) -> *const VMFunctionBody {
	// Mostly reverse copy of the similar method from wasmtime's
	// wasmtime-jit/src/compiler.rs.
	let pointer_type = isa.pointer_type();
	let mut stub_sig = ir::Signature::new(isa.frontend_config().default_call_conv);

	// Add the `vmctx` parameter.
	stub_sig.params.push(ir::AbiParam::special(
		pointer_type,
		ir::ArgumentPurpose::VMContext,
	));

	// Add the `call_id` parameter.
	stub_sig.params.push(ir::AbiParam::new(types::I32));

	// Add the `values_vec` parameter.
	stub_sig.params.push(ir::AbiParam::new(pointer_type));

	// Add error/trap return.
	stub_sig.returns.push(ir::AbiParam::new(types::I32));

	let values_vec_len = 8 * cmp::max(signature.params.len() - 1, signature.returns.len()) as u32;

	let mut context = Context::new();
	context.func =
		ir::Function::with_name_signature(ir::ExternalName::user(0, 0), signature.clone());

	let ss = context.func.create_stack_slot(StackSlotData::new(
		StackSlotKind::ExplicitSlot,
		values_vec_len,
	));
	let value_size = 8;

	{
		let mut builder = FunctionBuilder::new(&mut context.func, fn_builder_ctx);
		let block0 = builder.create_ebb();

		builder.append_ebb_params_for_function_params(block0);
		builder.switch_to_block(block0);
		builder.seal_block(block0);

		let values_vec_ptr_val = builder.ins().stack_addr(pointer_type, ss, 0);
		let mflags = ir::MemFlags::trusted();
		for i in 1..signature.params.len() {
			if i == 0 {
				continue;
			}

			let val = builder.func.dfg.ebb_params(block0)[i];
			builder.ins().store(
				mflags,
				val,
				values_vec_ptr_val,
				((i - 1) * value_size) as i32,
			);
		}

		let vmctx_ptr_val = builder.func.dfg.ebb_params(block0)[0];
		let call_id_val = builder.ins().iconst(types::I32, call_id as i64);

		let callee_args = vec![vmctx_ptr_val, call_id_val, values_vec_ptr_val];

		let new_sig = builder.import_signature(stub_sig.clone());

		let callee_value = builder
			.ins()
			.iconst(pointer_type, stub_fn as *const VMFunctionBody as i64);
		let call = builder
			.ins()
			.call_indirect(new_sig, callee_value, &callee_args);

		let call_result = builder.func.dfg.inst_results(call)[0];
		builder.ins().trapnz(call_result, TrapCode::User(0));

		let mflags = ir::MemFlags::trusted();
		let mut results = Vec::new();
		for (i, r) in signature.returns.iter().enumerate() {
			let load = builder.ins().load(
				r.value_type,
				mflags,
				values_vec_ptr_val,
				(i * value_size) as i32,
			);
			results.push(load);
		}
		builder.ins().return_(&results);
		builder.finalize()
	}

	let mut code_buf: Vec<u8> = Vec::new();
	let mut reloc_sink = RelocSink {};
	let mut trap_sink = binemit::NullTrapSink {};
	let mut stackmap_sink = binemit::NullStackmapSink {};
	context
		.compile_and_emit(
			isa,
			&mut code_buf,
			&mut reloc_sink,
			&mut trap_sink,
			&mut stackmap_sink,
		)
		.expect("compile_and_emit");

	code_memory
		.allocate_copy_of_byte_slice(&code_buf)
		.expect("allocate_copy_of_byte_slice")
		.as_ptr()
}

/// We don't expect trampoline compilation to produce any relocations, so
/// this `RelocSink` just asserts that it doesn't recieve any.
struct RelocSink {}

impl binemit::RelocSink for RelocSink {
	fn reloc_ebb(
		&mut self,
		_offset: binemit::CodeOffset,
		_reloc: binemit::Reloc,
		_ebb_offset: binemit::CodeOffset,
	) {
		panic!("trampoline compilation should not produce ebb relocs");
	}
	fn reloc_external(
		&mut self,
		_offset: binemit::CodeOffset,
		_reloc: binemit::Reloc,
		_name: &ir::ExternalName,
		_addend: binemit::Addend,
	) {
		panic!("trampoline compilation should not produce external symbol relocs");
	}
	fn reloc_jt(
		&mut self,
		_offset: binemit::CodeOffset,
		_reloc: binemit::Reloc,
		_jt: ir::JumpTable,
	) {
		panic!("trampoline compilation should not produce jump table relocs");
	}
}

unsafe fn write_value_to(p: *mut i64, val: Value) {
	match val {
		Value::I32(i) => ptr::write(p as *mut i32, *i),
		Value::I64(i) => ptr::write(p as *mut i64, *i),
		Value::F32(u) => ptr::write(p as *mut u32, *u),
		Value::F64(u) => ptr::write(p as *mut u64, *u),
	}
}

unsafe fn read_value_from(p: *const i64, ty: ValueType) -> Value {
	match ty {
		ValueType::I32 => Value::I32(ptr::read(p as *const i32)),
		ValueType::I64 => Value::I64(ptr::read(p as *const i64)),
		ValueType::F32 => Value::F32(ptr::read(p as *const u32)),
		ValueType::F64 => Value::F64(ptr::read(p as *const u64)),
	}
}
