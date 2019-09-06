use crate::sandbox::InstantiationError;
use wasmtime_runtime::VMCallerCheckedAnyfunc;

pub fn instantiate(
	// supervisor_externals: &mut FE,
	dispatch_thunk: &VMCallerCheckedAnyfunc,
	wasm: &[u8],
	raw_env_def: &[u8],
	state: u32,
) -> std::result::Result<u32, InstantiationError> {
	let (imports, guest_to_supervisor_mapping) =
		decode_environment_definition(raw_env_def, &supervisor_externals.store().memories)?;

	let module = Module::from_buffer(wasm).map_err(|_| InstantiationError::ModuleDecoding)?;
	let instance = ModuleInstance::new(&module, &imports).map_err(|_| InstantiationError::Instantiation)?;

	let sandbox_instance = Rc::new(SandboxInstance {
		// In general, it's not a very good idea to use `.not_started_instance()` for anything
		// but for extracting memory and tables. But in this particular case, we are extracting
		// for the purpose of running `start` function which should be ok.
		instance: instance.not_started_instance().clone(),
		dispatch_thunk,
		guest_to_supervisor_mapping,
	});

	with_guest_externals(
		supervisor_externals,
		&sandbox_instance,
		state,
		|guest_externals| {
			instance
				.run_start(guest_externals)
				.map_err(|_| InstantiationError::StartTrapped)
		},
	)?;

	// At last, register the instance.
	let instance_idx = supervisor_externals
		.store_mut()
		.register_sandbox_instance(sandbox_instance);
	Ok(instance_idx)
}
