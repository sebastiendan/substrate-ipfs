#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_mut_passed)]

// Here we declare the runtime API. It is implemented in the `impl` block in
// runtime amalgamator file (the `runtime/src/lib.rs`)
sp_api::decl_runtime_apis! {
	pub trait NodeTemplateApi {
		fn get_data_command() -> u32;
	}
}