//! RPC interface for the transaction payment module.

use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::sync::Arc;
use node_template_runtime_api::NodeTemplateApi as NodeTemplateRuntimeApi;

#[rpc]
pub trait NodeTemplateRpc<BlockHash> {
	#[rpc(name = "templateModule_getDataCommand")]
	fn get_data_command(&self, at: Option<BlockHash>) -> Result<u32>;
}

/// A struct that implements the `NodeTemplateApi`.
pub struct NodeTemplate<C, M> {
	// If you have more generics, no need to NodeTemplate<C, M, N, P, ...>
	// just use a tuple like NodeTemplate<C, (M, N, P, ...)>
	client: Arc<C>,
	_marker: std::marker::PhantomData<M>,
}

impl<C, M> NodeTemplate<C, M> {
	/// Create new `NodeTemplate` instance with the given reference to the client.
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: Default::default(),
		}
	}
}

impl<C, Block> NodeTemplateRpc<<Block as BlockT>::Hash> for NodeTemplate<C, Block>
where
	Block: BlockT,
	C: Send + Sync + 'static,
	C: ProvideRuntimeApi<Block>,
	C: HeaderBackend<Block>,
	C::Api: NodeTemplateRuntimeApi<Block>,
{
	fn get_data_command(&self, at: Option<<Block as BlockT>::Hash>) -> Result<Vec<DataCommand>> {
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

		let runtime_api_result = api.get_data_command(&at);
		runtime_api_result.map_err(|e| RpcError {
			code: ErrorCode::ServerError(9876), // No real reason for this value
			message: "Something wrong".into(),
			data: Some(format!("{:?}", e).into()),
		})
	}
}
