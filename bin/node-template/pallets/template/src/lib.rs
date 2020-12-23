#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::{fmt, string::String};
use alt_serde::{Deserialize, Deserializer};
use base64;
use codec::{Encode, Decode};
use frame_support::{
	debug, decl_module, decl_storage, decl_event, decl_error, dispatch::DispatchResult, traits::Get,
	sp_io,
	weights::Weight,
};
use frame_system::{
	ensure_signed, 
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer,
	}
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain::http,
	transaction_validity::{
		TransactionValidity, TransactionLongevity, ValidTransaction, InvalidTransaction
	},
};
use sp_std::{str, vec::Vec};

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const HTTP_BASE_URL: &str = "http://127.0.0.1:5001/api/v0";
const BOUNDARY: &'static str = "------------------------ea3bbcf87c101592";

static TOPIC: &'static str = "topos";

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default)]
struct IPFSAddResult {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    Name: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    Hash: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    Size: Vec<u8>,
}

#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default, Debug, Clone, PartialEq)]
pub struct IPNSKey {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    Name: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    Id: Vec<u8>,
}

#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default)]
struct IPNSPublishResult {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    Name: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    Value: Vec<u8>,
}

#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default, Debug, Clone)]
struct IPNSResolveResult {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    Path: Vec<u8>,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where D: Deserializer<'de> {
    let s: &str = Deserialize::deserialize(de)?;
    Ok(s.as_bytes().to_vec())
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub trait Trait: frame_system::Trait + CreateSignedTransaction<Call<Self>> {
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	type Call: From<Call<Self>>;
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

#[derive(Encode, Decode, PartialEq)]
enum DataCommand {
    AddBytes(Vec<u8>),
    CatBytes(Vec<u8>),
}

decl_storage! {
	trait Store for Module<T: Trait> as TemplateModule {
		pub DataQueue: Vec<DataCommand>;
		pub ReceivedMessages: Vec<Vec<u8>>;
		pub IPNSKeyCurrent: IPNSKey;
		pub IPNSKeyPrev: IPNSKey;
		pub IPNSKeyExternal: IPNSKey;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		QueuedDataToAdd(AccountId),
        QueuedDataToCat(AccountId),
        CommittedToNewIPNSKey(AccountId),
        CommittedToNewExternalIPNSKey(AccountId),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		NoneValue,
		StorageOverflow,
		HttpFetchingError,
		NoIPNSKeyError,
		// Error returned when making signed transactions in off-chain worker
		NoLocalAcctForSigning,
		OffchainSignedTxError,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		// needs to be synchronized with offchain_worker actitivies
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
			DataQueue::kill();
            0
        }

		/// Add arbitrary bytes to the IPFS repository. The registered `Cid` is printed out in the
        /// logs.
        #[weight = 200_000]
        pub fn ipfs_add_bytes(origin, data: Vec<u8>) {
            let who = ensure_signed(origin)?;

            DataQueue::mutate(|queue| queue.push(DataCommand::AddBytes(data)));
            Self::deposit_event(RawEvent::QueuedDataToAdd(who));
        }

        /// Find IPFS data pointed to by the given `Cid`; if it is valid UTF-8, it is printed in the
        /// logs verbatim; otherwise, the decimal representation of the bytes is displayed instead.
        #[weight = 100_000]
        pub fn ipfs_cat_bytes(origin, cid: Vec<u8>) {
            let who = ensure_signed(origin)?;

            DataQueue::mutate(|queue| queue.push(DataCommand::CatBytes(cid)));
            Self::deposit_event(RawEvent::QueuedDataToCat(who));
		}
		
		/// Commit a new IPNS key on the chain
		#[weight = 10000]
		pub fn ipns_commit_new_key(origin, ipns_key: IPNSKey) -> DispatchResult {
			let who = ensure_signed(origin)?;
			debug::info!("About to commit a new IPNS key: ({:?}, {:?})", ipns_key, who);

			if IPNSKeyPrev::get().Name.is_empty() {
				IPNSKeyPrev::put(ipns_key.clone());
			} else {
				IPNSKeyPrev::put(IPNSKeyCurrent::get());
			}

			IPNSKeyCurrent::put(ipns_key);
            Self::deposit_event(RawEvent::CommittedToNewIPNSKey(who));
			Ok(())
		}
		
		/// Commit a new IPNS key on the chain
		#[weight = 10000]
		pub fn ipns_commit_new_external_key(origin, ipns_key: IPNSKey) -> DispatchResult {
			let who = ensure_signed(origin)?;
			debug::info!("About to commit a new external IPNS key: ({:?}, {:?})", ipns_key, who);

			IPNSKeyExternal::put(ipns_key);
            Self::deposit_event(RawEvent::CommittedToNewExternalIPNSKey(who));
			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			let key_prev = IPNSKeyPrev::get();
			let key_curr = IPNSKeyCurrent::get();
			let key_external = IPNSKeyExternal::get();
			debug::info!("IPNS KEY PREV: {} - {}", str::from_utf8(&key_prev.Name).unwrap(), str::from_utf8(&key_prev.Id).unwrap());
			debug::info!("IPNS KEY: {} - {}", str::from_utf8(&key_curr.Name).unwrap(), str::from_utf8(&key_curr.Id).unwrap());
			debug::info!("IPNS KEY EXT: {} - {}", str::from_utf8(&key_external.Name).unwrap(), str::from_utf8(&key_external.Id).unwrap());

			if let Err(e) = Self::handle_data_requests() {
				debug::error!("IPFS: Encountered an error while processing data requests: {:?}", e);
			}

			if let Err(e) = Self::handle_ipns_publish_request(block_number) {
				debug::error!("IPNS: Encountered an error while publishing a block: {:?}", e);
			}
			
			if block_number % 10.into() == 0.into() {
				if let Err(e) = Self::handle_ipns_key_request(block_number) {
					debug::error!("IPNS: Encountered an error while requesting a new key: {:?}", e);
				}
			}

			if !key_external.Id.is_empty() {
				if let Err(e) = Self::handle_ipns_resolve_request() {
					debug::error!("IPNS: Encountered an error while resolving a name: {:?}", e);
				}
			}
		}
	}
}

impl<T: Trait> Module<T> {
	fn ipfs_request_add(data: Vec<u8>) -> Result<Vec<u8>, Error<T>> {
		let url = &format!("{}/add", HTTP_BASE_URL);
		let mut body: Vec<u8> = Vec::new();
		body.extend_from_slice(format!("--{}\r\n", BOUNDARY).as_bytes());
		body.extend_from_slice("Content-Disposition: form-data; name=\"file\"; filename=\"file.txt\"\r\n".as_bytes());
		body.extend_from_slice("Content-Type: application/octet-stream\r\n".as_bytes());
		body.extend_from_slice("\r\n".as_bytes());
		body.extend_from_slice(&data);
		body.extend_from_slice("\r\n".as_bytes());
		body.extend_from_slice(format!("--{}--\r\n", BOUNDARY).as_bytes());

		let request = http::Request::post(url, vec![body])
			.add_header("Content-type", &*format!("multipart/form-data; boundary={}", BOUNDARY));
		// debug::info!("About to send the add request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		let response = pending
			.wait()
			.map_err(|_| <Error<T>>::HttpFetchingError)?;
		// debug::info!("Received the response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<u8>>();
		let response_data_str = str::from_utf8(&response_data).unwrap();
		let added_data: IPFSAddResult = serde_json::from_str(&response_data_str).unwrap();

		Ok(added_data.Hash)
	}
	
	fn ipfs_request_cat(data: Vec<u8>) -> Result<Vec<u8>, Error<T>> {
		let url = &format!("{}/cat?arg={}", HTTP_BASE_URL, String::from_utf8(data).unwrap());
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the cat request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		let response = pending
			.wait()
			.map_err(|_| <Error<T>>::HttpFetchingError)?;

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<u8>>();

		Ok(response_data)
	}
	
	fn ipns_request_key_gen(block_number: T::BlockNumber) -> Result<IPNSKey, Error<T>> {
		let key_name = &format!("block-{:?}", block_number);
		let url = &format!("{}/key/gen?arg={}", HTTP_BASE_URL, key_name);
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the key_gen request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		debug::info!("Pending: {:?}", pending);

		let response = pending
			.wait()
			.map_err(|_| <Error<T>>::HttpFetchingError)?;

		debug::info!("Response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<u8>>();
		let response_data_str = str::from_utf8(&response_data).unwrap();
		let ipns_key: IPNSKey = serde_json::from_str(&response_data_str).unwrap();

		Ok(ipns_key)
	}
	
	fn ipns_request_publish(ipfs_path: Vec<u8>, key: IPNSKey) -> Result<IPNSPublishResult, Error<T>> {
		if key.Name.is_empty() {
			return Err(<Error<T>>::NoIPNSKeyError);
		}

		let url = &format!("{}/name/publish?arg={}&key={}", HTTP_BASE_URL, str::from_utf8(&ipfs_path).unwrap(), str::from_utf8(&key.Name).unwrap());
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the ipns_publish request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error pending: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		debug::info!("Pending: {:?}", pending);

		let response = pending
			.wait()
			.map_err(|err| {
				debug::error!("Error response: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;

		debug::info!("Response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<u8>>();
		let response_data_str = str::from_utf8(&response_data).unwrap();
		let ipns_publish_result: IPNSPublishResult = serde_json::from_str(&response_data_str).unwrap();

		Ok(ipns_publish_result)
	}
	
	fn ipns_request_resolve(key: IPNSKey) -> Result<IPNSResolveResult, Error<T>> {
		if key.Id.is_empty() {
			return Err(<Error<T>>::NoIPNSKeyError);
		}

		let url = &format!("{}/name/resolve?arg={}&nocache=true", HTTP_BASE_URL, str::from_utf8(&key.Id).unwrap());
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the ipns_resolve request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error pending: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		debug::info!("Pending: {:?}", pending);

		let response = pending
			.wait()
			.map_err(|err| {
				debug::error!("Error response: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;

		debug::info!("Response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<u8>>();
		let response_data_str = str::from_utf8(&response_data).unwrap();
		let ipns_resolve_result: IPNSResolveResult = serde_json::from_str(&response_data_str).unwrap();

		Ok(ipns_resolve_result)
	}
	
	fn handle_data_requests() -> Result<(), Error<T>> {
        let data_queue = DataQueue::get();
        let len = data_queue.len();
        if len != 0 {
            debug::info!("IPFS: {} entr{} in the data queue", len, if len == 1 { "y" } else { "ies" });
        }

        for cmd in data_queue.into_iter() {
            match cmd {
                DataCommand::AddBytes(data) => {
                    match Self::ipfs_request_add(data) {
                        Ok(cid) => {
                            debug::info!(
                                "IPFS: added data with Cid {}",
                                str::from_utf8(&cid).expect("our own IPFS node can be trusted here; qed")
                            );
                        },
                        Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
                        Err(e) => debug::error!("IPFS: add error: {:?}", e),
                    }
                }
                DataCommand::CatBytes(data) => {
                    match Self::ipfs_request_cat(data) {
                        Ok(data) => {
                            if let Ok(str) = str::from_utf8(&data) {
                                debug::info!("IPFS: got data: {:?}", str);
                            } else {
                                debug::info!("IPFS: got data: {:x?}", data);
                            };
                        },
                        Ok(_) => unreachable!("only CatBytes can be a response for that request type; qed"),
                        Err(e) => debug::error!("IPFS: error: {:?}", e),
                    }
                }
            }
        }

        Ok(())
    }
	
	fn handle_ipns_key_request(block_number: T::BlockNumber) -> Result<(), Error<T>> {
		match Self::ipns_request_key_gen(block_number) {
			Ok(ipns_key) => {
				debug::info!("Received IPNS key: {:?}", ipns_key.clone().Id);

				let ipns_prev_key = IPNSKeyPrev::get();
				if !ipns_prev_key.Name.is_empty() {
					match Self::ipfs_request_add(ipns_key.clone().Id) {
						Ok(cid) => {
							debug::info!(
								"IPFS: added new key with Cid {}",
								str::from_utf8(&cid).expect("our own IPFS node can be trusted here; qed")
							);
							
							match Self::ipns_request_publish(cid, ipns_prev_key.clone()) {
								Ok(result) => {
									debug::info!(
										"IPNS: published new name under {} name",
										str::from_utf8(&ipns_prev_key.Name).expect("our own IPFS node can be trusted here; qed"),
									);
								},
								Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
								Err(e) => debug::error!("IPNS: publish to prev key error: {:?}", e),
							}
						},
						Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
						Err(e) => debug::error!("IPFS: add error: {:?}", e),
					}
				}

				Self::offchain_signed_new_ipns_key(ipns_key);
			},
			Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
			Err(e) => debug::error!("IPFS: add error: {:?}", e),
		}

        Ok(())
	}
	
	fn handle_ipns_publish_request(block_number: T::BlockNumber) -> Result<(), Error<T>> {
		let block_number_string = &format!("{:?}", block_number);
		match Self::ipfs_request_add(block_number_string.as_bytes().to_vec()) {
			Ok(cid) => {
				debug::info!(
					"IPFS: added data with Cid {}",
					str::from_utf8(&cid).expect("our own IPFS node can be trusted here; qed")
				);

				match Self::ipns_request_publish(cid, IPNSKeyCurrent::get()) {
					Ok(result) => {
						debug::info!(
							"IPNS: published new data under {} name",
							str::from_utf8(&result.Name).expect("our own IPFS node can be trusted here; qed")
						);
					},
					Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
					Err(e) => debug::error!("IPNS: publish error: {:?}", e),
				}
			},
			Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
			Err(e) => debug::error!("IPFS: add error: {:?}", e),
		}

        Ok(())
	}
	
	fn handle_ipns_resolve_request() -> Result<(), Error<T>> {
		match Self::ipns_request_resolve(IPNSKeyExternal::get()) {
			Ok(result) => {
				debug::info!(
					"IPNS: resolved IPNS name and got {}",
					str::from_utf8(&result.clone().Path).expect("our own IPFS node can be trusted here; qed")
				);

				match Self::ipfs_request_cat(result.Path) {
					Ok(data) => {
						if let Ok(str) = str::from_utf8(&data) {
							debug::info!("IPFS: got data behind IPNS name: {:?}", str);
						} else {
							debug::info!("IPFS: got data behind IPNS name: {:x?}", data);
						};

						if data.len() > 4 {
							let new_key = IPNSKey {
								Id: data,
								Name: b"external".to_vec()
							};
							Self::offchain_signed_new_ipns_external_key(new_key);
						}
					},
					Ok(_) => unreachable!("only CatBytes can be a response for that request type; qed"),
					Err(e) => debug::error!("IPFS: error: {:?}", e),
				}
			},
			Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
			Err(e) => debug::error!("IPFS: add error: {:?}", e),
		}

        Ok(())
	}
	
	fn offchain_signed_new_ipns_key(ipns_key: IPNSKey) -> Result<(), Error<T>> {
		// We retrieve a signer and check if it is valid.
		//   Since this pallet only has one key in the keystore. We use `any_account()1 to
		//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
		//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
		let signer = Signer::<T, T::AuthorityId>::any_account();
		
		// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
		//   - `None`: no account is available for sending transaction
		//   - `Some((account, Ok(())))`: transaction is successfully sent
		//   - `Some((account, Err(())))`: error occured when sending the transaction
		let result = signer.send_signed_transaction(|_acct| {
			// This is the on-chain function
			debug::info!("Result inner: {:?}", _acct.id);
			Call::ipns_commit_new_key(ipns_key.clone())
		});

		// Display error if the signed tx fails.
		if let Some((acc, res)) = result {
			if res.is_err() {
				debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
				return Err(<Error<T>>::OffchainSignedTxError);
			}
			// Transaction is sent successfully
			debug::info!("Transaction was sent with the following account: {:?}", acc.id);
			return Ok(());
		}

		// The case of `None`: no account is available for sending
		debug::error!("No local account available");
		Err(<Error<T>>::NoLocalAcctForSigning)
	}
	
	fn offchain_signed_new_ipns_external_key(ipns_key: IPNSKey) -> Result<(), Error<T>> {
		// We retrieve a signer and check if it is valid.
		//   Since this pallet only has one key in the keystore. We use `any_account()1 to
		//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
		//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
		let signer = Signer::<T, T::AuthorityId>::any_account();
		
		// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
		//   - `None`: no account is available for sending transaction
		//   - `Some((account, Ok(())))`: transaction is successfully sent
		//   - `Some((account, Err(())))`: error occured when sending the transaction
		let result = signer.send_signed_transaction(|_acct| {
			// This is the on-chain function
			debug::info!("Result inner: {:?}", _acct.id);
			Call::ipns_commit_new_external_key(ipns_key.clone())
		});

		// Display error if the signed tx fails.
		if let Some((acc, res)) = result {
			if res.is_err() {
				debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
				return Err(<Error<T>>::OffchainSignedTxError);
			}
			// Transaction is sent successfully
			debug::info!("Transaction was sent with the following account: {:?}", acc.id);
			return Ok(());
		}

		// The case of `None`: no account is available for sending
		debug::error!("No local account available");
		Err(<Error<T>>::NoLocalAcctForSigning)
	}
}