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
struct ReceivedMessage {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    from: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    data: Vec<u8>,
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

#[derive(Encode, Decode, PartialEq)]
enum PubsubCommand {
    Publish(Vec<u8>, Vec<u8>),
    Subscribe(Vec<u8>),
}

decl_storage! {
	trait Store for Module<T: Trait> as TemplateModule {
		pub DataQueue: Vec<DataCommand>;
		pub PubsubQueue: Vec<PubsubCommand>;
		pub ReceivedMessages: Vec<Vec<u8>>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		QueuedDataToAdd(AccountId),
        QueuedDataToCat(AccountId),
        QueuedPubsubPublished(AccountId),
        QueuedPubsubSubscribed(AccountId),
        ReceivedMessage(AccountId),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		NoneValue,
		StorageOverflow,
		HttpFetchingError,

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
			PubsubQueue::kill();
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
		
		/// Subscribe to a pubsub topic
        #[weight = 100_000]
        pub fn ipfs_pubsub_subscribe(origin, topic: Vec<u8>) {
            let who = ensure_signed(origin)?;

            PubsubQueue::mutate(|queue| queue.push(PubsubCommand::Subscribe(topic)));
            Self::deposit_event(RawEvent::QueuedPubsubSubscribed(who));
        }
		
		/// Publish data to a pubsub topic
        #[weight = 100_000]
        pub fn ipfs_pubsub_publish(origin, topic: Vec<u8>, data: Vec<u8>) {
            let who = ensure_signed(origin)?;

            PubsubQueue::mutate(|queue| queue.push(PubsubCommand::Publish(topic, data)));
            Self::deposit_event(RawEvent::QueuedPubsubPublished(who));
		}
		
		/// Commit received pubsub data to the chain
		#[weight = 10000]
		pub fn submit_data_signed(origin, data: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			debug::info!("submit_data_signed: ({:?}, {:?})", data, who);

			ReceivedMessages::mutate(|list| list.push(data));
            Self::deposit_event(RawEvent::ReceivedMessage(who));
			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			if let Err(e) = Self::handle_data_requests() {
				debug::error!("IPFS: Encountered an error while processing data requests: {:?}", e);
			}

			if let Err(e) = Self::handle_pubsub_requests() {
				debug::error!("IPFS: Encountered an error while processing pubsub requests: {:?}", e);
			}
		}
	}
}

impl<T: Trait> Module<T> {
	fn ipfs_request_add(data: Vec<u8>) -> Result<Vec<Vec<u8>>, Error<T>> {
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
		debug::info!("About to send the add request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
		
		let response = pending
			.wait()
			.map_err(|_| <Error<T>>::HttpFetchingError)?;
		debug::info!("Received the response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let response_data = response.body().collect::<Vec<Vec<u8>>>();

		Ok(response_data)
	}
	
	fn ipfs_request_cat(data: Vec<u8>) -> Result<Vec<Vec<u8>>, Error<T>> {
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

		let response_data = response.body().collect::<Vec<Vec<u8>>>();

		Ok(response_data)
	}
	
	fn ipfs_request_pubsub_subscribe(topic: Vec<u8>) -> Result<Vec<Vec<u8>>, Error<T>> {
		let url = &format!("{}/pubsub/sub?arg={}", HTTP_BASE_URL, String::from_utf8(topic).unwrap());
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the pubsub subcribe request: {:?}", request);
		
		let pending = request
			.send()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;
			
			debug::info!("Pending: {:?}", pending);
			
		let response = pending
			.wait()
			.map_err(|err| {
				debug::error!("Error: {:?}", err);
				<Error<T>>::HttpFetchingError
			})?;

		debug::info!("Response: {:?}", response);

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		let mut response_body = response.body();

		let response_data = response_body
			.inspect(|msg| {
				let response_data_str = str::from_utf8(msg).unwrap();
				let received_message: ReceivedMessage = serde_json::from_str(&response_data_str).unwrap();
				let received_message_str = str::from_utf8(&received_message.data).unwrap();
				debug::info!("Received msg: {:?}", str::from_utf8(&base64::decode(&received_message_str).unwrap()).unwrap());
			})
			.collect::<Vec<Vec<u8>>>();

		debug::info!("ResponseData: {:?}", response_data);

		Ok(response_data)
	}
	
	fn ipfs_request_pubsub_publish(topic: Vec<u8>, data: Vec<u8>) -> Result<Vec<Vec<u8>>, Error<T>> {
		let url = &format!("{}/pubsub/pub?arg={}&arg={}", HTTP_BASE_URL, String::from_utf8(topic).unwrap(), String::from_utf8(data).unwrap());
		let body: Option<Vec<u8>> = None;
		let request = http::Request::post(url, body);
		debug::info!("About to send the pubsub publish request: {:?}", request);
		
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

		let response_data = response.body().collect::<Vec<Vec<u8>>>();

		Ok(response_data)
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
                                str::from_utf8(&cid[0]).expect("our own IPFS node can be trusted here; qed")
                            );
                        },
                        Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
                        Err(e) => debug::error!("IPFS: add error: {:?}", e),
                    }
                }
                DataCommand::CatBytes(data) => {
                    match Self::ipfs_request_cat(data) {
                        Ok(data) => {
                            if let Ok(str) = str::from_utf8(&data[0]) {
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
	
	fn handle_pubsub_requests() -> Result<(), Error<T>> {
        let pubsub_queue = PubsubQueue::get();
        let len = pubsub_queue.len();
        if len != 0 {
            debug::info!("IPFS: {} entr{} in the pubsub queue", len, if len == 1 { "y" } else { "ies" });
        }

        for cmd in pubsub_queue.into_iter() {
            match cmd {
                PubsubCommand::Subscribe(topic) => {
                    match Self::ipfs_request_pubsub_subscribe(topic) {
                        Ok(data) => {
							debug::info!("Subscribe received data: {:?}", data.clone());
							// Self::offchain_signed_tx(data);
                        },
                        Ok(_) => unreachable!("only AddBytes can be a response for that request type; qed"),
                        Err(e) => debug::error!("IPFS: add error: {:?}", e),
                    }
                }
                PubsubCommand::Publish(topic, data) => {
                    match Self::ipfs_request_pubsub_publish(topic, data) {
                        Ok(data) => {
                            if let Ok(str) = str::from_utf8(&data[0]) {
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
	
	fn offchain_signed_tx(data: Vec<u8>) -> Result<(), Error<T>> {
		// We retrieve a signer and check if it is valid.
		//   Since this pallet only has one key in the keystore. We use `any_account()1 to
		//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
		//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
		let signer = Signer::<T, T::AuthorityId>::any_account();
		debug::info!("Signer");
		
		// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
		//   - `None`: no account is available for sending transaction
		//   - `Some((account, Ok(())))`: transaction is successfully sent
		//   - `Some((account, Err(())))`: error occured when sending the transaction
		let result = signer.send_signed_transaction(|_acct| {
			// This is the on-chain function
			debug::info!("Result inner: {:?}", _acct.id);
			Call::submit_data_signed(data.clone())
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