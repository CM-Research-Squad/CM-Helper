use std::error::Error;
use std::collections::BTreeMap;
use rand::{Rng, thread_rng};
use rand::distributions::Uniform;
use hmac::*;
use sha2::Sha256;

use crate::Transaction;

pub fn box_err<E: Error + Send + 'static>(e: E) -> Box<dyn Error + Send> {
    Box::new(e)
}

#[derive(Debug, Default)]
pub struct TransactionInfo {
    transaction_type: String,
    transaction_id: Option<String>,
    transaction_validation_id: Option<String>,
    data: BTreeMap<String, String>
}

impl From<&Transaction> for TransactionInfo {
    fn from(transaction: &Transaction) -> TransactionInfo {
        TransactionInfo {
            transaction_type: transaction.transaction_type.clone(),
            transaction_id: Some(transaction.transaction_id.clone()),
            transaction_validation_id: Some(transaction.validation_transaction_id.clone()),
            data: transaction.data.transaction_data.iter().map(|v| (v.code.clone(), v.value.clone())).collect()
        }
    }
}

pub fn create_transaction_data(
    transaction_type: &str,
    alea: Option<&str>,
    user_id: Option<&str>,
    transaction_validation_id: Option<&str>,
    device_id: Option<&str>,
) -> TransactionInfo
{
    let mut data = BTreeMap::new();
    if let Some(alea) = alea {
        data.insert("ALEA".to_string(), alea.to_string());
    }
    if let Some(device_id) = device_id {
        data.insert("IDNDEVICE".to_string(), device_id.to_string());
    }
    data.insert("PLATEFORME".to_string(), "ANDROID".to_string());
    if let Some(user_id) = user_id {
        data.insert("IDNU".to_string(), user_id.to_uppercase());
    }
    if let Some(transaction_validation_id) = transaction_validation_id {
        data.insert("TRANSACTIONVALIDATIONID".to_string(), transaction_validation_id.to_string());
    }

    TransactionInfo {
        transaction_type: transaction_type.to_string(),
        data: data,
        ..Default::default()
    }
}

pub fn encode_transaction_data(mut transaction_data: TransactionInfo, alea_short: bool) -> String {
    if let Some(transaction_validation_id) = &transaction_data.transaction_validation_id {
        if transaction_data.data.get("ALEA").is_none() {
            transaction_data.data.insert("ALEA".to_string(), transaction_data.transaction_id.as_ref().unwrap().to_string());
            if alea_short {
                transaction_data.data.insert("ALEASHORT".to_string(), transaction_validation_id.clone());
            }
            transaction_data.data.insert("CDFNX".to_string(), transaction_data.transaction_type.clone());
        }
    }
    transaction_data_to_string(transaction_data)
}

pub fn transaction_data_to_string(transaction_data: TransactionInfo) -> String {
    transaction_data.data.iter().map(|(k, v)| {
        k.clone() + "=" + v
    }).collect::<Vec<String>>().join("$$")
}

pub fn random() -> String {
    thread_rng()
        .sample_iter(&Uniform::new_inclusive(0, 9))
        .map(|v| char::from(v + b'0'))
        .take(40)
        .collect()
}

pub fn derive_key(secret_key: &[u8], pin_code: Option<&str>, salt: &str) -> Vec<u8> {
    let mut key_source = Vec::from(&b"\x01\x00\x00\x00"[..]);
    if pin_code.is_some() {
        key_source.extend(b"ConfMobWithPin");
    } else {
        key_source.extend(b"ConfMobWithoutPin");
    }
    key_source.extend(salt.as_bytes());
    key_source.extend(b"\x00ConfMobMKv1\x00\x01\x00\x00");
    let mut key = Hmac::<Sha256>::new_varkey(secret_key).unwrap();
    key.update(&key_source);
    let mut derived_key = key.finalize().into_bytes().to_vec();

    if let Some(pin_code) = pin_code {
        derived_key.extend(pin_code.as_bytes());
        let mut key = Hmac::<Sha256>::new_varkey(&derived_key).unwrap();
        let mut key_source: Vec<u8> = salt.as_bytes().into();
        key_source.extend(&[0x01, 0x00, 0x00, 0x00]);
        key.update(&key_source);
        hex::encode(&key.finalize().into_bytes()).into()
    } else {
        hex::encode(&derived_key).into()
    }
}