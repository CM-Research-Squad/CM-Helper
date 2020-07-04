use hmac::*;
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::de::DeserializeOwned;
use quick_xml::de::from_str;
use std::error::Error;
use std::future::Future;
use rsa::{RSAPublicKey, PublicKey, PaddingScheme};
use futures::prelude::*;

mod serialization_utils;
mod error;
mod utils;
pub mod settings;
mod xml;
use utils::*;
use error::*;
pub use xml::*;

trait XmlResult {
    fn result(&self, url: &str) -> Result<(), FormError>;
}

trait XmlResultExtension: Sized {
    fn from_data(data: &str, url: &str) -> Result<Self, Box<dyn Error + Send + Sync>>;
}

impl<'a, T: XmlResult + DeserializeOwned> XmlResultExtension for T {
    fn from_data(data: &str, url: &str) -> Result<T, Box<dyn Error + Send + Sync>> {
        let doc: T = from_str(&data)
            .map_err(|err| DeserializeError {
                url: url.to_string(),
                data: data.to_string(),
                source: err
            })?;
        doc.result(url)?;
        Ok(doc)
    }
}

pub use reqwest::Client;
pub fn create_client() -> Client {
    Client::builder()
        .cookie_store(true)
        .user_agent("Security Research")
        .build()
        .unwrap()
}

pub fn get_account_info(client: &Client, account_id: &str) -> impl Future<Output = Result<AccountInformationResponse, Box<dyn Error + Send + Sync>>> {
    let req = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/LSTMVT2.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("webid", account_id.to_string());
            form.insert("_wsversion", "1".to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = req.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = AccountInformationResponse::from_data(&xml, "/cmmabn/fr/LSTMVT2.html")?;
            Ok(doc)
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            Err::<_, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")))
        }
    }
}

pub fn get_user_info(client: &Client, categorize: u32) -> impl Future<Output = Result<UserInformationResponse, Box<dyn Error + Send + Sync>>> {
    let req = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/banque/PRC2.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "4".to_string());
            form.insert("categorize", categorize.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = req.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = UserInformationResponse::from_data(&xml, "/cmmabn/fr/banque/PRC2.html")?;
            Ok(doc)
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            Err::<_, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")))
        }
    }
}

pub async fn validate_transaction(client: &Client, device_id: &str, user_id: &str, secret_key: &[u8], transaction: &Transaction, pin: &str, counter: u32) -> Result<(), Box<dyn Error + Send + Sync>> {
    let random = rand::random::<u32>().to_string();
    let token_data = encode_transaction_data(transaction.into(), true);

    let token_key_salt = Sha1::digest((transaction.transaction_type.clone() + &random + "Client/Serv").as_bytes());
    let token_key = derive_key(secret_key, Some(pin), &hex::encode(&token_key_salt));
    let mut token_key = Hmac::<Sha256>::new_varkey(&token_key).unwrap();
    token_key.update(token_data.as_bytes());
    let token = hex::encode(token_key.finalize().into_bytes());

    let resp = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_TransactionValidation.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("userId", user_id.to_string());
            form.insert("worldId", "CM".to_string());
            form.insert("transactionToken", token.to_string());
            form.insert("validationTransactionId", transaction.validation_transaction_id.clone());
            form.insert("safetynet", "".to_string());
            form.insert("transactionData", token_data.to_string());
            form.insert("action", "VALIDATE".to_string());
            form.insert("random", random.to_string());
            form.insert("validationCounter", counter.to_string());
            form.insert("authMode", "PINCODE".to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send()
        .await?;
    if resp.status().is_success() {
        let bytes = resp.bytes().await?;
        let xml = String::from_utf8_lossy(&bytes);
        let doc: TransactionValidationResponse = from_str(&xml)?;
        if doc.code_retour == 0 {
            return Ok(())
        } else {
            println!("{:?}", doc);
            return Err(Box::new(MyError::new("Invalid return code")));
        }
    } else {
        println!("{:?}", resp.status());
        println!("{:?}", resp.text().await?);
        return Err(Box::new(MyError::new("Request failed")));
    }
}

pub async fn find_transactions(client: &Client, device_id: &str, user_id: &str, secret_key: &[u8], auth: bool) -> Result<FindTransactionsResult, Box<dyn Error + Send + >> {
    let random = rand::random::<u32>().to_string();
    let transaction_random = rand::random::<u32>().to_string();
    let token_key_salt = Sha1::digest(("RCH".to_string() + &random + "Client/Serv").as_bytes());
    let token_key = derive_key(secret_key, None, &hex::encode(&token_key_salt));
    let token_data = encode_transaction_data(
        create_transaction_data("RCH", Some(&transaction_random), Some(user_id), None, Some(device_id)), true);

    let mut token_key = Hmac::<Sha256>::new_varkey(&token_key).unwrap();
    token_key.update(token_data.as_bytes());
    let token = hex::encode(token_key.finalize().into_bytes());

    let url = if auth {
        "https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_FindTransactionsAuth.html"
    } else {
        "https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_FindTransactionsUnauth.html"
    };
    let resp = client
        .post(url)
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("worldId", "CM".to_string());
            form.insert("userId", user_id.to_string());
            form.insert("random", random.to_string());
            form.insert("token", token.to_string());
            form.insert("transactionRandom", transaction_random.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send()
        .await
        .map_err(box_err)?;
    if resp.status().is_success() {
        let bytes = resp.bytes().await.map_err(box_err)?;
        let xml = String::from_utf8_lossy(&bytes);
        let doc: FindTransactionsResponse = from_str(&xml).unwrap();
        if doc.code_retour == 0 {
            return Ok(doc.find_transactions_result)
        } else {
            println!("{:?}", doc);
            return Err(Box::new(MyError::new("Invalid return code")));
        }
    } else {
        println!("{:?}", resp.status());
        println!("{:?}", resp.text().await.map_err(box_err)?);
        return Err(Box::new(MyError::new("Request failed")));
    }
}

pub fn verify_application(client: &Client, user_id: &str, device_id: &str, pin_code: &str, validation_transaction_id: &str, secret_key: &[u8]) -> impl Future<Output = Result<(), Box<dyn Error + Send>>> {
    let random = rand::random::<u32>();
    let salt = "EVF".to_string() + &random.to_string() + "Client/Serv";
    let salt = hex::encode(Sha1::digest(salt.as_bytes()));
    let derived_key = derive_key(secret_key, Some(pin_code), &salt);

    let transaction_data = create_transaction_data("EVF", None, Some(user_id), Some(validation_transaction_id), None);
    let transaction_data = encode_transaction_data(transaction_data, true);
    let mut hmac = Hmac::<Sha256>::new_varkey(&derived_key).unwrap();
    hmac.update(transaction_data.as_bytes());
    let data = hex::encode(&hmac.finalize().into_bytes());

    let resp = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_VerifyEnrolment.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("transactionValidationId", validation_transaction_id.to_string());
            form.insert("random", random.to_string());
            form.insert("validationToken", data.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = resp.await.map_err(box_err)?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await.map_err(box_err)?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = VerifyEnrolment::from_data(&xml, "/cmmabn/fr/SOSD_PUSH_VerifyEnrolment.html").map_err(|err| err as _)?;
            Ok::<_, Box<dyn Error + Send>>(())
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await.map_err(box_err)?);
            return Err::<_, Box<dyn Error + Send>>(Box::new(MyError::new("Request failed")));
        }
    }
}

pub fn enroll_application(client: &Client, device_id: &str, device_name: &str, otp_code: &str, otp_hidden: &str, server_key: &[u8], pin: &str, client_key: &[u8]) -> impl Future<Output = Result<EnrolmentResult, Box<dyn Error + Send + Sync>>> {
    let alea = random();
    let pin = pin.to_string() + "::" + &alea;
    let server_key = match RSAPublicKey::from_pkcs8(server_key) {
        Ok(v) => v,
        Err(err) => return futures::future::ready(Err(err.into())).left_future(),
    };
    let encrypted_pin = match server_key.encrypt(&mut thread_rng(), PaddingScheme::OAEP {
        digest: Box::new(Sha1::new()),
        label: None
    }, pin.as_bytes()) {
        Ok(v) => v,
        Err(err) => return futures::future::ready(Err(err.into())).left_future()
    };
    let encrypted_pin_data = base64::encode(encrypted_pin);
    let client_public_key = base64::encode(client_key);
    let client_public_key_hash = base64::encode(Sha256::digest(client_key));
    let resp = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_EnrollApplication.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("method", "SMS".to_string());
            form.insert("applicationVersion", "7.19.1".to_string());
            form.insert("deviceName", device_name.to_string());
            form.insert("isDeviceByDefault", false.to_string());
            form.insert("pin", encrypted_pin_data);
            // FCM token.
            //form.insert("pushId", push_id.to_string());
            form.insert("alea", alea);
            form.insert("enrolmentsToDelete", "".to_string());
            form.insert("clientPublicKey", client_public_key.to_string());
            form.insert("clientPublicKeyHash", client_public_key_hash.to_string());
            form.insert("otp_password", otp_code.to_string());
            form.insert("otp_hidden", otp_hidden.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = resp.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = EnrollApplicationResponse::from_data(&xml, "/cmmabn/fr/SOSD_PUSH_EnrollApplication.html")?;
            return Ok::<_, Box<dyn Error + Send + Sync>>(doc.enrolment_result.unwrap())
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            return Err::<_, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")));
        }
    }.right_future()
}

pub fn deliver_enrolment_code(client: &Client, device_id: &str, device_name: &str) -> impl Future<Output = Result<OtpDeliveringResult, Box<dyn Error + Send + Sync>>> {
    let resp = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_DeliverEnrolmentCode.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("method", "SMS".to_string());
            form.insert("action", "".to_string());
            form.insert("deviceName", device_name.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = resp.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = DeliverEnrolmentCodeResponse::from_data(&xml, "/cmmabn/fr/SOSD_PUSH_DeliverEnrolmentCode.html")?;
            return Ok::<_, Box<dyn Error + Send + Sync>>(doc.otp_delivering_result)
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            return Err::<_, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")));
        }
    }
}

pub fn exists_enroll(client: &Client, device_id: &str, alea: &str) -> impl Future<Output = Result<ExistsEnrolmentResult, Box<dyn Error + Send + Sync>>> {
    // Enrolling is the act of adding a new
    let resp = client
        .post("https://mobile.creditmutuel.fr/cmmabn/fr/SOSD_PUSH_ExistsEnrolment.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_wsversion", "5".to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("alea", alea.to_string());
            form.insert("_media", "AN".to_string());
            form
        })
        .send();

    async {
        let resp = resp.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = ExistsEnrolmentResponse::from_data(&xml, "/cmmabn/fr/SOSD_PUSH_ExistsEnrolment.html")?;
            Ok(doc.exists_enrolment_result)
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            return Err::<ExistsEnrolmentResult, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")));
        }
    }
}

pub fn login(client: &Client, device_id: &str, username: &str, password: &str) -> impl Future<Output = Result<LoginXmlResponse, Box<dyn Error + Send + Sync>>> {
    const HMAC_KEY: &'static [u8] = b"1da5d62a7ddd29f1ad97b61a0a9a872308f46f6297f71ead6a638d0953e606bc";
    let hmac_key = hex::decode(HMAC_KEY).unwrap();

    let req = client
        .post("https://mobile.creditmutuel.fr/wsmb/fr/IDE2.html")
        .form(&{
            let mut form = HashMap::<&'static str, String>::new();
            form.insert("_cm_user", username.to_string());
            form.insert("applicationCode", "CM".to_string());
            form.insert("platform", "ANDROID".to_string());
            form.insert("deviceId", device_id.to_string());
            form.insert("_appversion", "7.19.1".to_string());
            form.insert("_wsversion", "2".to_string());
            // TODO: Get userId somehow.
            form.insert("userId", "".to_string());
            form.insert("_cm_pwd", password.to_string());
            form.insert("cv", "AN1".to_string());
            form.insert("timestamp", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis().to_string());
            form.insert("_cible", "CM".to_string());
            form.insert("_media", "AN".to_string());
            let code_data = form["_cm_user"].clone() + &form["_cm_pwd"] + &form["_media"] + &form["timestamp"] + &form["cv"];
            let mut key = Hmac::<Sha256>::new_varkey(&hmac_key).unwrap();
            key.update(code_data.as_bytes());
            let code = key.finalize().into_bytes();
            form.insert("code", hex::encode(code));
            form
        })
        .send();

    async {
        let resp = req.await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            let xml = String::from_utf8_lossy(&bytes);
            let doc = LoginXmlResponse::from_data(&xml, "/wsmb/fr/IDE2.html")?;
            Ok(doc)
        } else {
            println!("{:?}", resp.status());
            println!("{:?}", resp.text().await?);
            Err::<LoginXmlResponse, Box<dyn Error + Send + Sync>>(Box::new(MyError::new("Request failed")))
        }
    }
}