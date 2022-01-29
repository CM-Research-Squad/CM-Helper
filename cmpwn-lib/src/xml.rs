use serde::{Deserialize, Deserializer};
use serde::de::{Error, Unexpected};
use crate::serialization_utils::*;
use chrono::NaiveDate;

macro_rules! make_result {
    ($t:ident) => {
        impl crate::XmlResult for $t {
            fn result(&self, url: &str) -> Result<(), crate::FormError> {
                if self.code_retour == 0 {
                    Ok(())
                } else {
                    Err(crate::FormError {
                        url: url.to_string(),
                        code: self.code_retour,
                        msg: self.msg_retour.clone(),
                        details: self.detail_msg_retour.clone(),
                    })
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LigMvt {
    #[serde(deserialize_with = "deser_naive_date")]
    pub dat: NaiveDate,
    pub lib: String,
    pub lib2: String,
    pub lib3: String,
    pub lib4: String,
    pub lib5: String,
    pub mnt: String,
    #[serde(rename = "type")]
    pub ty: String
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TabMvt {
    pub ligmvt: Vec<LigMvt>
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountInformationResponse {
    pub code_retour: u32,
    #[serde(default)]
    pub msg_retour: String,
    #[serde(default)]
    pub detail_msg_retour: String,
    #[serde(default)]
    pub date_msg: String,
    #[serde(default)]
    pub tabmvt: TabMvt,
}

make_result!(AccountInformationResponse);

#[derive(Debug, Clone, Deserialize)]
pub struct Category {
    pub name: String,
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CategoryList {
    pub category: Vec<Category>
}

#[derive(Debug, Clone, Deserialize)]
pub struct Compte {
    pub account_type: u32,
    pub iban: String,
    pub devise: String,
    pub account_number: String,
    pub intc: String,
    pub int: String,
    pub tit: String,
    pub refprd: String,
    pub codprd: String,
    pub refctr_exi_val: String,
    pub refctr_inn_val: String,
    pub has_announced_transactions: Option<u32>,
    pub category_code: String,
    pub category_name: String,
    pub solde: String,
    pub agreed_overdraft: String,
    pub appcpt: u32,
    pub isholder: u32,
    pub webid: String,
    pub checkingaccount: u32,
    pub characteristics: u32,
    pub simulation: u32,
    pub contract: (),
    #[serde(rename = "isFavorite")]
    pub is_favorite: u32
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListeCompte {
    pub compte: Vec<Compte>
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserInformationResponse {
    pub code_retour: u32,
    #[serde(default)]
    pub msg_retour: String,
    #[serde(default)]
    pub detail_msg_retour: String,
    #[serde(default)]
    pub date_msg: String,
    #[serde(deserialize_with = "deserialize_code_retour_cpl")]
    pub code_retour_cpl: u32,
    pub category_list: Option<CategoryList>,
    #[serde(default)]
    pub liste_compte: ListeCompte,
}

fn deserialize_code_retour_cpl<'de, D>(de: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>
{
    let s = String::deserialize(de)?;
    if s == "" {
        return Ok(0);
    }

    match s.parse() {
        Ok(v) => Ok(v),
        Err(err) => Err(D::Error::invalid_value(Unexpected::Str(&s), &"Expected a number")),
    }
}

make_result!(UserInformationResponse);

#[derive(Debug, Clone, Deserialize)]
pub struct Fct {
    pub code: String
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ListFn {
    pub fct: Vec<Fct>
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Cdc {
    pub civ: String,
    pub prenom: String,
    pub nom: String,
    pub tel: String,
    pub mel: String
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct LoginXmlResponse {
    pub code_retour: u32,
    #[serde(default)]
    pub msg_retour: String,
    #[serde(default)]
    pub detail_msg_retour: String,
    #[serde(default)]
    pub date_msg: String,

    #[serde(default)]
    pub sca: bool,
    #[serde(default)]
    pub liste_fonction: ListFn,
    #[serde(default)]
    pub userid: String,
    #[serde(default)]
    pub libelle_client: String,
    #[serde(default)]
    pub dtcnx: String,
    #[serde(default)]
    pub fede: u32,
    #[serde(default)]
    pub is_bad_contract_signed: String,
    #[serde(default)]
    pub cdc: Cdc,
    #[serde(default)]
    pub root_url: String,
    #[serde(default)]
    pub password_change_date: String
}

make_result!(LoginXmlResponse);

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "enrolmentForUser")]
#[serde(rename_all = "camelCase")]
pub struct EnrolmentForUser {
    pub device_name: String,
    pub enrolment_date: String,
    pub user_enrolment_id: String,
    pub is_default: bool,
    pub platform: String,
    pub application_code: String,
    pub is_incomplete: bool
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "otherEnrolmentsForUser")]
pub struct OtherEnrolmentsForUser {
    #[serde(rename = "enrolmentForUser")]
    pub enrolments_for_user: Vec<EnrolmentForUser>
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "delivery")]
pub struct Delivery {
    pub method: String,
    pub desc: String
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "otpAvailabilityResult")]
#[serde(rename_all = "camelCase")]
pub struct OtpAvailabilityResult {
    pub availability: String,
    pub unavailability_description: String,
    pub delivery: Delivery
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "existsEnrolmentResult")]
#[serde(rename_all = "camelCase")]
pub struct ExistsEnrolmentResult {
    pub is_enrolled: bool,
    pub is_active: bool,
    pub push_token: String,
    pub is_incomplete_enrolment: bool,
    pub validation_transaction_id: String,
    pub other_enrolments_for_user: OtherEnrolmentsForUser,
    pub otp_availability_result: Option<OtpAvailabilityResult>
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "root")]
pub struct ExistsEnrolmentResponse {
    pub code_retour: u32,
    #[serde(default)]
    pub msg_retour: String,
    #[serde(default)]
    pub detail_msg_retour: String,
    #[serde(default)]
    pub date_msg: String,
    #[serde(rename = "existsEnrolmentResult")]
    pub exists_enrolment_result: ExistsEnrolmentResult
}

make_result!(ExistsEnrolmentResponse);

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputPassword {
    pub key: String,
    pub format: String,
    pub label: String,
    pub max_length: u32
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputHidden {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivering {
    pub method: String,
    pub status: String,
    pub desc: String,
    pub delivery_date: String,
    pub input_password: InputPassword,
    pub input_hidden: InputHidden
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTransactionMethods {
    pub in_transaction_methods_title: String,
    pub backup_input_hidden_key: String,
    pub backup_delivery_methods_tab: BackupDeliveryMethodsTab,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDeliveryMethodsTab {
    pub backup_delivery_method: Vec<BackupDeliveryMethod>
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDeliveryMethod {
    pub method: Option<String>,
    pub desc: String,
    pub obfuscated_coordinate: Option<String>,
    pub backup_input_hidden_key: Option<String>
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutTransactionMethods {
    pub backup_delivery_method: BackupDeliveryMethod
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDeliveryMethods {
    pub backup_delivery_title: String,
    pub in_transaction_methods: InTransactionMethods,
    pub out_transaction_methods: OutTransactionMethods,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpDeliveringResult {
    pub delivering: Delivering,
    pub backup_delivery_methods: BackupDeliveryMethods,
    #[serde(deserialize_with = "deser_base64")]
    pub server_public_key: Vec<u8>,
    pub server_public_key_hash: String
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "root")]
pub struct DeliverEnrolmentCodeResponse {
    pub code_retour: u32,
    pub msg_retour: String,
    pub detail_msg_retour: String,
    pub date_msg: String,
    #[serde(rename = "otpDeliveringResult")]
    pub otp_delivering_result: OtpDeliveringResult
}

make_result!(DeliverEnrolmentCodeResponse);

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpCheckResult {
    pub status: String,
    pub error_message: String
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrolmentResult {
    pub otp_check_result: OtpCheckResult,
    #[serde(deserialize_with = "deser_base64")]
    pub secret_key: Vec<u8>,
    pub secret_key_hash: String
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "root")]
pub struct EnrollApplicationResponse {
    pub code_retour: u32,
    pub msg_retour: String,
    pub detail_msg_retour: String,
    pub date_msg: String,
    #[serde(rename = "enrolmentResult")]
    pub enrolment_result: Option<EnrolmentResult>
}

make_result!(EnrollApplicationResponse);

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "root")]
pub struct VerifyEnrolment {
    pub code_retour: u32,
    pub msg_retour: String,
    pub detail_msg_retour: String,
    pub date_msg: String,
}

make_result!(VerifyEnrolment);

#[derive(Debug, Deserialize)]
enum EnrolmentMethod {
    SMS,
    PKC,
    IVS,
    EMAIL,
    PMAIL,
    INMOBILEAPP,
    NONE
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename = "root")]
pub struct FindTransactionsResponse {
    pub code_retour: u32,
    pub msg_retour: String,
    pub detail_msg_retour: String,
    pub date_msg: String,
    #[serde(rename = "findTransactionsResult")]
    pub find_transactions_result: FindTransactionsResult
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct FindTransactionsResult {
    pub transactions: Transactions,
    pub is_blocked: bool
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Transactions {
    #[serde(default)]
    pub transaction: Vec<Transaction>
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub can_biometrics_be_used: bool,
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    pub validation_transaction_id: String,
    pub transaction_nonce: String,
    pub transaction_type: String,
    pub transaction_label: String,
    pub data: Data
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub transaction_data: Vec<TransactionData>
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionData {
    pub code: String,
    pub value: String
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct TransactionValidationResponse {
    pub code_retour: u32,
    pub msg_retour: String,
    pub detail_msg_retour: String,
    pub date_msg: String,
    #[serde(rename = "transactionValidationResult")]
    pub transaction_validation_result: Option<TransactionValidationResult>
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct TransactionValidationResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XmlResultExtension;

    #[test]
    fn regression_test_empty_code_retour_cpl() {
        let xml = r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><code_retour>0000</code_retour><msg_retour /><date_msg>20220101010101</date_msg><code_retour_cpl /><category_list><category><name>Comptes courants</name><code>depot</code></category><category><name>Épargne</name><code>saving</code></category></category_list><liste_compte></liste_compte></root>"#;
        let doc = UserInformationResponse::from_data(&xml, "/cmmabn/fr/banque/PRC2.html").unwrap();
    }
}
