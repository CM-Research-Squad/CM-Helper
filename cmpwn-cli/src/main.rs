use cmpwn_lib::*;
use structopt::StructOpt;
use rand::{Rng, thread_rng};
use rand::distributions::Uniform;
use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyParts, PaddingScheme};
use yasna::models::ObjectIdentifier;
use num_bigint::BigUint;
use std::error::Error;
use sha1::Sha1;
use tokio;
use prettytable::*;

#[derive(StructOpt)]
#[structopt(name = "cmpwn", about = "Credit Mutuel tools for shit and giggles.")]
enum Args {
    Enroll {
        username: String,
    },
    #[structopt(name = "2fa")]
    SecondFA {
        username: String,
    },
    Info {
        username: String,
        account_name: Option<String>
    }
}

#[tokio::main]
async fn main() {
    let client = create_client();
    let settings = settings::get().unwrap();
    let args = Args::from_args();

    match args {
        Args::Enroll { username } => {
            let password = dialoguer::Password::new().with_prompt("Password")
                .interact()
                .unwrap();
            let response = login(&client, &settings.get_device_id().unwrap(), &username, &password).await.unwrap();

            let alea = settings.get_user_info(&username, false).unwrap()
                .map(|v| v.alea)
                .unwrap_or_else(||
                    thread_rng()
                        .sample_iter(&Uniform::new_inclusive(0, 9))
                        .map(|v| char::from(v + b'0'))
                        .take(40)
                        .collect());

            let user_info = enroll(&client, &response.userid, &settings.get_device_id().unwrap(), "My CLI Tool", &alea).await.unwrap();
            settings.create_user_info(&username, &user_info).unwrap();
        },
        Args::SecondFA { username } => {
            if let Some(user_info) = settings.get_user_info(&username, true).unwrap() {
                validate_2fa(&client, &settings.get_device_id().unwrap(), &user_info.user_id, &user_info.secret_key, user_info.validation_counter, false).await.unwrap();
            }
        },
        Args::Info { username, account_name } => {
            let password = dialoguer::Password::new().with_prompt("Password")
                .interact()
                .unwrap();
            let response = login(&client, &settings.get_device_id().unwrap(), &username, &password).await.unwrap();
            let info = get_user_info(&client, 1).await.unwrap();
            let webid = if let Some(account_name) = account_name {
                // TODO: print pretty error if account is not found. Maybe
                // fallback to the selector?
                info.liste_compte.compte.iter().find(|v| v.int == account_name).unwrap().webid.clone()
            } else {
                let mut select = dialoguer::Select::new();
                for compte in &info.liste_compte.compte {
                    select.item(format!("{}: {}", compte.int, compte.solde));
                }
                let compte = select.interact().unwrap();
                info.liste_compte.compte[compte].webid.clone()
            };
            let act_info = get_account_info(&client, &webid).await.unwrap();
            let mut table = Table::new();
            table.set_titles(row!["Date", "Libelé", "Montant"]);
            for ligmvt in &act_info.tabmvt.ligmvt {
                table.add_row(row![ligmvt.dat, ligmvt.lib, ligmvt.mnt]);
            }
            let format = prettytable::format::FormatBuilder::new()
                .column_separator(' ')
                .borders(' ')
                .separators(&[], prettytable::format::LineSeparator::new(' ', ' ', ' ', ' '))
                .padding(1, 1)
                .build();
            table.set_format(format);
            table.printstd();
        }
    }
}

async fn validate_2fa(client: &Client, device_id: &str, user_id: &str, secret_key: &[u8], counter: u32, auth: bool) -> Result<(), Box<dyn Error + Send>> {
    let mut result = find_transactions(client, device_id, user_id, secret_key, auth).await?;
    println!("{:#?}", result);
    let transaction = if result.transactions.transaction.len() == 1 {
        result.transactions.transaction.pop().unwrap()
    } else {
        unimplemented!();
    };
    let pin = dialoguer::Password::new().with_prompt("Pin")
        .interact()
        .unwrap();
    validate_transaction(client, device_id, user_id, secret_key, &transaction, &pin, counter).await
        .map_err(|v| v as _)?;
    Ok(())
}

fn key_to_pkcs8(key: &RSAPublicKey) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::new(vec![1,2,840,113549,1,1,1]));
                writer.next().write_null();
            });
            let key = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    let bytes = key.n().to_bytes_be();
                    writer.next().write_biguint(&BigUint::from_bytes_be(&bytes));
                    let bytes = key.e().to_bytes_be();
                    writer.next().write_biguint(&BigUint::from_bytes_be(&bytes));
                });
            });
            writer.next().write_bitvec_bytes(&key, key.len() * 8);
        });
    })
}

async fn enroll(client: &Client, user_id: &str, device_id: &str, device_name: &str, alea: &str) -> Option<settings::UserInfo> {
    let generate_client_key_hnd = std::thread::spawn(move || {
        RSAPrivateKey::new(&mut thread_rng(), 2048).unwrap()
    });

    let enrolment = exists_enroll(client, device_id, Some(alea)).await.unwrap();
    if enrolment.is_enrolled {
        println!("Weird, we're already enrolled.");
        return None
    }

    let otp_availability = enrolment.otp_availability_result.unwrap();
    if otp_availability.availability.to_lowercase() == "available" && otp_availability.delivery.method == "SMS" {
        // Send the second factor
        let delivery = deliver_enrolment_code(&client, device_id, device_name).await.unwrap();

        println!("{}", delivery.delivering.desc);


        let code = dialoguer::Input::<String>::new()
            .with_prompt("Confirmation code")
            .interact()
            .unwrap();
        let pin = dialoguer::Password::new()
            .with_prompt("Choose a Pin")
            .with_confirmation("Confirm pin", "Pins mismatch")
            .interact()
            .unwrap();

        let client_key = generate_client_key_hnd.join().unwrap();
        let client_key_data = key_to_pkcs8(&*client_key);

        let result = enroll_application(
            &client,
            device_id,
            device_name,
            alea,
            &code,
            &delivery.delivering.input_hidden.value,
            &delivery.server_public_key,
            &pin,
            &client_key_data).await.unwrap();

        let secret_key = client_key.decrypt(PaddingScheme::new_oaep::<Sha1>(), &result.secret_key).unwrap();
        let secret_key = base64::decode(secret_key).unwrap();

        // Don't even bothering verifying the key hash. CM hashes the wrong
        // thing anyways...
        verify_application(client, user_id, device_id, &pin, &enrolment.validation_transaction_id, &secret_key).await.unwrap();

        Some(settings::UserInfo {
            user_id: user_id.to_string(),
            secret_key,
            validation_counter: 0,
            alea: alea.to_string()
        })
    } else {
        println!("otp_availability unexpected: {:#?}", otp_availability);
        None
    }
}
