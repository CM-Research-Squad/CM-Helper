use gtk::prelude::*;
use gio::prelude::*;
use std::rc::Rc;
use std::cell::*;
use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyParts, PaddingScheme};
use rand::prelude::*;
use yasna::models::ObjectIdentifier;
use num_bigint::BigUint;
use sha1::Sha1;
use rand::prelude::*;
use rand::distributions::Uniform;

mod remote_tokio;
mod login;

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

#[derive(Debug)]
struct KeyProvider {
    key: RefCell<Option<Result<futures::channel::oneshot::Receiver<RSAPrivateKey>, RSAPrivateKey>>>
}

impl Default for KeyProvider {
    fn default() -> KeyProvider {
        let (sender, receiver) = futures::channel::oneshot::channel();
        std::thread::spawn(move || {
            let key = RSAPrivateKey::new(&mut thread_rng(), 2048).unwrap();
            let _ = sender.send(key);
        });
        KeyProvider {
            key: RefCell::new(Some(Ok(receiver)))
        }
    }
}

impl KeyProvider {
    async fn acquire(&self) -> RSAPrivateKey {
        let mut key = self.key.borrow_mut().take().unwrap();
        let ret_val = match key {
            Ok(v) => {
                let key_data = v.await.unwrap();
                key = Err(key_data.clone());
                key_data
            },
            Err(ref key_data) => key_data.clone()
        };
        *self.key.borrow_mut() = Some(key);
        ret_val
    }
}

#[derive(Debug, Default)]
pub struct AppState {
    enroll_device_name: RefCell<String>,
    enroll_device_default: Cell<bool>,
    client_key: KeyProvider,
    otp_delivery: RefCell<cmpwn_lib::OtpDeliveringResult>,
    user_id: RefCell<String>,
    username: RefCell<String>
}

fn main() {
    // Initialize gtk. Should be the first thing done by the app.
    if gtk::init().is_err() {
        println!("Failed to initialize GTK.");
        return;
    }

    remote_tokio::init();

    // Force libhandy to get linked into the final binary...
    libhandy::ActionRow::new();

    // Create the Credit Mutuel HTTP Client and connect to the settings database.
    let client = cmpwn_lib::create_client();
    let settings = cmpwn_lib::settings::get().unwrap();
    let state = Rc::new(AppState::default());

    // Create the Gtk Application that will drive this program.
    let application = gtk::Application::new(Some("la.roblab.cmpwn"), Default::default())
        .expect("Initialization failed...");

    application.connect_activate(move |app| {
        let glade_src = include_str!("main.glade");
        let builder = gtk::Builder::new_from_string(glade_src);

        let window: gtk::Window = builder.get_object("main_window").unwrap();

        window.set_application(Some(app));

        // Wire up all the pages.
        login::setup(client.clone(), settings.clone(), builder.clone(), state.clone());
        setup_enroll_devicename(client.clone(), settings.clone(), builder.clone(), state.clone());
        setup_enroll_smsconfirm(client.clone(), settings.clone(), builder.clone(), state.clone());
        window.show_all();
    });

    application.run(&std::env::args().collect::<Vec<_>>());
}

fn setup_enroll_devicename(client: cmpwn_lib::Client, settings: cmpwn_lib::settings::Settings, builder: gtk::Builder, state: Rc<AppState>) {
    let btn: gtk::Button = builder.get_object("enroll_devicename_next").unwrap();
    let spinner: gtk::Spinner = builder.get_object("enroll_devicename_spinner").unwrap();
    let stack: gtk::Stack = builder.get_object("content_stack").unwrap();
    let device_name: gtk::Entry = builder.get_object("enroll_devicename_name").unwrap();
    let is_main: gtk::Switch = builder.get_object("enroll_devicename_main").unwrap();
    let infobar: gtk::InfoBar = builder.get_object("infobar").unwrap();
    let errors_label: gtk::Label = builder.get_object("infobar_errors").unwrap();
    let smsconfirm_desc: gtk::Label = builder.get_object("enroll_smsconfirmation_desc").unwrap();

    btn.clone().connect_clicked(move |_| {
        let device_name = device_name.get_text().unwrap().to_string();
        *state.enroll_device_name.borrow_mut() = device_name.clone();
        state.enroll_device_default.set(is_main.get_active());

        btn.set_sensitive(false);
        spinner.start();

        let ctx = glib::MainContext::default();
        let btn = btn.clone();
        let spinner = spinner.clone();
        let client = client.clone();
        let settings = settings.clone();
        let infobar = infobar.clone();
        let errors_label = errors_label.clone();
        let smsconfirm_desc = smsconfirm_desc.clone();
        let stack = stack.clone();
        let state = state.clone();
        ctx.spawn_local(async move {
            let res = (|| async move {
                let res = remote_tokio::run(cmpwn_lib::deliver_enrolment_code(
                    &client,
                    &settings.get_device_id().map_err(|err| err as _)?,
                    &device_name))
                    .await
                    .map_err(|err| err as _)?;
                *state.otp_delivery.borrow_mut() = res.clone();
                smsconfirm_desc.set_text(&res.delivering.desc);
                // TODO: Stop using string here
                stack.set_visible_child_name("enroll_smsconfirmation");
                Ok::<(), Box<dyn std::error::Error + Send>>(())
            })().await;

            btn.set_sensitive(true);
            spinner.stop();

            if let Err(err) = res {
                println!("{:?}", err);
                infobar.set_revealed(true);
                errors_label.set_text(&format!("{}", err));
            }
        });
    });
}

fn setup_enroll_smsconfirm(client: cmpwn_lib::Client, settings: cmpwn_lib::settings::Settings, builder: gtk::Builder, state: Rc<AppState>) {
    let btn: gtk::Button = builder.get_object("enroll_smsconfirmation_btn").unwrap();
    let sms_code: gtk::Entry = builder.get_object("enroll_smsconfirmation_code").unwrap();
    let pin: gtk::Entry = builder.get_object("enroll_smsconfirmation_pin").unwrap();
    let stack: gtk::Stack = builder.get_object("content_stack").unwrap();
    let spinner: gtk::Spinner = builder.get_object("enroll_smsconfirmation_spinner").unwrap();
    let infobar: gtk::InfoBar = builder.get_object("infobar").unwrap();
    let errors_label: gtk::Label = builder.get_object("infobar_errors").unwrap();

    btn.clone().connect_clicked(move |_| {
        let code = sms_code.get_text().unwrap().to_string();
        let pin = pin.get_text().unwrap().to_string();

        btn.set_sensitive(false);
        spinner.start();

        let ctx = glib::MainContext::default();
        let client = client.clone();
        let settings = settings.clone();
        let state = state.clone();
        let btn = btn.clone();
        let infobar = infobar.clone();
        let errors_label = errors_label.clone();
        let spinner = spinner.clone();
        ctx.spawn_local(async move {
            let res = (|| async move {
                let client_key = state.client_key.acquire().await;
                let client_key_data = key_to_pkcs8(&*client_key);
                let enrolled = remote_tokio::run(cmpwn_lib::enroll_application(
                    &client,
                    &settings.get_device_id().map_err(|err| err as _)?,
                    &state.enroll_device_name.borrow(),
                    &code,
                    &state.otp_delivery.borrow().delivering.input_hidden.value,
                    &state.otp_delivery.borrow().server_public_key,
                    &pin,
                    &client_key_data))
                    .await
                    .map_err(|err| err as Box<dyn std::error::Error + Send>)?;

                let secret_key = client_key.decrypt(PaddingScheme::new_oaep::<Sha1>(), &enrolled.secret_key)
                    .map_err(|err| Box::new(err) as _)?;
                let secret_key = base64::decode(secret_key)
                    .map_err(|err| Box::new(err) as _)?;

                let alea: String = thread_rng()
                    .sample_iter(&Uniform::new_inclusive(0, 9))
                    .map(|v| char::from(v + b'0'))
                    .take(40)
                    .collect();

                let exists_enroll = remote_tokio::run(cmpwn_lib::exists_enroll(
                    &client,
                    &settings.get_device_id().map_err(|err| err as _)?,
                    &alea))
                    .await
                    .map_err(|err| err as _)?;



                // Don't even bothering verifying the key hash. CM hashes the wrong
                // thing anyways...
                let res = remote_tokio::run(cmpwn_lib::verify_application(
                    &client,
                    &state.user_id.borrow(),
                    &settings.get_device_id().map_err(|err| err as _)?,
                    &pin,
                    &exists_enroll.validation_transaction_id,
                    &secret_key)).await?;

                println!("{:?}", res);

                let user_info = cmpwn_lib::settings::UserInfo {
                    user_id: state.user_id.borrow().clone(),
                    secret_key,
                    validation_counter: 0
                };
                settings.create_user_info(&state.username.borrow(), &user_info).unwrap();

                // TODO: Move to account screen.
                Ok::<(), Box<dyn std::error::Error + Send>>(())
            })().await;

            btn.set_sensitive(true);
            spinner.stop();

            if let Err(err) = res {
                println!("{:?}", err);
                infobar.set_revealed(true);
                errors_label.set_text(&format!("{}", err));
            }
        });
    });
}