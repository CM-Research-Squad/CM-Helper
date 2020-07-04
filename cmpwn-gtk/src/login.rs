use crate::remote_tokio::run;
use crate::AppState;

use gio::prelude::*;
use gtk::prelude::*;
use rand::prelude::*;
use rand::distributions::Uniform;
use cmpwn_lib::{Client, settings::Settings};
use std::error::Error;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct LoginParams {
    spinner: gtk::Spinner,
    btn: gtk::Button,
    infobar: gtk::InfoBar,
    errors_label: gtk::Label,
    // TODO: Add a combo box with known usernames.
    username_entry: gtk::Entry,
    password_entry: gtk::Entry,
    stack: gtk::Stack,
}

pub fn setup(client: Client, settings: Settings, widgets: gtk::Builder, state: Rc<AppState>) {
    let widgets = LoginParams {
        spinner: widgets.get_object("login_spinner").unwrap(),
        btn: widgets.get_object("login_btn").unwrap(),
        infobar: widgets.get_object("infobar").unwrap(),
        errors_label: widgets.get_object("infobar_errors").unwrap(),
        username_entry: widgets.get_object("login_username").unwrap(),
        password_entry: widgets.get_object("login_password").unwrap(),
        stack: widgets.get_object("content_stack").unwrap(),
    };
    widgets.btn.clone().connect_clicked(move |btn| {
        widgets.infobar.set_revealed(false);

        let username = widgets.username_entry.get_text().unwrap();
        let password = widgets.password_entry.get_text().unwrap();

        btn.set_sensitive(false);
        widgets.spinner.start();

        let client = client.clone();
        let settings = settings.clone();
        let widgets = widgets.clone();

        // Get the main thread's context, in order to run futures on it.
        let ctx = glib::MainContext::default();
        let state = state.clone();
        ctx.spawn_local(async move {
            let app_widgets = widgets.clone();
            let res = (|| async move {
                let res = run(cmpwn_lib::login(
                    &client,
                    &settings.get_device_id().map_err(|err| err as _)?,
                    username.as_str(),
                    password.as_str())).await.map_err(|err| err as _)?;

                *state.username.borrow_mut() = username.to_string();
                *state.user_id.borrow_mut() = res.userid;

                let alea: String = thread_rng()
                    .sample_iter(&Uniform::new_inclusive(0, 9))
                    .map(|v| char::from(v + b'0'))
                    .take(40)
                    .collect();

                let enroll = run(cmpwn_lib::exists_enroll(
                    &client,
                    &settings.get_device_id().map_err(|err| err as _)?,
                    &alea))
                    .await
                    .map_err(|err| err as _)?;

                let otp_availability = &enroll.otp_availability_result;

                if enroll.is_enrolled && enroll.is_active && !enroll.is_incomplete_enrolment {
                    // We are enrolled. Ask for pin and go to main page.
                    return Ok(())
                } else if let Some(availability) = otp_availability {
                    if availability.availability.to_lowercase() == "available" &&
                        availability.delivery.method == "SMS"
                    {
                        println!("{:?}", enroll);
                        // TODO: Stop using string type here.
                        app_widgets.stack.set_visible_child_name("enroll_devicename");
                        return Ok::<_, Box<dyn Error + Send>>(())
                    }
                }
                return Err(Box::<dyn Error + Send + Sync>::from("No OTP availability found that satisfies our needs."))
                    .map_err(|err| err as _);
            })().await;

            widgets.spinner.stop();
            widgets.btn.set_sensitive(true);

            if let Err(err) = res {
                println!("{:?}", err);
                widgets.infobar.set_revealed(true);
                widgets.errors_label.set_text(&format!("{}", err));
            }
        });
    });
}