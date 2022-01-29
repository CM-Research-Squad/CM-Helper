use crate::remote_tokio::run;
use crate::AppState;

use gio::prelude::*;
use gtk::prelude::*;
use rand::prelude::*;
use rand::distributions::Uniform;
use cmpwn_lib::Client;
use std::error::Error;
use std::rc::Rc;
use crate::SETTINGS_DB;

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
    overview_carousel: gtk::Container,
}

fn do_login(client: Client, state: Rc<AppState>, widgets: LoginParams) {
    widgets.infobar.set_revealed(false);

    let username = widgets.username_entry.get_text().unwrap();
    let password = widgets.password_entry.get_text().unwrap();

    widgets.btn.set_sensitive(false);
    widgets.spinner.start();

    let client = client.clone();
    let widgets = widgets.clone();

    // Get the main thread's context, in order to run futures on it.
    let ctx = glib::MainContext::default();
    let state = state.clone();
    ctx.spawn_local(async move {
        let app_widgets = widgets.clone();
        let res = (|| async move {
            let res = run(cmpwn_lib::login(
                &client,
                &SETTINGS_DB.with(|v| v.get_device_id().map_err(|err| err as _))?,
                username.as_str(),
                password.as_str())).await.map_err(|err| err as _)?;

            *state.username.borrow_mut() = username.to_string();
            *state.user_id.borrow_mut() = res.userid;

            let alea = SETTINGS_DB.with(|v| v.get_user_info(username.as_str(), false))
                .map_err(|err| err as _)?
                .map(|v| v.alea)
                .unwrap_or_else(||
                    thread_rng()
                        .sample_iter(&Uniform::new_inclusive(0, 9))
                        .map(|v| char::from(v + b'0'))
                        .take(40)
                        .collect());
            println!("{:?}", alea);

            let enroll = run(cmpwn_lib::exists_enroll(
                &client,
                &SETTINGS_DB.with(|v| v.get_device_id().map_err(|err| err as _))?,
                Some(&alea)))
                .await
                .map_err(|err| err as _)?;

            println!("{:?}", enroll);

            let otp_availability = &enroll.otp_availability_result;

            if enroll.is_enrolled && enroll.is_active /*&& !enroll.is_incomplete_enrolment*/ {
                crate::show_overview(client, app_widgets.stack, app_widgets.overview_carousel)
                    .await
                    .map_err(|err| err as _)?;
                return Ok(())
            } else if let Some(availability) = otp_availability {
                if availability.availability.to_lowercase() == "available" &&
                    availability.delivery.method == "SMS"
                {
                    // TODO: Stop using string type here.
                    crate::start_enroll(app_widgets.stack.clone(), enroll, &alea, state.clone()).await;
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
}

macro_rules! clone {
    (@param _ ) => ( _ );
    (@param $x:ident) => ( $x );
    ($($n:ident),+ => move || $body:expr) => (
        {
            $( let $n = $n.clone(); )+
            move || $body
        }
    );
    ($($n:ident),+ => move |$($p:tt),+| $body:expr) => (
        {
            $( let $n = $n.clone(); )+
            move |$(clone!(@param $p),)+| $body
        }
    );
    ($($n:ident),+ => move |$($p:tt : $z:ty),+| $body:expr) => (
        {
            $( let $n = $n.clone(); )+
            move |$(clone!(@param $p) : $z,)+| $body
        }
    );
}

pub fn setup(client: Client, widgets: gtk::Builder, state: Rc<AppState>) {
    let widgets = LoginParams {
        spinner: widgets.get_object("login_spinner").unwrap(),
        btn: widgets.get_object("login_btn").unwrap(),
        infobar: widgets.get_object("infobar").unwrap(),
        errors_label: widgets.get_object("infobar_errors").unwrap(),
        username_entry: widgets.get_object("login_username").unwrap(),
        password_entry: widgets.get_object("login_password").unwrap(),
        stack: widgets.get_object("content_stack").unwrap(),
        overview_carousel: widgets.get_object("overview_carousel").unwrap(),
    };
    widgets.btn.clone().connect_clicked(clone!(client, widgets, state => move |btn| {
        do_login(client.clone(), state.clone(), widgets.clone());
    }));
    widgets.username_entry.clone().connect_activate(clone!(widgets => move |entry| {
        widgets.password_entry.grab_focus();
    }));
    widgets.password_entry.clone().connect_activate(clone!(client, widgets, state => move |entry| {
        do_login(client.clone(), state.clone(), widgets.clone());
    }));
}
