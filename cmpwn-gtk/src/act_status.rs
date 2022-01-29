use gtk::prelude::*;
use cmpwn_lib::{Compte, LigMvt};
use gtk::{Orientation, Align, Widget};
use pango::{AttrList, Attribute, Weight};

pub fn create_account_status(act: &Compte, last_movements: &[LigMvt]) -> impl IsA<Widget> {
    let widget = gtk::Box::new(Orientation::Vertical, 0);
    widget.get_style_context().add_class("frame");
    widget.get_style_context().add_class("act_overview");

    let header = gtk::Box::new(Orientation::Horizontal, 0);
    let act_name_num = gtk::Box::new(Orientation::Vertical, 0);
    act_name_num.set_hexpand(true);

    let act_name = gtk::Label::new(Some(&act.int));
    act_name.set_halign(Align::Start);
    let attrs = AttrList::new();
    attrs.insert(Attribute::new_scale(1.2).unwrap());
    act_name.set_attributes(Some(&attrs));

    // TODO: star out the first numbers.
    let act_num = gtk::Label::new(Some(&act.account_number));
    act_num.set_halign(Align::Start);
    act_name_num.pack_start(&act_name, false, true, 0);
    act_name_num.pack_start(&act_num, false, true, 0);

    let balance = gtk::Label::new(Some(&act.solde));
    let attrs = AttrList::new();
    attrs.insert(Attribute::new_scale(1.2).unwrap());
    attrs.insert(Attribute::new_weight(Weight::Bold).unwrap());
    balance.set_attributes(Some(&attrs));

    header.pack_start(&act_name_num, false, true, 10);
    header.pack_start(&balance, false, true, 10);
    widget.pack_start(&header, false, true, 0);

    let transactions_box = gtk::Box::new(Orientation::Vertical, 0);
    for mvt in last_movements.iter().take(3) {
        let transaction_box = gtk::Box::new(Orientation::Horizontal, 0);
        transaction_box.get_style_context().add_class("act_line");

        let dat_lbl = gtk::Label::new(Some(&format!("{}", mvt.dat.format("%d/%m"))));

        let lib_lbl = gtk::Label::new(Some(&mvt.lib));
        lib_lbl.set_halign(Align::Start);

        let mnt_lbl = gtk::Label::new(Some(&mvt.mnt));
        let attrs = AttrList::new();
        attrs.insert(Attribute::new_weight(Weight::Semibold).unwrap());
        mnt_lbl.set_attributes(Some(&attrs));

        transaction_box.pack_start(&dat_lbl, false, true, 10);
        transaction_box.pack_start(&lib_lbl, true, true, 10);
        transaction_box.pack_start(&mnt_lbl, false, true, 10);
        transactions_box.pack_start(&transaction_box, false, true, 5);
    }

    widget.pack_start(&transactions_box, false, true, 0);

    widget.show_all();
    widget
}