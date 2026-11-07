"""Sliding two-level section menu (Home) and Config Check as its child."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _menu():
    from pfsense_checker.section_menu import SlidingSectionMenu

    _app()
    menu = SlidingSectionMenu()
    menu.set_sections(
        [
            ("login", "Login to Routers", None),
            ("config", "Config Check", [("config.open", "Open / Pull config")]),
            ("setup", "Setup", [("setup.oui", "OUI"), ("setup.logging", "Logging")]),
        ]
    )
    menu.resize(300, 600)
    return menu


def test_parent_slides_main_to_strip_and_shows_submenu() -> None:
    from pfsense_checker import section_menu as sm

    menu = _menu()
    picked: list[str] = []
    menu.section_selected.connect(picked.append)
    menu.select("login", animate=False)
    assert menu.main.width() == 300
    assert not menu.sub_panel.isVisibleTo(menu)

    item = menu.main.topLevelItem(2)  # Setup
    menu._on_main_clicked(item, 0)
    menu._apply(1.0)  # finish the slide
    assert picked[-1] == "setup.oui"
    assert menu.open_parent() == "setup"
    assert menu.main.width() == int(300 * sm.STRIP_RATIO)
    assert menu.sub_panel.isVisibleTo(menu)
    assert menu.sub_title.text() == "Setup"
    assert "#9e9e9e" in menu.main.styleSheet()  # main text greyed

    menu._on_main_clicked(menu.main.topLevelItem(0), 0)  # Login: slide back
    menu._apply(0.0)
    assert picked[-1] == "login"
    assert not menu.is_open()
    assert menu.main.width() == 300
    assert "#9e9e9e" not in menu.main.styleSheet()


def test_reopening_a_parent_returns_to_its_last_child() -> None:
    menu = _menu()
    picked: list[str] = []
    menu.section_selected.connect(picked.append)
    menu.select("setup.logging", animate=False)
    menu.select("login", animate=False)
    menu._on_main_clicked(menu.main.topLevelItem(2), 0)
    assert picked[-1] == "setup.logging"


def test_children_can_be_replaced_while_open() -> None:
    menu = _menu()
    menu.select("config.open", animate=False)
    menu.set_children(
        "config",
        [("config.open", "Open / Pull config"), ("config.tab:Dashboard", "Dashboard")],
    )
    assert menu.sub.topLevelItemCount() == 2
    assert menu.current_key() == "config.open"
    menu.select("config.tab:Dashboard", animate=False)
    assert menu.current_key() == "config.tab:Dashboard"
    assert menu.parent_of("config.tab:Dashboard") == "config"


def test_main_window_lists_config_tabs_under_config_check() -> None:
    _app()
    from pfsense_checker.gui import MainWindow

    window = MainWindow()
    try:
        home = window.home_screen
        home._deferred_ensure_login_page()
        assert home.stack.currentWidget() is home._pages["login"]
        home.show_section("config")
        labels = [
            home.nav.sub.topLevelItem(i).text(0)
            for i in range(home.nav.sub.topLevelItemCount())
        ]
        assert labels[0] == "Open / Pull config"
        assert "Dashboard" in labels and "Findings" in labels
        assert home.nav.open_parent() == "config"

        window._enter_workspace("Findings")
        assert home.current_section_key() == "config.tab:Findings"
        assert home.stack.currentWidget() is home._pages["config.workspace"]
        assert window._stack.currentIndex() == 0

        home.show_section("login")
        assert not home.nav.is_open()
        assert home.stack.currentWidget() is home._pages["login"]
    finally:
        window.close()
        window.deleteLater()


def test_back_arrow_returns_to_full_list_and_reopens_at_last_child() -> None:
    menu = _menu()
    picked: list[str] = []
    menu.section_selected.connect(picked.append)
    menu.select("setup.logging", animate=False)
    assert menu.back_btn.toolTip() == "Back to all sections"
    assert not menu.back_btn.icon().isNull()

    menu.back()
    menu._apply(0.0)  # finish the slide
    assert not menu.is_open()
    assert menu.main.width() == 300
    assert menu.main.currentItem().text(0) == "Setup"
    assert picked == []  # back does not change the page

    menu._on_main_clicked(menu.main.topLevelItem(2), 0)
    assert picked[-1] == "setup.logging"
    assert menu.open_parent() == "setup"


def test_loaded_configs_list_opens_config_check(tmp_path) -> None:
    _app()
    from pfsense_checker.home_screen import HomeScreen, loaded_config_devices
    from pfsense_checker.topology_site import ConfigSource, Device, SiteTopology

    cfg = tmp_path / "host-222-10-50-5.rsc"
    cfg.write_text("# export", encoding="utf-8")
    site = SiteTopology(subnets=["222.10.50.0/24"])
    with_cfg = Device(name="host-222-10-50-5", kind="mikrotik", mgmt_ip="222.10.50.5")
    with_cfg.config_source = ConfigSource.from_local_path(str(cfg))
    ignored = Device(name="dup-gw", kind="pfsense", mgmt_ip="222.10.50.1", ignored=True)
    ignored.config_source = ConfigSource.from_local_path(str(cfg))
    missing = Device(name="gone", kind="mikrotik", mgmt_ip="222.10.50.9")
    missing.config_source = ConfigSource.from_local_path(str(tmp_path / "nope.rsc"))
    for d in (with_cfg, ignored, missing):
        site.add_or_update_device(d)

    rows = loaded_config_devices(site)
    assert [r[0] for r in rows] == ["host-222-10-50-5", "dup-gw"]  # ignored last
    assert rows[0][1:4] == ("mikrotik", "222.10.50.5", str(cfg))

    home = HomeScreen()
    assert home.loaded_configs.item(0).text().startswith("None yet")
    home._live_site = site
    home._refresh_loaded_configs()
    assert home.loaded_configs.count() == 2
    opened: list[str] = []
    home.config_pulled_for_check.connect(opened.append)
    home._open_loaded_config(home.loaded_configs.item(0))
    assert opened == [str(cfg)]


def test_security_sections_open() -> None:
    _app()
    from pfsense_checker.home_screen import HomeScreen

    home = HomeScreen()
    for key, title in (
        ("security_holes", "Security Holes"),
        ("pentesting", "Pentesting"),
        ("dns_leakage", "DNS Leakage"),
    ):
        home.show_section(key)
        assert home.current_section_key() == key
        assert home.stack.currentWidget() is home._pages[key]
        assert home.nav.label(key) == title
