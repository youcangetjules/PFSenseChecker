"""Dashboard tiles: Show and explain lists what is behind each number."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import kpi_explain as ke  # noqa: E402
from pfsense_checker.models import (  # noqa: E402
    BridgeInfo,
    CheckResult,
    Finding,
    InterfaceInfo,
    RuleInfo,
    Severity,
    VlanInfo,
)


def _result() -> CheckResult:
    r = CheckResult(hostname="guardian")
    r.findings = [Finding(Severity.ERROR, "Firewall", "WAN allows SSH from any", remediation="Restrict it"),
                  Finding(Severity.WARNING, "Crypto", "OpenVPN uses SHA1")]
    r.interfaces = [InterfaceInfo(name="wan", descr="WAN", device="igb3", enabled=True, ipaddr="dhcp"),
                    InterfaceInfo(name="opt4", device="igb2", enabled=False)]
    r.bridges = [BridgeInfo(bridgeif="bridge0", members=["opt11", "opt13"])]
    r.vlans = [VlanInfo(tag="710", if_parent="igb0", vlanif="igb0.710", descr="IOT")]
    r.filter_rules = [RuleInfo(index=1, kind="filter", type="pass", interface="wan", dst_port="22")]
    return r


def test_every_tile_explains_and_lists() -> None:
    r = _result()
    for key in ke.TILES:
        title, html = ke.explain(key, r)
        assert title and "guardian" in html
    assert "WAN allows SSH from any" in ke.explain("errors", r)[1] and "Restrict it" in ke.explain("errors", r)[1]
    assert "OpenVPN uses SHA1" in ke.explain("warnings", r)[1]
    assert "igb3" in ke.explain("interfaces", r)[1] and ">NO<" in ke.explain("interfaces", r)[1]
    assert "bridge0" in ke.explain("virtual", r)[1] and "igb0.710" in ke.explain("virtual", r)[1]
    assert "No packages installed." in ke.explain("packages", r)[1]
    assert "Load a config" in ke.explain("fw", None)[1]


def test_tiles_have_the_button() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.viz import KpiCard

    QApplication.instance() or QApplication([])
    card = KpiCard("Errors", explain=True)
    hits = []
    card.explain_clicked.connect(lambda: hits.append(1))
    card.explain_btn.click()
    assert card.explain_btn.text() == "Show and explain" and hits == [1]
    assert KpiCard("Plain").explain_btn is None


def test_selected_row_text_is_white() -> None:
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import QApplication, QStyle, QStyleOptionViewItem, QTreeWidget, QTreeWidgetItem

    from pfsense_checker.viz import SelectedWhiteTextDelegate

    QApplication.instance() or QApplication([])
    tree = QTreeWidget()
    item = QTreeWidgetItem(["radio wlan1", "Managed by CAPsMAN"])
    item.setForeground(0, QColor("#1565c0"))  # blue text, as on an info row
    tree.addTopLevelItem(item)
    delegate = SelectedWhiteTextDelegate(tree)
    opt = QStyleOptionViewItem()
    opt.state |= QStyle.StateFlag.State_Selected
    delegate.initStyleOption(opt, tree.indexFromItem(item, 0))
    assert opt.palette.color(opt.palette.ColorRole.Text).name() == "#ffffff"
    assert opt.palette.color(opt.palette.ColorRole.HighlightedText).name() == "#ffffff"
    plain = QStyleOptionViewItem()
    delegate.initStyleOption(plain, tree.indexFromItem(item, 0))
    assert plain.palette.color(plain.palette.ColorRole.Text).name() == "#1565c0"  # unselected keeps its colour
