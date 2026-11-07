"""Site canvas zoom slider (Login to Routers, Topology, Topology Builder)."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from pfsense_checker import site_canvas as sc


def test_slider_mapping_is_logarithmic_and_clamped() -> None:
    assert sc.zoom_to_slider(sc.ZOOM_MIN) == 0
    assert sc.zoom_to_slider(sc.ZOOM_MAX) == sc._ZOOM_STEPS  # noqa: SLF001
    assert sc.zoom_to_slider(100) == sc._ZOOM_STEPS  # noqa: SLF001
    for z in (0.1, 0.25, 1.0, 2.0, 4.0):
        assert abs(sc.slider_to_zoom(sc.zoom_to_slider(z)) - z) / z < 0.02
    # equal slider steps = equal zoom ratios
    a, b, c = (sc.slider_to_zoom(p) for p in (50, 100, 150))
    assert abs(b / a - c / b) < 1e-9


def test_view_zoom_bar_follows_slider_buttons_and_wheel() -> None:
    from pfsense_checker.topology_site import Device, SiteTopology

    QApplication.instance() or QApplication([])
    site = SiteTopology(name="t")
    site.devices.append(Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD",
                               ports=["ether1"], x=0.0, y=0.0))
    view = sc.SiteTopologyView()
    view.resize(800, 500)
    view.render_site(site)
    view.show()
    QApplication.processEvents()
    bar = view.zoom_bar
    assert bar.isVisible() and bar.percent.text() == "100%"
    bar.slider.setValue(sc.zoom_to_slider(0.5))
    assert abs(view.zoom() - 0.5) < 0.02 and bar.percent.text() == "50%"
    view.set_zoom(10)  # clamped
    assert view.zoom() == sc.ZOOM_MAX and bar.slider.value() == sc._ZOOM_STEPS  # noqa: SLF001
    bar.percent.click()  # back to 100%
    assert abs(view.zoom() - 1.0) < 1e-6
    view.zoom_to_fit()
    assert sc.ZOOM_MIN <= view.zoom() <= sc.ZOOM_MAX
    assert bar.percent.text() == f"{round(view.zoom() * 100)}%"
    # the bar sits inside the canvas, bottom-right
    vp = view.viewport().geometry()
    assert bar.geometry().right() <= vp.right() and bar.geometry().bottom() <= vp.bottom()
    view.close()
