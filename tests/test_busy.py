from pfsense_checker.busy import begin_busy, end_busy, is_busy


def test_begin_busy_without_qapplication_is_noop() -> None:
    assert not is_busy()
    begin_busy()
    assert not is_busy()
    end_busy()
    assert not is_busy()
