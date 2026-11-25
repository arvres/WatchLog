from watchlog.detection.state import Cooldown, KeyedWindows, SlidingWindow


def test_sliding_window_evicts_old_items():
    w = SlidingWindow(10)
    w.add(0, "a")
    w.add(5, "b")
    assert len(w) == 2
    w.add(10, "c")  # t=0 sai: janela é (agora-10, agora]
    assert len(w) == 2
    assert w.values() == {"b", "c"}


def test_sliding_window_distinct_counts_repeated_values_once():
    w = SlidingWindow(100)
    for t in range(5):
        w.add(t, "admin")
    assert len(w) == 5
    assert w.distinct == 1


def test_sliding_window_distinct_shrinks_after_eviction():
    w = SlidingWindow(10)
    w.add(0, "a")
    w.add(1, "b")
    w.add(20, "c")
    assert w.distinct == 1 and w.values() == {"c"}


def test_keyed_windows_are_independent():
    kw = KeyedWindows(10)
    kw.add("x", 0, "1")
    kw.add("y", 0, "1")
    assert len(kw.add("x", 1, "2")) == 2
    assert len(kw.get("y", 1)) == 1


def test_keyed_windows_garbage_collects_stale_keys():
    kw = KeyedWindows(10, gc_every=4)
    for i in range(3):
        kw.add(f"old{i}", 0, "v")
    assert len(kw) == 3
    kw.add("new", 1000, "v")  # 4ª operação dispara a coleta
    assert len(kw) == 1


def test_keyed_windows_get_missing_and_discard():
    kw = KeyedWindows(10)
    assert kw.get("nope", 0) is None
    kw.add("k", 0, "v")
    kw.discard("k")
    assert kw.get("k", 0) is None


def test_cooldown_blocks_then_expires():
    c = Cooldown(60)
    assert c.try_acquire("k", 0)
    assert not c.try_acquire("k", 59)
    assert c.try_acquire("k", 60)
    assert c.try_acquire("other", 1)


def test_cooldown_zero_never_blocks():
    c = Cooldown(0)
    assert c.try_acquire("k", 0) and c.try_acquire("k", 0)
