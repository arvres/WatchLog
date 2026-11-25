import os
import sys

import pytest

from watchlog.reader import follow_lines, read_lines


def test_read_lines_strips_newlines_and_tolerates_bad_bytes(tmp_path):
    f = tmp_path / "a.log"
    f.write_bytes(b"one\r\ntwo\n\xff\xfebad\n")
    lines = list(read_lines(f))
    assert lines[:2] == ["one", "two"] and len(lines) == 3


def _follow(path, actions, **kw):
    """Executa uma ação por 'sleep' (momento em que o reader está ocioso)."""
    it = iter(actions)
    done = []

    def fake_sleep(_):
        try:
            next(it)()
        except StopIteration:
            done.append(True)

    return list(follow_lines(path, sleep=fake_sleep, stop=lambda: bool(done), **kw))


def append(path, text):
    def _do():
        with open(path, "ab") as fh:
            fh.write(text.encode())

    return _do


def test_follow_skips_existing_content_by_default(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("old\n")
    assert _follow(f, [append(f, "new\n")]) == ["new"]


def test_follow_from_start_reads_existing_content(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("old\n")
    assert _follow(f, [append(f, "new\n")], from_start=True) == ["old", "new"]


def test_follow_buffers_partial_lines(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("")
    out = _follow(f, [append(f, "par"), append(f, "tial\n")])
    assert out == ["partial"]


def test_follow_survives_truncation(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("")

    def truncate_and_write():
        f.write_text("c\n")  # mesmo inode, tamanho menor que a posição lida

    assert _follow(f, [append(f, "aaaa\nbbbb\n"), truncate_and_write]) == ["aaaa", "bbbb", "c"]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file locking prevents rotation test")
def test_follow_survives_rotation(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("")

    def rotate():
        os.rename(f, tmp_path / "a.log.1")
        f.write_text("after-rotation\n")

    assert _follow(f, [append(f, "before\n"), rotate]) == ["before", "after-rotation"]
