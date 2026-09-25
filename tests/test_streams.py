import io
import tarfile

import pytest

from aisb.errors import APIError
from aisb.streams import Stream, decode_output, demux, iter_jsonl, tar_context, tar_path, untar
from conftest import frame

PAYLOAD = frame(1, b"hello ") + frame(2, b"oops\n") + frame(1, b"world\n")


@pytest.mark.parametrize("size", [1, 3, 8, 9, len(PAYLOAD)])
def test_demux_across_arbitrary_chunk_boundaries(size):
    chunks = [PAYLOAD[i:i + size] for i in range(0, len(PAYLOAD), size)]
    assert list(demux(chunks)) == [(Stream.STDOUT, b"hello "), (Stream.STDERR, b"oops\n"), (Stream.STDOUT, b"world\n")]


def test_demux_rejects_truncated_frame():
    with pytest.raises(ValueError, match="truncated"):
        list(demux([PAYLOAD[:-2]]))


@pytest.mark.parametrize(("raw", "tty", "text"), [
    (PAYLOAD, False, "hello oops\nworld\n"),
    (b"raw tty \xe2\x9c\x93", True, "raw tty ✓"),
    (b"", False, ""),
])
def test_decode_output(raw, tty, text):
    assert decode_output(raw, tty) == text


def test_iter_jsonl_handles_split_objects_and_utf8():
    data = '{"status":"a"}\n{"status":"✓"}{"stream":"x"}\n'.encode()
    chunks = [data[i:i + 5] for i in range(0, len(data), 5)]
    assert list(iter_jsonl(chunks)) == [{"status": "a"}, {"status": "✓"}, {"stream": "x"}]


def test_iter_jsonl_raises_embedded_error():
    stream = [b'{"status":"ok"}\n{"error":"x","errorDetail":{"message":"manifest unknown"}}\n']
    with pytest.raises(APIError, match="manifest unknown"):
        list(iter_jsonl(stream))


def test_iter_jsonl_rejects_trailing_garbage():
    with pytest.raises(ValueError, match="incomplete"):
        list(iter_jsonl([b'{"a":1}\n{"b":']))


def test_tar_context_honors_dockerignore(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / ".dockerignore").write_text("# c\nnode_modules\n*.log\n!keep.log\n")
    (tmp_path / "node_modules" / "m").mkdir(parents=True)
    (tmp_path / "node_modules" / "m" / "i.js").write_text("")
    for name in ("app.py", "debug.log", "keep.log"):
        (tmp_path / name).write_text(name)
    names = tarfile.open(fileobj=io.BytesIO(tar_context(tmp_path))).getnames()
    assert sorted(names) == [".dockerignore", "Dockerfile", "app.py", "keep.log"]


def test_tar_context_requires_directory(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        tar_context(tmp_path / "nope")


def test_tar_path_roundtrip(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("A")
    names = untar(tar_path(tmp_path / "src"), tmp_path / "out")
    assert set(names) == {"src", "src/a.txt"}
    assert (tmp_path / "out" / "src" / "a.txt").read_text() == "A"


def test_untar_blocks_path_traversal(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("../evil")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(tarfile.TarError):
        untar(buf.getvalue(), tmp_path / "out")
