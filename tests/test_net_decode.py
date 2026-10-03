"""本文のデコード（app/net/decode.py）。圧縮爆弾対策: 出力が上限を超える前に止め、メモリを使い切らない。"""
import gzip
import time
import tracemalloc
import zlib

import pytest

from app.net.decode import BodyDecoder, DecodeError, UnsupportedEncoding, parse_content_encoding


def _feed_all(dec: BodyDecoder, data: bytes, step: int | None = None) -> BodyDecoder:
    step = step or len(data) or 1
    for i in range(0, len(data), step):
        dec.feed(data[i : i + step])
    dec.finish()
    return dec


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


@pytest.mark.parametrize(
    ("header", "expected"),
    [(None, None), ("", None), ("identity", None), ("gzip", "gzip"), ("GZIP", "gzip"), ("x-gzip", "gzip"), ("deflate", "deflate"), (" gzip ", "gzip"), ("identity, gzip", "gzip")],
)
def test_parse_content_encoding_accepts_only_gzip_deflate_identity(header, expected):
    assert parse_content_encoding(header) == expected


@pytest.mark.parametrize("header", ["br", "zstd", "compress", "gzip, gzip", "gzip, deflate", "gzip, br", "unknown"])
def test_parse_content_encoding_rejects_others_and_nesting(header):
    with pytest.raises(UnsupportedEncoding):
        parse_content_encoding(header)


def test_identity_passthrough_and_exact_cap_is_not_truncated():
    dec = _feed_all(BodyDecoder(None, 10), b"a" * 10)
    assert dec.data == b"a" * 10 and dec.truncated is False and dec.over is False
    dec = _feed_all(BodyDecoder(None, 10), b"a" * 11)
    assert dec.data == b"a" * 10 and dec.truncated is True and dec.over is True


@pytest.mark.parametrize("step", [None, 1, 7, 64])
def test_gzip_round_trip_with_any_chunking(step):
    raw = bytes(range(256)) * 40
    dec = _feed_all(BodyDecoder("gzip", 1 << 20), gzip.compress(raw), step)
    assert dec.data == raw and dec.truncated is False


@pytest.mark.parametrize("step", [None, 1, 5])
def test_deflate_zlib_wrapped_and_raw_both_work(step):
    raw = b"hello deflate " * 300
    assert _feed_all(BodyDecoder("deflate", 1 << 20), zlib.compress(raw), step).data == raw
    assert _feed_all(BodyDecoder("deflate", 1 << 20), _raw_deflate(raw), step).data == raw  # zlib ヘッダ無しを送る実装


@pytest.mark.parametrize("step", [None, 1, 3])
def test_concatenated_gzip_members_are_all_decoded(step):
    parts = [b"first part. ", b"second part. ", b"third."]
    dec = _feed_all(BodyDecoder("gzip", 1 << 20), b"".join(gzip.compress(p) for p in parts), step)
    assert dec.data == b"".join(parts)


def test_trailing_garbage_after_the_stream_is_ignored():
    dec = _feed_all(BodyDecoder("gzip", 1 << 20), gzip.compress(b"body") + b"\x00\x00junk")
    assert dec.data == b"body"
    dec = _feed_all(BodyDecoder("deflate", 1 << 20), zlib.compress(b"body") + b"junk")
    assert dec.data == b"body"


def test_gzip_bomb_stops_at_the_cap_without_expanding_it(  # noqa: PLR0915
):
    """展開後 256MiB・圧縮後約 250KB。上限 1MiB で止まり、メモリは上限の数倍に収まり、短時間で終わる。"""
    comp = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    payload = b"".join(comp.compress(b"\x00" * (1 << 20)) for _ in range(256)) + comp.flush()
    assert len(payload) < 400 * 1024
    cap = 1 << 20
    dec = BodyDecoder("gzip", cap)
    tracemalloc.start()
    t0 = time.perf_counter()
    dec.feed(payload)  # 1回で全部を渡しても、出力は cap+1 で止まる
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    dec.finish()
    assert dec.over and dec.truncated and len(dec.data) == cap
    assert peak < 8 * cap, f"メモリが上限の数倍を超えた: {peak}"
    assert elapsed < 2.0


def test_stream_that_ends_before_the_cap_is_complete_and_not_truncated():
    dec = _feed_all(BodyDecoder("gzip", 100), gzip.compress(b"x" * 100))
    assert dec.data == b"x" * 100 and dec.truncated is False
    dec = _feed_all(BodyDecoder("gzip", 100), gzip.compress(b"x" * 101))
    assert dec.data == b"x" * 100 and dec.truncated is True


def test_corrupt_and_truncated_streams_raise_decode_error():
    good = gzip.compress(b"hello world " * 50)
    with pytest.raises(DecodeError):
        _feed_all(BodyDecoder("gzip", 1 << 20), b"this is not gzip at all")
    with pytest.raises(DecodeError):
        _feed_all(BodyDecoder("gzip", 1 << 20), good[: len(good) // 2])  # 途中で切れた（黙って部分データを返さない）
    bad = bytearray(good)
    bad[len(bad) // 2] ^= 0xFF
    with pytest.raises(DecodeError):
        _feed_all(BodyDecoder("gzip", 1 << 20), bytes(bad))
    with pytest.raises(DecodeError):
        _feed_all(BodyDecoder("deflate", 1 << 20), b"\xff\xff\xff\xff not deflate")


def test_empty_body_with_a_compression_header_is_not_an_error():
    dec = BodyDecoder("gzip", 100)
    dec.finish()
    assert dec.data == b"" and dec.truncated is False


def test_nothing_is_read_after_over():
    dec = BodyDecoder(None, 3)
    dec.feed(b"abcdef")
    dec.feed(b"ghi")
    assert dec.data == b"abc" and dec.over
