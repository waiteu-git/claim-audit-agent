"""本文のデコード（設計 §5-3 圧縮爆弾対策）。

`zlib.decompressobj().decompress(data, max_length)` で出力を予算内に抑える。素直に全展開すると、数 KB の入力が数 GB に
なる（gzip 爆弾）。ここは「欲しい分より1バイト多く」だけ展開して、超えたら止める（超えたか＝打切りの印）。
受け付ける Content-Encoding は gzip / deflate だけ（Accept-Encoding で要求した範囲）。br・zstd・多重指定は拒否する。
"""
import zlib


class DecodeError(Exception):
    """圧縮データが壊れている・途中で切れている。"""


class UnsupportedEncoding(Exception):
    """要求していない Content-Encoding（br・zstd）や多重指定。"""


def parse_content_encoding(value: str | None) -> str | None:
    """None（無圧縮）・"gzip"・"deflate" のどれかを返す。それ以外は UnsupportedEncoding。"""
    tokens = [t.strip().lower() for t in (value or "").split(",") if t.strip()]
    tokens = [t for t in tokens if t != "identity"]
    if not tokens:
        return None
    if len(tokens) > 1:
        raise UnsupportedEncoding("encoding.multiple")  # 入れ子の圧縮は爆弾の定番なので受けない
    if tokens[0] in ("gzip", "x-gzip"):
        return "gzip"
    if tokens[0] == "deflate":
        return "deflate"
    raise UnsupportedEncoding("encoding.unsupported")


_GZIP_MAGIC = b"\x1f\x8b"


class BodyDecoder:
    """受信した塊を feed し、`limit` バイトを超える出力が確定したら over になる（それ以上は読まない）。"""

    def __init__(self, encoding: str | None, limit: int) -> None:
        self._encoding = encoding
        self._limit = limit
        self._out = bytearray()
        self._d = self._new_decompressor() if encoding else None
        self._started = False  # 圧縮ストリームへ1回でも入力したか
        self._ended = False  # 圧縮ストリームが正常に終わった（以降の入力は次のメンバか余り）
        self._tail = b""  # 終端後に届いた、まだ次メンバの先頭か判定できない端数
        self._raw_deflate_tried = False
        # deflate は「zlib 包み」か「生」かを最初の出力まで決められない。その間の入力を取っておき、読み替え時に先頭から流し直す
        self._head: bytearray | None = bytearray() if encoding == "deflate" else None
        self.over = False  # limit を超える出力が確定した

    def _new_decompressor(self):  # noqa: ANN202 zlib の型は公開されていない
        if self._encoding == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip ヘッダ・トレーラ込み
        return zlib.decompressobj(zlib.MAX_WBITS)  # zlib 包み（deflate の標準形）

    def _append(self, chunk: bytes) -> None:
        room = self._limit + 1 - len(self._out)
        if room > 0:
            self._out += chunk[:room]
        if len(self._out) > self._limit:
            self.over = True

    def feed(self, data: bytes) -> None:
        if self.over or not data:
            return
        if self._d is None:
            self._append(data)
            return
        self._started = True
        if self._head is not None:
            self._head += data
        buf = self._tail + data if self._ended else data
        self._tail = b""
        while buf and not self.over:
            if self._ended:
                if self._encoding == "gzip" and buf[:2] == _GZIP_MAGIC:  # 連結された次のメンバ
                    self._d = self._new_decompressor()
                    self._ended = False
                elif self._encoding == "gzip" and len(buf) < 2 and _GZIP_MAGIC.startswith(buf):
                    self._tail = buf  # 次の塊と合わせないと判定できない
                    return
                else:
                    return  # 余り（トレーラ後の無意味なバイト）は捨てる
            room = self._limit + 1 - len(self._out)  # 常に 1 以上（0 は zlib で「無制限」の意味になるので渡さない）
            try:
                chunk = self._d.decompress(buf, room)
            except zlib.error as e:
                if self._head is not None and not self._raw_deflate_tried and not self._out:
                    # 生 deflate（zlib ヘッダ無し）を送る実装がある。最初の失敗だけ読み替え、入力を先頭から流し直す
                    self._raw_deflate_tried = True
                    self._d = zlib.decompressobj(-zlib.MAX_WBITS)
                    buf = bytes(self._head)
                    continue
                raise DecodeError("decode.corrupt") from e
            self._append(chunk)
            if self._head is not None and (self._out or self._raw_deflate_tried):
                self._head = None  # 形式が決まった。以降は取っておかない
            if self._d.eof:
                self._ended = True
                buf = self._d.unused_data
            else:
                buf = self._d.unconsumed_tail  # room に達して残した入力（次のループで続きを展開する）

    def finish(self) -> None:
        """入力の終わり。圧縮ストリームが途中で切れていたら DecodeError（上限で止めた場合は問わない）。"""
        if self._d is not None and self._started and not self._ended and not self.over:
            raise DecodeError("decode.truncated")

    @property
    def data(self) -> bytes:
        return bytes(self._out[: self._limit])

    @property
    def truncated(self) -> bool:
        return len(self._out) > self._limit
