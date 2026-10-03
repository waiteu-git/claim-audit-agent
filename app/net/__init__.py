"""外向き HTTP の唯一の出口と、その部品（設計 §2・§5-3。担当 T3）。

  safefetch.py  SafeFetch（FetchPort 実装）。1回の取得の全体と、リダイレクトの各ホップの検査をやり直す流れ
  urlcheck.py   URL の検証・正規化（DNS の前）と、取得スコープ（URL 接頭辞）の照合
  ipcheck.py    DNS 解決後の IP 検査（非グローバル・メタデータ・IPv4 射影・NAT64 など）。標準ライブラリだけ
  resolver.py   GuardedResolver（全応答を検査し、1つでも悪ければ全体拒否）と、既定の名前解決（専用スレッドプール・同名は合流）
  backend.py    PinnedBackend（検査済みの IP にだけ接続する httpcore のネットワーク層。再解決しない）と WireMeter（受信バイトの計量）
  decode.py     gzip / deflate のデコード（出力を予算内に抑える＝圧縮爆弾対策）
  vectors.py    敵対ベクタ（pytest と共用のデータ。通信はしない）

httpcore・ssl・socket を import してよいのはこの package だけ（tests/test_safefetch_layout.py が固定）。
Gate3 で足すもの: fetcher（S3）へのクライアント実装（FetchPort のもう1つの実装）。
"""
