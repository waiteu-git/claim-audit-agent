"""プリセット②③（架空の欠陥入りサンプル・偽の命令入りサンプル）のフィクスチャ。

文章・名称・URL はすべて合成した架空のもの（実在の主催者文書・人名・社名・実URLを使わない）。
  site/            配信するファイル（公開面 S2 が /fx/ で配る）。gen.py が生成し、tests が「生成物と一致」を固定する
  site.py          FixtureSite（パス → 応答の唯一の定義）と FixtureFetch（同じ定義をプロセス内で引く FetchPort。評価・リプレイ生成用）
  gen.py           欠陥の変種を機械生成する（基準の2種＋評価用の変種6件）。正解表 expected.json もここから作る
  expected.json    欠陥の正解表と、評価用の台本 Reader（OracleReader）が返す要件の一覧
  eval.py          評価の骨組み（検出 x/y・誤検知 z）。実 LLM は呼ばない（OracleReader＋router）

import の向き: site・gen は contracts・config だけ。eval は agent を組み立てる入口（cli と同じ扱い）。
"""
