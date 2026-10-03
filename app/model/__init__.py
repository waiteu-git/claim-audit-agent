"""モデル呼び出しの境界。

ここでは何も import しない。ScriptedPort（テスト専用）を本番の import 連鎖に引き込まないため
（設計 §8 ⑩: ENV=public で ScriptedPort が import されていたら起動を拒否する）。
"""
