"""検査（T9）。決定論チェッカー（ネットワーク不使用・LLM 不使用・費用 0）と、FetchPort を注入して使う http_probe。

判定表は app/adjudicate.py（平置き）。run_check の窓口は registry.py。
class_screen.py は、要件の検査の種類（check_class。モデルが付ける）が引用の内容と合っているかを確かめる固定語彙の関門
（判定表が使う。AUTORUN・Planner の routes も、検査を走らせる前に同じ関数で確かめると、無駄な取得と誤った証拠チップを避けられる）。
"""
