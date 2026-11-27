"""コンプライアンスのルールのひな形（機種ごとに分けて持つ）

各ひな形は tpl() で作り、合格する例（good）と違反する例（bad）を一緒に持つ。例は実行時の API の応答には含めず、
テスト（tests/test_compliance_templates.py）が evaluate で全件を確かめる。
ひな形は実機では確かめていない（書式は公式ドキュメントと一部を照合したのみ）。合格・違反の例は手で書いたもので、
テストは書式の誤りを検出できない。環境に合わせて調整し、直し方は内容を確かめてから投入すること。既存のひな形の名前は、ひな形から作ったルールの「同じ名前」の判定に使われるので変えない
"""
from . import alliedware, arista_eos, cisco_asa, cisco_ios, cisco_nxos, common, fortigate, junos, panos, yamaha
from ._base import CATEGORIES, EXAMPLE_KEYS

# 画面に出す順。Cisco IOS / IOS-XE の既存の並びを先頭に保つ
_MODULES = [cisco_ios, common, panos, fortigate, alliedware, junos, cisco_nxos, cisco_asa, arista_eos, yamaha]

ALL_TEMPLATES: list[dict] = [t for m in _MODULES for t in m.TEMPLATES]

# API の応答に出す形（テスト用の例を除く）
TEMPLATES: list[dict] = [{k: v for k, v in t.items() if k not in EXAMPLE_KEYS} for t in ALL_TEMPLATES]

__all__ = ["ALL_TEMPLATES", "CATEGORIES", "TEMPLATES"]
