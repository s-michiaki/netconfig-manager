"""ルールのひな形の共通部分（作り方と、分野・根拠の決まり）"""

# 分野（ComplianceRule.category）。画面の絞り込みと同じ並び
CATEGORIES = ["管理アクセス", "認証", "ログ", "時刻", "SNMP", "暗号", "サービス", "バナー", "そのほか"]

# 根拠（ComplianceRule.reference）。特定の文書の節番号は書かず、出どころの種類だけを書く
REF_GENERAL = "一般的な堅牢化の推奨"
REF_VENDOR = "ベンダーの堅牢化ガイドの考え方"
REF_OPS = "運用上の推奨"

ADJUST = "環境に合わせて調整してください。"

# 例を 1 つも持たない・API の応答に含めない項目（テスト用の例）
EXAMPLE_KEYS = ("good", "bad", "extra_good", "extra_bad")


def tpl(
    name: str, severity: str, platforms: list[str], category: str, description: str,
    match_type: str, expect: str, pattern: str, *, good: str, bad: str, remediation: str,
    reference: str = REF_GENERAL, scope: str = "config", section_pattern: str | None = None,
    extra_good: list[str] | None = None, extra_bad: list[str] | None = None,
) -> dict:
    """ひな形 1 件。good は合格するコンフィグの例、bad は違反するコンフィグの例（テストが evaluate で確かめる）。

    remediation の「# 」で始まる行は説明（画面のコピーでは除かれる）、それ以外の行が機器の設定モードで入れる例。
    値は <プレースホルダ> にして、実在のアドレス・コミュニティ名・パスワードは書かない
    """
    t: dict = {
        "name": name, "severity": severity, "platforms": platforms, "category": category,
        "description": description if description.endswith(ADJUST) else f"{description.rstrip('。')}。{ADJUST}",
        "match_type": match_type, "expect": expect, "pattern": pattern, "scope": scope,
        "remediation": remediation.strip("\n"), "reference": reference,
        "good": good, "bad": bad, "extra_good": extra_good or [], "extra_bad": extra_bad or [],
    }
    if scope == "section":
        t["section_pattern"] = section_pattern
    return t
