"""Multilingual intent classifier for deletion authorization requests."""
import re

DELETE = [
    r"\bdelet", r"\berase", r"\bremove (my|all)", r"close my account", r"forgotten",
    r"supprim", r"effac", r"elimin", r"borr", r"suprim", r"lösch", r"entfern",
    r"excluir", r"apag", r"削除", r"消去", r"삭제", r"حذف", r"مسح"
]

NON_DELETE = [
    r"\bexport\b", r"copy of", r"\bdownload\b", r"access request", r"\bunsubscribe",
    r"opt[- ]?out", r"\bupdate\b", r"change my", r"correct my", r"exportation",
    r"copie", r"envíen", r"copia", r"exporta", r"mettre à jour", r"actualiz",
    r"cópia", r"エクスポート", r"내보내", r"تصدير", r"نسخة"
]

NEGATION = [
    r"do not delete", r"don't delete", r"not want .* delet",
    r"no (quiero|deseo) (borrar|eliminar)"
]


def classify(text: str) -> str:
    t = (text or "").lower()
    if any(re.search(p, t) for p in NEGATION):
        return "AMBIGUOUS"
    d = any(re.search(p, t) for p in DELETE)
    n = any(re.search(p, t) for p in NON_DELETE)
    if d and not n:
        return "DELETE"
    if n and not d:
        return "NOT_APPLICABLE"
    return "AMBIGUOUS"


def is_deletion(text: str) -> bool:
    """Returns True if the request authorizes deletion, False if NOT_APPLICABLE."""
    return classify(text) != "NOT_APPLICABLE"
