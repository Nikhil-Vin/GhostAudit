"""Multilingual intent classifier: does request_text actually authorize account deletion?

Decision order (rule based, deterministic, no model calls):
  1. PRESERVE cues  - the sender explicitly wants the account/records kept, or says the message is
                      not a deletion request                              -> NOT_APPLICABLE
  2. DELETE cues    - an explicit erase / close-and-delete request          -> DELETE
  3. NON_DELETE cues- access, export, correction, update, login help       -> NOT_APPLICABLE
  4. otherwise      -> AMBIGUOUS (treated as a deletion request by is_deletion, because the
                       workflow only reaches this classifier with a deletion-style request).
"""
import re

PRESERVE = [
    # English
    r"not asking for (a )?(deletion|erasure)", r"not a request to (delete|erase|remove)",
    r"(do not|don't|dont) (close|delete|erase|remove)\b", r"\bnot (want|wish) .{0,30}(delet|clos|eras|remov)",
    r"(leave|keep) (the |my |this )?(account|profile)", r"\bwithout (removing|deleting|erasing|closing)",
    r"\bstill (need|want|use|require)\b", r"continue using", r"\bmarketing (lists?|emails?|messages?) only\b",
    r"\bonly (from )?(the )?marketing\b", r"\bin place\b.*\bkeep|\bleave .{0,30} in place",
    r"\bkeep (it|them|everything)\b", r"\bnot (to )?(delete|erase|close)\b",
    # French
    r"(ne|n') ?(pas )?(supprim|effac|ferm)\w* pas", r"\bne (supprimez|effacez|fermez) pas",
    r"\bsans supprimer", r"\bconserv\w+ (le|mon) (compte|profil)",
    # Spanish
    r"\bno (quiero|deseo|solicito) (borrar|eliminar|cerrar)", r"\bno (borren|eliminen|cierren)",
    r"\bsin (borrar|eliminar)", r"\bmantengan (la|mi) cuenta",
    # Portuguese
    r"\bn[ãa]o (quero|desejo|solicito) (excluir|apagar|encerrar)", r"\bn[ãa]o (excluam|apaguem|encerrem)",
    r"\bsem (excluir|apagar)", r"\bmantenham (a|minha) conta",
]

DELETE = [
    r"\bdelet", r"\berase", r"\berasure", r"\bremove (my|all|the|this)\b", r"close (my|this|the) account",
    r"\bforgotten", r"\bpermanent(ly)? .{0,20}(delet|eras|remov|clos)",
    r"suppress?ion", r"supprim", r"effac", r"\belimin", r"\bborr(ar|en|ad|e)", r"suprim", r"lösch",
    r"entfern", r"\bexclus", r"\bexclu[ií]", r"\bapag", r"\bencerr", r"削除", r"消去", r"삭제", r"حذف", r"مسح",
]

NON_DELETE = [
    r"\bexport\b", r"copy of", r"\bdownload\b", r"access request", r"\bunsubscribe", r"opt[- ]?out",
    r"\bupdate\b", r"\bchange\b", r"correct\b", r"\breplace\b", r"\breset\b", r"out of date", r"misspelled",
    r"\binvoices?\b", r"what personal information", r"\bsend me a copy",
    r"exportation", r"mettre à jour", r"actualiz", r"エクスポート", r"내보내", r"تصدير",
]


def _any(patterns, t):
    return any(re.search(p, t) for p in patterns)


def classify(text: str) -> str:
    t = " ".join((text or "").lower().split())
    if _any(PRESERVE, t):
        return "NOT_APPLICABLE"
    if _any(DELETE, t):
        return "DELETE"
    if _any(NON_DELETE, t):
        return "NOT_APPLICABLE"
    return "AMBIGUOUS"


def is_deletion(text: str) -> bool:
    """True if the request authorizes deletion; False means NOT_APPLICABLE."""
    return classify(text) != "NOT_APPLICABLE"
