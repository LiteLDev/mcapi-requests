"""Validates a request issue against LeviLamina headers.

Usage: check_request.py <LeviLamina checkout> <report.md>
The issue body is read from the ISSUE_BODY environment variable.
Exits with 1 when the request is invalid.
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from msvc_demangle import DemangleError, Symbol, demangle

HEADER_DIRS = ("src/mc", "src-client/mc", "src-server/mc")
MAX_JUSTIFICATION_TOKENS = 200
IMPLEMENTED_MACROS = {"MCAPI", "MCFOLD", "MCTAPI"}
NOT_IMPLEMENTED_MACRO = "MCNAPI"

TYPE_WORDS = {
    "const", "volatile", "int", "char", "short", "long", "unsigned", "signed", "bool", "float", "double", "void",
    "int64", "uint64", "uchar", "schar", "ushort", "uint", "ulong", "size_t", "wchar_t", "char8_t", "char16_t",
    "char32_t", "auto",
}  # fmt: skip

TYPE_ALIASES = [
    (r"\bunsigned\s+__int64\b", "uint64"),
    (r"\b__int64\b", "int64"),
    (r"\bunsigned\s+char\b", "uchar"),
    (r"\bsigned\s+char\b", "schar"),
    (r"\bunsigned\s+short\b", "ushort"),
    (r"\bunsigned\s+int\b", "uint"),
    (r"\bunsigned\s+long\b", "ulong"),
    (r"\bunsigned\b", "uint"),
    (r"\b(?:std::)?size_t\b", "uint64"),
]


def canon(t: str) -> str:
    """Canonical spelling of a C++ type, used to compare header and demangled types."""
    t = re.sub(r"\b(?:class|struct|enum|union|typename)\s+", "", t)
    t = re.sub(r"(^|[^\w>])::", r"\1", t)
    for pattern, repl in TYPE_ALIASES:
        t = re.sub(pattern, repl, t)
    t = re.sub(r"\s+", " ", t).strip()
    return re.sub(r"\s*([^\w\s$])\s*", r"\1", t)


def strip_template_args(t: str) -> str:
    out, depth = [], 0
    for ch in t:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(depth - 1, 0)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def loose(t: str) -> str:
    """Looser key: template arguments and namespaces are dropped."""
    return re.sub(r"\w+::", "", strip_template_args(t))


def split_top_level(s: str, sep: str = ",") -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


# ---------------------------------------------------------------------------
# Header index
# ---------------------------------------------------------------------------


@dataclass
class Decl:
    name: str
    params: list[str]
    const: bool
    static: bool
    macro: str
    file: str


@dataclass
class HeaderIndex:
    scopes: set[str] = field(default_factory=set)
    classes: dict[str, bool] = field(default_factory=dict)  # full name -> has unknown members
    decls: dict[str, list[Decl]] = field(default_factory=lambda: defaultdict(list))


COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
PREPROCESSOR_RE = re.compile(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", re.M)
TEMPLATE_PREFIX_RE = re.compile(r"^\s*template\s*<")
ACCESS_RE = re.compile(r"^\s*(?:(?:public|protected|private)\s*:(?!:)\s*)+")
NAMESPACE_RE = re.compile(r"^\s*(?:inline\s+)?namespace\s+([\w:]+)\s*$")
RECORD_RE = re.compile(r"^\s*(?:(?:enum\s+)?(class|struct|union))\b(.*)$", re.S)
MACRO_RE = re.compile(r"^\s*(MCAPI|MCNAPI|MCFOLD|MCTAPI)\b(.*)$", re.S)


def strip_template_prefix(s: str) -> str:
    while TEMPLATE_PREFIX_RE.match(s):
        start = s.index("<")
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "<":
                depth += 1
            elif s[i] == ">":
                depth -= 1
                if depth == 0:
                    s = s[i + 1 :]
                    break
        else:
            return s
    return s


def record_name(rest: str) -> str | None:
    """Name of a class being defined, given the text after the class-key."""
    head = rest
    depth = 0
    for i, ch in enumerate(rest):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == ":" and depth == 0 and rest[i + 1 : i + 2] != ":" and rest[i - 1 : i] != ":":
            head = rest[:i]
            break
    head = re.sub(r"\[\[.*?\]\]", " ", head)
    head = re.sub(r"\bfinal\b", " ", head).strip()
    tokens = re.findall(r"[\w:]+(?:<.*>)?", head)
    return canon(tokens[-1]) if tokens else None


def parse_decl(stmt: str, file: str) -> Decl | None:
    m = MACRO_RE.match(stmt)
    if not m:
        return None
    macro, text = m.group(1), m.group(2)
    # Find the parameter list: the first '(' outside of template arguments, skipping operator().
    depth = 0
    paren = -1
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "<" and not re.search(r"operator\s*<*$", text[:i]):
            depth += 1
        elif ch == ">" and depth > 0 and not re.search(r"operator\s*[->]*$", text[:i]):
            depth -= 1
        elif ch == "(" and depth == 0:
            if re.search(r"\boperator\s*$", text[:i]):
                i += 2
                continue
            paren = i
            break
        i += 1
    if paren < 0:
        return None
    prefix = text[:paren].rstrip()
    op = re.search(r"\boperator\b.*$", prefix, re.S)
    if op:
        name = canon(op.group())
    else:
        nm = re.search(r"([~$\w]+)\s*(?:<.*>)?$", prefix, re.S)
        if not nm:
            return None
        name = nm.group(1)
    depth = 0
    for j in range(paren, len(text)):
        if text[j] in "(<[{":
            depth += 1
        elif text[j] in ")>]}":
            depth -= 1
            if depth == 0:
                break
    params_text = text[paren + 1 : j]
    tail = text[j + 1 :]
    params = []
    for p in split_top_level(params_text):
        p = split_top_level(p, "=")[0].strip()
        if not p or p == "void":
            continue
        pm = re.match(r"^(.*?[\w>*&\]\)])\s+([A-Za-z_]\w*)$", p, re.S)
        if pm and pm.group(2) not in TYPE_WORDS and not pm.group(1).rstrip().endswith("::"):
            p = pm.group(1)
        # Top-level const on a by-value parameter is not part of the mangled name.
        params.append(re.sub(r"(?<=[\w>])\s*\bconst$", "", canon(p)))
    return Decl(
        name=name,
        params=params,
        const=bool(re.match(r"\s*const\b", tail)),
        static=bool(re.search(r"\bstatic\b", prefix)),
        macro=macro,
        file=file,
    )


def index_file(path: Path, rel: str, index: HeaderIndex) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    text = COMMENT_RE.sub(" ", text)
    text = PREPROCESSOR_RE.sub(" ", text)

    # Each stack entry: ("ns", name) | ("class", full name) | ("anon", None) | ("opaque", None)
    stack: list[tuple[str, str | None]] = []

    def scope_name() -> str | None:
        """Qualified name of the current scope, or None inside an opaque block."""
        parts = []
        for kind, name in stack:
            if kind == "opaque":
                return None
            if kind in ("ns", "class"):
                parts.append(name)
        return "::".join(parts)

    def current_class() -> str | None:
        for kind, _ in reversed(stack):
            if kind == "anon":
                continue
            if kind == "class":
                return scope_name_upto_class()
            return None
        return None

    def scope_name_upto_class() -> str:
        parts = []
        last_class = max(i for i, (k, _) in enumerate(stack) if k == "class")
        for kind, name in stack[: last_class + 1]:
            if kind in ("ns", "class"):
                parts.append(name)
        return "::".join(parts)

    pos = 0
    for m in re.finditer(r"[{};]", text):
        stmt = text[pos : m.start()]
        pos = m.end()
        ch = m.group()
        if ch == "}":
            if stack:
                stack.pop()
            continue
        stmt = ACCESS_RE.sub("", stmt)
        stmt_nt = strip_template_prefix(stmt)
        if ch == "{":
            cur = scope_name()
            if cur is None:
                stack.append(("opaque", None))
                continue
            nm = NAMESPACE_RE.match(stmt_nt)
            if nm:
                stack.append(("ns", canon(nm.group(1))))
                index.scopes.add("::".join(filter(None, [cur, canon(nm.group(1))])))
                continue
            rm = RECORD_RE.match(stmt_nt)
            if rm and not re.match(r"^\s*enum\b", stmt_nt) and "(" not in rm.group(2).split(":")[0]:
                name = record_name(rm.group(2))
                if name is None:
                    stack.append(("anon", None))
                    continue
                stack.append(("class", name))
                full = scope_name()
                index.scopes.add(full)
                index.classes.setdefault(full, False)
                continue
            stack.append(("opaque", None))
            continue
        # ';' terminates a declaration
        cur = scope_name()
        if cur is None:
            continue
        if "UntypedStorage<" in stmt:
            owner = current_class()
            if owner:
                index.classes[owner] = True
        decl = parse_decl(stmt_nt, rel)
        if decl:
            index.decls[cur].append(decl)


def build_index(root: Path) -> HeaderIndex:
    index = HeaderIndex()
    for d in HEADER_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.h")):
            index_file(path, path.relative_to(root).as_posix(), index)
    return index


# ---------------------------------------------------------------------------
# Issue parsing
# ---------------------------------------------------------------------------


def parse_issue(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current = None
    lines: list[str] = []
    for line in body.replace("\r\n", "\n").split("\n"):
        m = re.match(r"^###\s+(.+?)\s*$", line)
        if m:
            if current is not None:
                fields[current] = "\n".join(lines).strip()
            current, lines = m.group(1), []
        elif current is not None:
            lines.append(line)
    if current is not None:
        fields[current] = "\n".join(lines).strip()
    return {k: ("" if v == "_No response_" else v) for k, v in fields.items()}


def field_lines(value: str) -> list[str]:
    out = []
    for line in value.splitlines():
        line = line.strip().strip("`").strip()
        if not line or line == "text":
            continue
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def count_tokens(text: str) -> int:
    import tiktoken

    return len(tiktoken.get_encoding("o200k_base").encode(text))


def check_class(line: str, index: HeaderIndex) -> str | None:
    name = canon(re.sub(r"^\s*(?:class|struct|union)\s+", "", line))
    if name not in index.classes:
        candidates = sorted(c for c in index.classes if c.rsplit("::", 1)[-1] == name.rsplit("::", 1)[-1])
        hint = f" Did you mean {', '.join(f'`{c}`' for c in candidates[:5])}?" if candidates else ""
        return f"`{line}`: no definition of this class was found in LeviLamina headers.{hint}"
    if not index.classes[name]:
        return f"`{line}`: all member variables of this class are already available."
    return None


def candidate_names(sym: Symbol) -> list[str]:
    if sym.kind == "vftable":
        if not sym.vftable_bases:
            return ["$vftable"]
        names = [b.rsplit("::", 1)[-1] for b in sym.vftable_bases]
        return ["$vftableFor" + "".join(names), "$vftableFor" + names[-1]]
    if sym.special == "ctor":
        return [sym.name, "$ctor"]
    if sym.special == "dtor":
        return [sym.name, "$dtor"]
    name = canon(sym.name if sym.name.startswith("operator") else strip_template_args(sym.name))
    return [name, "$" + name]


def score(decl: Decl, params: list[str]) -> int:
    s = 0
    for a, b in zip(decl.params, params):
        if a == b:
            s += 2
        elif loose(a) == loose(b):
            s += 1
    return s


def check_symbol(line: str, index: HeaderIndex) -> str | None:
    symbol = line[len("__imp_") :] if line.startswith("__imp_") else line
    if not symbol.startswith("?"):
        return f"`{line}`: not an MSVC mangled symbol. Paste the symbol from the linker error, one per line."
    try:
        sym = demangle(symbol)
    except DemangleError as e:
        return f"`{line}`: failed to demangle this symbol ({e})."
    scope = "::".join(sym.scope)
    display = "::".join([*sym.scope, sym.name])
    if scope and scope not in index.scopes:
        alt = canon(strip_template_args(scope))
        if alt not in index.scopes:
            return f"`{line}`: `{scope}` is not declared in LeviLamina headers, so it can't be made an MCAPI."
        scope = alt
    names = candidate_names(sym)
    decls = [d for d in index.decls.get(scope, []) if strip_template_args(d.name) in names]
    if not decls:
        return f"`{line}`: `{display}` is not declared in LeviLamina headers, so it can't be made an MCAPI."
    params = [canon(p) for p in sym.params]
    if sym.kind == "function":
        matches = [d for d in decls if len(d.params) == len(params) and d.const == sym.const]
        if scope in index.classes and sym.special is None:
            matches = [d for d in matches if d.static == sym.static or d.name.startswith("$")]
    else:
        matches = [d for d in decls if not d.params]
    if not matches:
        return f"`{line}`: no declaration of `{display}` in LeviLamina headers matches this signature."
    best = max(score(d, params) for d in matches)
    best_matches = [d for d in matches if score(d, params) == best]
    if any(d.macro == NOT_IMPLEMENTED_MACRO for d in best_matches):
        return None
    return f"`{line}`: `{display}` is already an MCAPI in LeviLamina (`{best_matches[0].file}`)."


def main() -> int:
    root, report_path = Path(sys.argv[1]), Path(sys.argv[2])
    fields = parse_issue(os.environ.get("ISSUE_BODY", ""))
    errors: list[str] = []

    missing = [f for f in ("Mod", "Classes", "Symbols", "Justification") if f not in fields]
    if missing:
        errors.append(f"The issue was not created from the Request template (missing {', '.join(missing)}).")
    else:
        if not fields["Mod"]:
            errors.append("**Mod** is required.")
        justification = fields["Justification"]
        if not justification:
            errors.append("**Justification** is required.")
        else:
            tokens = count_tokens(justification)
            if tokens > MAX_JUSTIFICATION_TOKENS:
                errors.append(
                    f"**Justification** is {tokens} tokens long; keep it within {MAX_JUSTIFICATION_TOKENS} tokens."
                )
        classes = field_lines(fields["Classes"])
        symbols = field_lines(fields["Symbols"])
        if not classes and not symbols:
            errors.append("Request at least one class or symbol.")
        if classes or symbols:
            index = build_index(root)
            for line in classes:
                if err := check_class(line, index):
                    errors.append("**Classes** " + err)
            for line in symbols:
                if err := check_symbol(line, index):
                    errors.append("**Symbols** " + err)

    if errors:
        report = "### ❌ Request check failed\n\nPlease edit the issue to fix the following:\n\n"
        report += "\n".join(f"- {e}" for e in errors) + "\n"
    else:
        report = "### ✅ Request check passed\n"
    report_path.write_text(report, encoding="utf-8")
    print(report)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
