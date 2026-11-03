"""Minimal MSVC (x64) symbol demangler.

Types are rendered in the spelling LeviLamina headers use (``int64``, ``uchar``,
``std::string``, east const, no ``class``/``struct`` keywords) so that they can be
compared with header declarations directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class DemangleError(Exception):
    pass


BASIC_TYPES = {
    "C": "schar",
    "D": "char",
    "E": "uchar",
    "F": "short",
    "G": "ushort",
    "H": "int",
    "I": "uint",
    "J": "long",
    "K": "ulong",
    "M": "float",
    "N": "double",
    "O": "long double",
    "X": "void",
}

EXTENDED_TYPES = {
    "D": "schar",
    "E": "uchar",
    "F": "short",
    "G": "ushort",
    "H": "int",
    "I": "uint",
    "J": "int64",
    "K": "uint64",
    "L": "__int128",
    "M": "unsigned __int128",
    "N": "bool",
    "Q": "char8_t",
    "S": "char16_t",
    "U": "char32_t",
    "W": "wchar_t",
}

OPERATORS = {
    "2": "operator new",
    "3": "operator delete",
    "4": "operator=",
    "5": "operator>>",
    "6": "operator<<",
    "7": "operator!",
    "8": "operator==",
    "9": "operator!=",
    "A": "operator[]",
    "C": "operator->",
    "D": "operator*",
    "E": "operator++",
    "F": "operator--",
    "G": "operator-",
    "H": "operator+",
    "I": "operator&",
    "J": "operator->*",
    "K": "operator/",
    "L": "operator%",
    "M": "operator<",
    "N": "operator<=",
    "O": "operator>",
    "P": "operator>=",
    "Q": "operator,",
    "R": "operator()",
    "S": "operator~",
    "T": "operator^",
    "U": "operator|",
    "V": "operator&&",
    "W": "operator||",
    "X": "operator*=",
    "Y": "operator+=",
    "Z": "operator-=",
}

UNDERSCORE_OPERATORS = {
    "0": "operator/=",
    "1": "operator%=",
    "2": "operator>>=",
    "3": "operator<<=",
    "4": "operator&=",
    "5": "operator|=",
    "6": "operator^=",
    "U": "operator new[]",
    "V": "operator delete[]",
}

DOUBLE_UNDERSCORE_OPERATORS = {
    "L": "operator co_await",
    "M": "operator<=>",
}

# Function access codes: (static, virtual, has this-qualifiers)
FUNCTION_CODES = {}
for _codes, _kind in (("ABIJQR", "member"), ("CDKLST", "static"), ("EFMNUV", "virtual"), ("GHOPWX", "thunk")):
    for _c in _codes:
        FUNCTION_CODES[_c] = _kind
FUNCTION_CODES["Y"] = FUNCTION_CODES["Z"] = "global"

STRING_TEMPLATES = {"char": "string", "wchar_t": "wstring", "char8_t": "u8string", "char16_t": "u16string", "char32_t": "u32string"}
DEFAULT_TEMPLATE_ARGS = ("std::allocator<", "std::char_traits<", "std::default_delete<", "std::less<", "std::hash<", "std::equal_to<")


@dataclass
class Symbol:
    kind: str  # "function", "data" or "vftable"
    scope: list[str]  # rendered scope components, outermost first
    name: str  # unqualified name, without template arguments
    special: str | None = None  # "ctor", "dtor" or None
    params: list[str] = field(default_factory=list)
    const: bool = False
    static: bool = False
    virtual: bool = False
    vftable_bases: list[str] = field(default_factory=list)


def _apply_cv(t: str, cv: str) -> str:
    if cv in "AQ":
        return t
    if cv in "BR":
        return t + " const"
    if cv in "CS":
        return t + " volatile"
    if cv in "DT":
        return t + " const volatile"
    raise DemangleError(f"unknown cv qualifier {cv!r}")


def _render_component(outer: list[tuple], base: str, args: tuple | None) -> str:
    if args is None:
        return base
    in_std = [c[0] for c in outer] == ["std"]
    if in_std and base in ("basic_string", "basic_string_view") and args and args[0] in STRING_TEMPLATES:
        return STRING_TEMPLATES[args[0]] + ("_view" if base.endswith("view") else "")
    args = list(args)
    if in_std:
        while len(args) > 1 and args[-1].startswith(DEFAULT_TEMPLATE_ARGS):
            args.pop()
    return f"{base}<{', '.join(args)}>"


def _render_scope(comps: list[tuple]) -> list[str]:
    """Renders components given outermost first."""
    return [_render_component(comps[:i], *c) for i, c in enumerate(comps)]


class _Parser:
    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.names: list[tuple] = []
        self.types: list[str] = []

    def peek(self, n: int = 1) -> str:
        return self.s[self.i : self.i + n]

    def eat(self, t: str) -> bool:
        if self.s.startswith(t, self.i):
            self.i += len(t)
            return True
        return False

    def expect(self, t: str) -> None:
        if not self.eat(t):
            raise DemangleError(f"expected {t!r} at offset {self.i}")

    def next(self) -> str:
        if self.i >= len(self.s):
            raise DemangleError("unexpected end of symbol")
        c = self.s[self.i]
        self.i += 1
        return c

    def number(self) -> int:
        neg = self.eat("?")
        c = self.next()
        if c.isdigit():
            v = int(c) + 1
        else:
            v = 0
            while c != "@":
                if not "A" <= c <= "P":
                    raise DemangleError("bad encoded number")
                v = v * 16 + ord(c) - ord("A")
                c = self.next()
        return -v if neg else v

    def memo_name(self, comp: tuple) -> None:
        if comp not in self.names and len(self.names) < 10:
            self.names.append(comp)

    def memo_type(self, t: str) -> None:
        if len(self.types) < 10:
            self.types.append(t)

    def simple_name(self) -> str:
        j = self.s.find("@", self.i)
        if j < 0:
            raise DemangleError("unterminated name")
        name = self.s[self.i : j]
        self.i = j + 1
        return name

    def operator_name(self) -> tuple[str, str | None]:
        """Parses the code following '?' at the start of a symbol name."""
        if self.eat("0"):
            return "", "ctor"
        if self.eat("1"):
            return "", "dtor"
        if self.eat("B"):
            return "", "conversion"
        if self.eat("__"):
            c = self.next()
            if c in DOUBLE_UNDERSCORE_OPERATORS:
                return DOUBLE_UNDERSCORE_OPERATORS[c], None
            if c == "K":
                return "operator\"\"" + self.simple_name(), None
            raise DemangleError(f"unsupported special name ??__{c}")
        if self.eat("_"):
            c = self.next()
            if c == "7":
                return "", "vftable"
            if c in UNDERSCORE_OPERATORS:
                return UNDERSCORE_OPERATORS[c], None
            raise DemangleError(f"unsupported special name ??_{c}")
        c = self.next()
        if c in OPERATORS:
            return OPERATORS[c], None
        raise DemangleError(f"unknown operator code {c!r}")

    def template_name(self) -> tuple:
        saved = self.names, self.types
        self.names, self.types = [], []
        if self.eat("?"):
            base, special = self.operator_name()
            if special:
                raise DemangleError("unsupported templated special member")
        else:
            base = self.simple_name()
            self.memo_name((base, None))
        args = self.template_args()
        self.names, self.types = saved
        return base, args

    def template_args(self) -> tuple:
        args = []
        while not self.eat("@"):
            if self.eat("$$V") or self.eat("$$$V") or self.eat("$$Z") or self.eat("$S"):
                continue
            if self.eat("$0"):
                args.append(str(self.number()))
            elif self.eat("$1"):
                args.append("&" + "::".join(self.symbol().scope_and_name()))
            elif self.eat("$$Y"):
                args.append("::".join(self.qualified_name()))
            elif self.peek() == "$" and self.peek(2) != "$$":
                raise DemangleError("unsupported template argument")
            elif self.peek().isdigit():
                args.append(self.types[int(self.next())])
            else:
                start = self.i
                t = self.type()
                if self.i - start > 1:
                    self.memo_type(t)
                args.append(t)
        return tuple(args)

    def name_component(self) -> tuple:
        c = self.peek()
        if not c:
            raise DemangleError("unexpected end of name")
        if c.isdigit():
            self.i += 1
            idx = int(c)
            if idx >= len(self.names):
                raise DemangleError("bad name back reference")
            return self.names[idx]
        if self.eat("?$"):
            comp = self.template_name()
            self.memo_name(comp)
            return comp
        if self.eat("?A"):
            self.simple_name()
            comp = ("`anonymous namespace'", None)
            self.memo_name(comp)
            return comp
        if c == "?":
            raise DemangleError("locally scoped names are not supported")
        comp = (self.simple_name(), None)
        self.memo_name(comp)
        return comp

    def qualified_comps(self, first: tuple | None = None) -> list[tuple]:
        comps = [first] if first is not None else [self.name_component()]
        while not self.eat("@"):
            comps.append(self.name_component())
        comps.reverse()
        return comps

    def qualified_name(self) -> list[str]:
        return _render_scope(self.qualified_comps())

    def function_type(self) -> tuple[str, list[str]]:
        self.next()  # calling convention
        ret = self.return_type()
        params = self.params()
        self.eat("_E") or self.eat("Z")
        return ret, params

    def return_type(self) -> str:
        if self.eat("@"):
            return ""
        if self.eat("?"):
            cv = self.next()
            return _apply_cv(self.type(), cv)
        return self.type()

    def params(self) -> list[str]:
        if self.eat("X"):
            return []
        ps = []
        while True:
            if self.eat("@"):
                break
            if self.eat("Z"):
                ps.append("...")
                return ps
            c = self.peek()
            if c.isdigit():
                self.i += 1
                if int(c) >= len(self.types):
                    raise DemangleError("bad type back reference")
                ps.append(self.types[int(c)])
                continue
            start = self.i
            t = self.type()
            if self.i - start > 1:
                self.memo_type(t)
            ps.append(t)
        return ps

    def pointer(self, suffix: str, ptr_cv: str) -> str:
        while self.peek() in ("E", "I", "F") and self.peek():
            self.i += 1
        if self.eat("6"):
            ret, params = self.function_type()
            return f"{ret}({suffix.strip()})({', '.join(params)})"
        if self.peek() == "8":
            raise DemangleError("member function pointers are not supported")
        cv = self.next()
        inner = self.type()
        return _apply_cv(inner, cv) + suffix + ptr_cv

    def type(self) -> str:
        c = self.peek()
        if not c:
            raise DemangleError("unexpected end of type")
        if c in BASIC_TYPES:
            self.i += 1
            return BASIC_TYPES[c]
        if c == "_":
            self.i += 1
            e = self.next()
            if e not in EXTENDED_TYPES:
                raise DemangleError(f"unknown extended type _{e}")
            return EXTENDED_TYPES[e]
        if c in "TUV":
            self.i += 1
            return "::".join(self.qualified_name())
        if c == "W":
            self.i += 2
            return "::".join(self.qualified_name())
        if c in "PQRS":
            self.i += 1
            return self.pointer("*", {"P": "", "Q": " const", "R": " volatile", "S": " const volatile"}[c])
        if c in "AB":
            self.i += 1
            return self.pointer("&", "")
        if self.eat("$$Q") or self.eat("$$R"):
            return self.pointer("&&", "")
        if self.eat("$$A6"):
            ret, params = self.function_type()
            return f"{ret}({', '.join(params)})"
        if self.eat("$$T"):
            return "std::nullptr_t"
        if self.eat("$$C"):
            cv = self.next()
            return _apply_cv(self.type(), cv)
        if c == "?":
            self.i += 1
            cv = self.next()
            return _apply_cv(self.type(), cv)
        if c == "Y":
            self.i += 1
            dims = [self.number() for _ in range(self.number())]
            return self.type() + "".join(f"[{d}]" for d in dims)
        raise DemangleError(f"unsupported type code {c!r}")

    def symbol(self) -> "_Parsed":
        self.expect("?")
        special = None
        if self.eat("?$"):
            first = self.template_name()
            self.memo_name(first)
        elif self.eat("?"):
            op, special = self.operator_name()
            first = (op, None)
        else:
            first = (self.simple_name(), None)
            self.memo_name(first)
        if special in ("ctor", "dtor", "conversion", "vftable"):
            comps = self.qualified_comps()
            if not comps:
                raise DemangleError("special member without a class")
            name_comp = None
        else:
            comps = self.qualified_comps(first)
            name_comp = comps.pop()
        return _Parsed(self, comps, name_comp, special)


class _Parsed:
    def __init__(self, p: _Parser, comps: list[tuple], name_comp: tuple | None, special: str | None):
        self.scope = _render_scope(comps)
        if special == "ctor":
            name = comps[-1][0]
        elif special == "dtor":
            name = "~" + comps[-1][0]
        elif special == "conversion":
            name = "operator"
        elif special == "vftable":
            name = "$vftable"
        else:
            name = name_comp[0]
        self.sym = Symbol(kind="function", scope=self.scope, name=name, special=special if special in ("ctor", "dtor") else None)
        self._encoding(p, special)

    def scope_and_name(self) -> list[str]:
        return [*self.scope, self.sym.name]

    def _encoding(self, p: _Parser, special: str | None) -> None:
        sym = self.sym
        c = p.next()
        if special == "vftable":
            if c not in "67":
                raise DemangleError("bad vftable encoding")
            sym.kind = "vftable"
            p.next()  # cv
            while not p.eat("@"):
                sym.vftable_bases.append("::".join(p.qualified_name()))
            return
        if c in "01234":
            sym.kind = "data"
            sym.static = c in "012"
            p.type()
            while p.peek() in ("E", "I", "F") and p.peek():
                p.i += 1
            p.next()  # cv
            return
        kind = FUNCTION_CODES.get(c)
        if kind is None:
            raise DemangleError(f"unsupported symbol kind {c!r}")
        if kind == "thunk":
            p.number()
        sym.static = kind == "static"
        sym.virtual = kind in ("virtual", "thunk")
        if kind in ("member", "virtual", "thunk"):
            while p.peek() and p.peek() in "EIFGH":
                p.i += 1
            sym.const = p.next() in "BD"
        p.next()  # calling convention
        ret = p.return_type()
        if special == "conversion":
            sym.name = "operator " + ret
        sym.params = p.params()


def demangle(symbol: str) -> Symbol:
    """Demangles an MSVC symbol; raises DemangleError when it is malformed or unsupported."""
    try:
        return _Parser(symbol).symbol().sym
    except (IndexError, KeyError, ValueError) as e:
        raise DemangleError(str(e)) from e
