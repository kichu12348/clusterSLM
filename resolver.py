from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from models import FileParseResult, GraphEdge, ImportRecord, SymbolNode

# Builtin functions and ubiquitous container/string methods that are not security sinks
PYTHON_BUILTINS = {
    "len",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "isinstance",
    "issubclass",
    "print",
    "range",
    "enumerate",
    "zip",
    "min",
    "max",
    "sum",
    "any",
    "all",
    "sorted",
    "reversed",
    "abs",
    "round",
    "getattr",
    "hasattr",
    "setattr",
    "super",
    "type",
    "id",
    "hex",
    "ord",
    "chr",
}

CONTAINER_NOISE_METHODS = {
    "get",
    "setdefault",
    "keys",
    "values",
    "items",
    "pop",
    "update",
    "append",
    "extend",
    "insert",
    "remove",
    "clear",
    "copy",
    "strip",
    "lstrip",
    "rstrip",
    "split",
    "rsplit",
    "join",
    "lower",
    "upper",
    "startswith",
    "endswith",
    "replace",
    "encode",
    "decode",
    "format",
    "isoformat",
    "to_dict",
    "isprintable",
    "isalnum",
    "isalpha",
    "isdigit",
    "hexdigest",
    "hex",
}


class RepositoryResolver:
    """
    Resolves imports, class inheritance, and function/method call sites across
    a parsed repository with explicit confidence levels.
    """

    def __init__(self, parse_results: List[FileParseResult], repo_root: Path):
        self.parse_results = [r for r in parse_results if not r.parse_error]
        self.repo_root = repo_root.resolve()
        self.root_pkg_name = self.repo_root.name

        # Master dictionary of all internal SymbolNodes by their canonical FQN (id)
        self.symbols: Dict[str, SymbolNode] = {}
        # Maps module aliases (both "api.controllers" and "Test.api.controllers") -> canonical module_name
        self.module_aliases: Dict[str, str] = {}
        # Maps each canonical module_name -> {local_bound_alias: target_canonical_symbol_id}
        self.module_scopes: Dict[str, Dict[str, str]] = {}
        # Maps short method/function name -> list of canonical SymbolNode IDs in the repo
        self.short_name_index: Dict[str, List[str]] = {}

        self.edges: List[GraphEdge] = []
        self._seen_edges: Set[Tuple[str, str, str, int]] = set()

        self._build_indices()

    # ------------------------------------------------------------------
    # Pass 1: Indexing & Import Scope Construction
    # ------------------------------------------------------------------
    def _build_indices(self):
        for res in self.parse_results:
            mod = res.module_name
            self.module_aliases[mod] = mod
            self.module_aliases[f"{self.root_pkg_name}.{mod}"] = mod
            self.module_scopes[mod] = {}

            for sym_id, sym in res.symbols.items():
                self.symbols[sym_id] = sym
                # Bind top-level classes and functions in their own module's scope
                if sym.parent_id == mod:
                    self.module_scopes[mod][sym.name] = sym_id
                if sym.kind in ("function", "method", "class"):
                    self.short_name_index.setdefault(sym.name, []).append(sym_id)

        # Resolve imports for each file and populate module_scopes + IMPORTS / DEFINES edges
        for res in self.parse_results:
            mod = res.module_name
            for sym_id, sym in res.symbols.items():
                if sym.parent_id and sym.parent_id in self.symbols:
                    self._add_edge(
                        sym.parent_id,
                        sym_id,
                        kind="DEFINES",
                        confidence="EXACT",
                        line=sym.start_line,
                        weight=2.0,
                    )

            for imp in res.imports:
                target_sym_id = self._resolve_import_target(mod, imp)
                if target_sym_id:
                    self.module_scopes[mod][imp.alias] = target_sym_id
                    # Add module-to-module or module-to-symbol IMPORTS edge
                    target_mod = self.symbols[target_sym_id].module_name
                    if target_mod != mod:
                        self._add_edge(
                            mod,
                            target_mod,
                            kind="IMPORTS",
                            confidence="EXACT",
                            line=imp.line,
                            weight=1.5,
                        )

        # Resolve class inheritance (INHERITS edges)
        for sym in self.symbols.values():
            if sym.kind == "class":
                for base_expr in sym.bases:
                    base_id = self._resolve_symbol_in_module(sym.module_name, base_expr)
                    if base_id and base_id in self.symbols:
                        self._add_edge(
                            sym.id,
                            base_id,
                            kind="INHERITS",
                            confidence="EXACT",
                            line=sym.start_line,
                            weight=2.5,
                        )

    def _resolve_import_target(
        self, source_module: str, imp: ImportRecord
    ) -> Optional[str]:
        """Resolves an ImportRecord to a canonical internal SymbolNode.id if it belongs to the repo."""
        if imp.level > 0:
            parts = source_module.split(".")
            base_parts = (
                parts[: len(parts) - imp.level + 1] if imp.level <= len(parts) else []
            )
            raw_mod = ".".join(base_parts + ([imp.module] if imp.module else []))
        else:
            raw_mod = imp.module

        canonical_mod = self.module_aliases.get(raw_mod)

        if imp.imported_name is None:
            # e.g., `import Test.auth.authenticator as auth`
            return canonical_mod

        # e.g., `from Test.auth.authenticator import Authenticator`
        if canonical_mod:
            candidate_sym = f"{canonical_mod}.{imp.imported_name}"
            if candidate_sym in self.symbols:
                return candidate_sym
            # Could also be importing a submodule: `from Test.api import controllers`
            submod_candidate = f"{canonical_mod}.{imp.imported_name}"
            if submod_candidate in self.module_aliases:
                return self.module_aliases[submod_candidate]

        # Check if raw_mod + imported_name forms a known module alias
        combined = f"{raw_mod}.{imp.imported_name}".strip(".")
        if combined in self.module_aliases:
            return self.module_aliases[combined]

        return None

    def _resolve_symbol_in_module(self, module_name: str, expr: str) -> Optional[str]:
        """Resolves a type or symbol name (`Authenticator` or `auth.Authenticator`) within a module."""
        scope = self.module_scopes.get(module_name, {})
        if expr in scope:
            return scope[expr]

        parts = expr.split(".")
        if parts[0] in scope:
            base_id = scope[parts[0]]
            candidate = ".".join([base_id] + parts[1:])
            if candidate in self.symbols:
                return candidate

        # Fallback: if there is a unique class with this exact name in the repo
        candidates = [
            cid
            for cid in self.short_name_index.get(expr, [])
            if self.symbols[cid].kind == "class"
        ]
        if len(candidates) == 1:
            return candidates[0]
        return None

    # ------------------------------------------------------------------
    # Pass 2: Call Graph Resolution
    # ------------------------------------------------------------------
    def resolve_all_calls(self) -> List[GraphEdge]:
        for sym in self.symbols.values():
            for call in sym.calls:
                self._resolve_single_call(sym, call)
        self._propagate_dynamic_returns()
        return self.edges

    def _propagate_dynamic_returns(self):
        """
        If a symbol calls an internal helper that returns a dynamic string
        (e.g., `build_audit_filter_query`), marks subsequent calls in the same
        symbol that consume local variables (e.g., `execute_raw_query(query_sql)`)
        as `is_dynamic_arg = True`.
        """
        for sym in self.symbols.values():
            calls_dynamic_helper = False
            for call in sym.calls:
                if any(
                    self.symbols.get(tid) and self.symbols[tid].returns_dynamic
                    for tid in call.resolved_targets
                ):
                    calls_dynamic_helper = True
                    sym.dynamic_locals.append(
                        f"L{call.line}: <return from {call.callee_expr}> (returns_dynamic=True)"
                    )
                elif calls_dynamic_helper and call.args_preview:
                    # A subsequent call in the same function after a dynamic-returning helper
                    call.is_dynamic_arg = True
                    sym.returns_dynamic = True

    def _resolve_single_call(self, caller: SymbolNode, call):
        expr = call.callee_expr
        parts = expr.split(".")
        mod_scope = self.module_scopes.get(caller.module_name, {})
        enclosing_class = self._get_enclosing_class(caller)

        # --------------------------------------------------------------
        # Case 1: Bare call `foo()` or `ClassName()`
        # --------------------------------------------------------------
        if len(parts) == 1:
            name = parts[0]
            if name in PYTHON_BUILTINS or name in CONTAINER_NOISE_METHODS:
                call.resolution_status = "BUILTIN_NOISE"
                return

            if name == "cls" and enclosing_class is not None:
                self._record_resolved_call(
                    caller, call, [enclosing_class.id], "EXACT", weight=2.5
                )
                return

            if name in mod_scope:
                target_id = mod_scope[name]
                self._record_resolved_call(
                    caller, call, [target_id], "EXACT", weight=2.0
                )
                return

            # Unimported bare call matching a unique function/class in repo
            candidates = [
                sid
                for sid in self.short_name_index.get(name, [])
                if self.symbols[sid].kind in ("function", "class")
            ]
            if len(candidates) == 1:
                self._record_resolved_call(
                    caller, call, candidates, "HEURISTIC", weight=1.0
                )
                return

            call.resolution_status = "EXTERNAL"
            return

        # --------------------------------------------------------------
        # Case 2: `self.method()` or `self.attr.method()`
        # --------------------------------------------------------------
        if parts[0] in ("self", "cls") and enclosing_class is not None:
            # 2a: `self.method()`
            if len(parts) == 2:
                method_name = parts[1]
                target_id = self._find_method_on_class(enclosing_class.id, method_name)
                if target_id:
                    self._record_resolved_call(
                        caller, call, [target_id], "EXACT", weight=2.5
                    )
                    return

            # 2b: `self.attr.method()`
            elif len(parts) == 3:
                _, attr_name, method_name = parts
                attr_type_expr = enclosing_class.attribute_types.get(attr_name)
                if attr_type_expr:
                    target_cls_id = self._resolve_symbol_in_module(
                        caller.module_name, attr_type_expr
                    )
                    if target_cls_id:
                        target_method_id = self._find_method_on_class(
                            target_cls_id, method_name
                        )
                        if target_method_id:
                            self._record_resolved_call(
                                caller, call, [target_method_id], "EXACT", weight=2.5
                            )
                            return

        # --------------------------------------------------------------
        # Case 3: `<prefix>.<member>()` (Module alias, Class alias, or Typed Param/Local)
        # --------------------------------------------------------------
        if len(parts) == 2:
            prefix, member = parts

            # 3a: Prefix is an imported module or class (e.g., `Database.get_instance()`)
            if prefix in mod_scope:
                base_id = mod_scope[prefix]
                candidate = f"{base_id}.{member}"
                if candidate in self.symbols:
                    self._record_resolved_call(
                        caller, call, [candidate], "EXACT", weight=2.5
                    )
                    return

            # 3b: Prefix is a typed parameter or local variable (e.g., `session. is_expired()`)
            var_type_expr = caller.param_types.get(prefix)
            if var_type_expr:
                target_cls_id = self._resolve_symbol_in_module(
                    caller.module_name, var_type_expr
                )
                if target_cls_id:
                    target_method_id = self._find_method_on_class(target_cls_id, member)
                    if target_method_id:
                        self._record_resolved_call(
                            caller, call, [target_method_id], "EXACT", weight=2.0
                        )
                        return

        # --------------------------------------------------------------
        # Case 4: Heuristic / Ambiguous / Noise Fallback
        # --------------------------------------------------------------
        leaf_method = parts[-1]
        if leaf_method in CONTAINER_NOISE_METHODS or leaf_method in PYTHON_BUILTINS:
            call.resolution_status = "BUILTIN_NOISE"
            return

        # Check if any repository method matches `leaf_method`
        method_candidates = [
            sid
            for sid in self.short_name_index.get(leaf_method, [])
            if self.symbols[sid].kind == "method"
        ]
        if len(method_candidates) == 1:
            self._record_resolved_call(
                caller, call, method_candidates, "HEURISTIC", weight=1.0
            )
        elif len(method_candidates) > 1:
            self._record_resolved_call(
                caller, call, method_candidates, "AMBIGUOUS", weight=0.3
            )
        else:
            call.resolution_status = "EXTERNAL"

    def _find_method_on_class(self, class_id: str, method_name: str) -> Optional[str]:
        """Looks up a method on `class_id` or its resolved base classes."""
        direct = f"{class_id}.{method_name}"
        if direct in self.symbols:
            return direct

        cls_sym = self.symbols.get(class_id)
        if cls_sym:
            for base_expr in cls_sym.bases:
                base_id = self._resolve_symbol_in_module(cls_sym.module_name, base_expr)
                if base_id and base_id != class_id:
                    found = self._find_method_on_class(base_id, method_name)
                    if found:
                        return found
        return None

    def _get_enclosing_class(self, sym: SymbolNode) -> Optional[SymbolNode]:
        if sym.kind == "class":
            return sym
        if sym.parent_id and sym.parent_id in self.symbols:
            parent = self.symbols[sym.parent_id]
            if parent.kind == "class":
                return parent
        return None

    def _record_resolved_call(
        self,
        caller: SymbolNode,
        call,
        target_ids: List[str],
        confidence: str,
        weight: float,
    ):
        resolved_actual: List[str] = []
        for tid in target_ids:
            target_sym = self.symbols.get(tid)
            if not target_sym:
                continue
            # If calling a Class constructor (`Authenticator()`), link to `Authenticator.__init__` if defined
            if target_sym.kind == "class":
                init_id = f"{tid}.__init__"
                if init_id in self.symbols:
                    tid = init_id
            resolved_actual.append(tid)
            self._add_edge(
                caller.id,
                tid,
                kind="CALLS",
                confidence=confidence,
                line=call.line,
                weight=weight,
            )

        call.resolved_targets = resolved_actual
        call.resolution_status = confidence

    def _add_edge(
        self,
        source: str,
        target: str,
        kind: str,
        confidence: str,
        line: int,
        weight: float,
    ):
        if source == target:
            return
        key = (source, target, kind, line)
        if key not in self._seen_edges:
            self._seen_edges.add(key)
            self.edges.append(
                GraphEdge(
                    source=source,
                    target=target,
                    kind=kind,
                    confidence=confidence,
                    line=line,
                    weight=weight,
                )
            )
