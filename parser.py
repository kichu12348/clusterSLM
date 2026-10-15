import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from models import (
    CallSite,
    FileParseResult,
    GuardRecord,
    ImportRecord,
    SymbolNode,
)


def compute_module_name(file_path: Path, repo_root: Path) -> str:
    rel_path = file_path.relative_to(repo_root)
    parts = list(rel_path.parts)
    parts[-1] = parts[-1].removesuffix(".py")

    if parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()

    return ".".join(parts)


def format_numbered_source(lines: List[str], start_line: int, end_line: int) -> str:
    sliced = lines[start_line - 1 : end_line]
    return "\n".join(
        f"{line_no:4d} | {text}"
        for line_no, text in zip(range(start_line, end_line + 1), sliced)
    )


def safe_unparse(node: ast.AST, max_len: int = 120) -> str:
    try:
        text = ast.unparse(node).replace("\n", " ")
        if len(text) > max_len:
            return text[: max_len - 3] + "..."
        return text
    except Exception:
        return "<expr>"


def unwrap_type_annotation(annotation_node: Optional[ast.AST]) -> Optional[str]:
    if annotation_node is None:
        return None
    if isinstance(annotation_node, ast.Name):
        return annotation_node.id
    if isinstance(annotation_node, ast.Attribute):
        return safe_unparse(annotation_node)
    if isinstance(annotation_node, ast.Subscript):
        container = safe_unparse(annotation_node.value)
        if container in ("Optional", "typing.Optional"):
            return unwrap_type_annotation(annotation_node.slice)
        if container in ("Union", "typing.Union") and isinstance(
            annotation_node.slice, ast.Tuple
        ):
            for elt in annotation_node.slice.elts:
                unwrapped = unwrap_type_annotation(elt)
                if unwrapped and unwrapped != "None":
                    return unwrapped
    return None


def is_dynamic_expression(
    node: ast.AST, dynamic_var_names: Optional[Set[str]] = None
) -> bool:
    """
    Returns True if `node` uses string interpolation (f-string, %, +, .format, .join)
    OR references a local variable previously tainted by dynamic string construction.
    """
    dynamic_var_names = dynamic_var_names or set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.JoinedStr):
            return True
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr in ("format", "join"):
                return True
        if isinstance(sub, ast.Name) and sub.id in dynamic_var_names:
            return True
    return False


class ScopeAwareVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, module_name: str, source_lines: List[str]):
        self.rel_path = rel_path
        self.module_name = module_name
        self.source_lines = source_lines
        self.result = FileParseResult(file_path=rel_path, module_name=module_name)
        self.scope_stack: List[Tuple[str, str]] = []
        self.active_local_types: Dict[str, str] = {}
        self.active_dynamic_vars: Set[str] = set()

    @property
    def current_symbol_id(self) -> str:
        return self.scope_stack[-1][0]

    @property
    def current_symbol(self) -> SymbolNode:
        return self.result.symbols[self.current_symbol_id]

    def _enclosing_class_symbol(self) -> Optional[SymbolNode]:
        for sym_id, kind in reversed(self.scope_stack):
            if kind == "class":
                return self.result.symbols[sym_id]
        return None

    def visit_Module(self, node: ast.Module):
        end_line = len(self.source_lines) or 1
        doc = ast.get_docstring(node)
        doc_summary = doc.strip().splitlines()[0] if doc else None

        mod_symbol = SymbolNode(
            id=self.module_name,
            name=self.module_name.split(".")[-1],
            kind="module",
            file_path=self.rel_path,
            module_name=self.module_name,
            parent_id=None,
            start_line=1,
            end_line=end_line,
            signature=f"module {self.module_name}",
            docstring_summary=doc_summary,
            source_code="",
        )
        self.result.symbols[self.module_name] = mod_symbol
        self.scope_stack.append((self.module_name, "module"))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef):
        parent_id, _ = self.scope_stack[-1]
        class_id = f"{parent_id}.{node.name}"

        bases = [safe_unparse(b) for b in node.bases]
        decorators = [f"@{safe_unparse(d)}" for d in node.decorator_list]
        base_str = f"({', '.join(bases)})" if bases else ""
        signature = f"class {node.name}{base_str}"

        doc = ast.get_docstring(node)
        doc_summary = doc.strip().splitlines()[0] if doc else None

        start_line = (
            node.decorator_list[0].lineno if node.decorator_list else node.lineno
        )
        end_line = getattr(node, "end_lineno", node.lineno)

        cls_symbol = SymbolNode(
            id=class_id,
            name=node.name,
            kind="class",
            file_path=self.rel_path,
            module_name=self.module_name,
            parent_id=parent_id,
            start_line=start_line,
            end_line=end_line,
            signature=signature,
            decorators=decorators,
            bases=bases,
            docstring_summary=doc_summary,
            source_code=format_numbered_source(self.source_lines, start_line, end_line),
        )
        self.result.symbols[class_id] = cls_symbol

        self.scope_stack.append((class_id, "class"))
        self.generic_visit(node)
        self.scope_stack.pop()

    def _visit_function_or_method(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool
    ):
        parent_id, parent_kind = self.scope_stack[-1]
        func_id = f"{parent_id}.{node.name}"
        kind = "method" if parent_kind == "class" else "function"

        decorators = [f"@{safe_unparse(d)}" for d in node.decorator_list]
        args_str = safe_unparse(node.args, max_len=240)
        ret_str = f" -> {safe_unparse(node.returns)}" if node.returns else ""
        prefix = "async def" if is_async else "def"
        signature = f"{prefix} {node.name}({args_str}){ret_str}"

        params: List[str] = []
        param_types: Dict[str, str] = {}
        for arg in node.args.args:
            if arg.arg in ("self", "cls"):
                continue
            params.append(arg.arg)
            unwrapped = unwrap_type_annotation(arg.annotation)
            if unwrapped:
                param_types[arg.arg] = unwrapped

        doc = ast.get_docstring(node)
        doc_summary = doc.strip().splitlines()[0] if doc else None

        start_line = (
            node.decorator_list[0].lineno if node.decorator_list else node.lineno
        )
        end_line = getattr(node, "end_lineno", node.lineno)

        func_symbol = SymbolNode(
            id=func_id,
            name=node.name,
            kind=kind,
            file_path=self.rel_path,
            module_name=self.module_name,
            parent_id=parent_id,
            start_line=start_line,
            end_line=end_line,
            signature=signature,
            decorators=decorators,
            docstring_summary=doc_summary,
            source_code=format_numbered_source(self.source_lines, start_line, end_line),
            parameters=params,
            param_types=param_types,
        )
        self.result.symbols[func_id] = func_symbol

        prev_locals = self.active_local_types
        prev_dyn = self.active_dynamic_vars
        self.active_local_types = dict(param_types)
        self.active_dynamic_vars = set()

        self.scope_stack.append((func_id, kind))
        self.generic_visit(node)
        self.scope_stack.pop()

        self.active_local_types = prev_locals
        self.active_dynamic_vars = prev_dyn

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_function_or_method(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_function_or_method(node, is_async=True)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            bound_name = alias.asname if alias.asname else alias.name
            self.result.imports.append(
                ImportRecord(
                    module=alias.name,
                    imported_name=None,
                    alias=bound_name,
                    level=0,
                    line=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            bound_name = alias.asname if alias.asname else alias.name
            self.result.imports.append(
                ImportRecord(
                    module=mod,
                    imported_name=alias.name,
                    alias=bound_name,
                    level=node.level or 0,
                    line=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        cls_sym = self._enclosing_class_symbol()
        inferred_type = self._infer_assigned_type(node.value)
        is_dyn_rhs = is_dynamic_expression(node.value, self.active_dynamic_vars)

        for target in node.targets:
            attr_name = self._extract_self_attribute(target)
            if attr_name and cls_sym is not None and inferred_type:
                cls_sym.attribute_types[attr_name] = inferred_type
            elif isinstance(target, ast.Name):
                if inferred_type:
                    self.active_local_types[target.id] = inferred_type
                    self.current_symbol.param_types[target.id] = inferred_type
                if is_dyn_rhs:
                    self.active_dynamic_vars.add(target.id)
                    expr_preview = f"L{node.lineno}: {target.id} = {safe_unparse(node.value, max_len=80)}"
                    self.current_symbol.dynamic_locals.append(expr_preview)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Captures `sql += f" AND ..."` dynamic string concatenations."""
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            self.active_dynamic_vars.add(node.target.id)
            expr_preview = f"L{node.lineno}: {node.target.id} += {safe_unparse(node.value, max_len=80)}"
            self.current_symbol.dynamic_locals.append(expr_preview)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        cls_sym = self._enclosing_class_symbol()
        inferred_type = unwrap_type_annotation(
            node.annotation
        ) or self._infer_assigned_type(node.value)

        if inferred_type:
            attr_name = self._extract_self_attribute(node.target)
            if attr_name and cls_sym is not None:
                cls_sym.attribute_types[attr_name] = inferred_type
            elif isinstance(node.target, ast.Name):
                self.active_local_types[node.target.id] = inferred_type
                self.current_symbol.param_types[node.target.id] = inferred_type

        if node.value and isinstance(node.target, ast.Name):
            if is_dynamic_expression(node.value, self.active_dynamic_vars):
                self.active_dynamic_vars.add(node.target.id)
                expr_preview = f"L{node.lineno}: {node.target.id} = {safe_unparse(node.value, max_len=80)}"
                self.current_symbol.dynamic_locals.append(expr_preview)

        self.generic_visit(node)

    @staticmethod
    def _extract_self_attribute(target: ast.AST) -> Optional[str]:
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
        ):
            return target.attr
        return None

    def _infer_assigned_type(self, value_node: Optional[ast.AST]) -> Optional[str]:
        if value_node is None:
            return None
        if isinstance(value_node, ast.Call):
            callee = safe_unparse(value_node.func)
            for suffix in (".get_instance", ".create", ".build"):
                if callee.endswith(suffix):
                    return callee.removesuffix(suffix)
            short = callee.split(".")[-1]
            if short and short[0].isupper():
                return callee
            return None
        if isinstance(value_node, ast.Name):
            return self.active_local_types.get(value_node.id)
        if isinstance(value_node, ast.BoolOp):
            for val in value_node.values:
                inferred = self._infer_assigned_type(val)
                if inferred:
                    return inferred
        if isinstance(value_node, ast.IfExp):
            return self._infer_assigned_type(
                value_node.body
            ) or self._infer_assigned_type(value_node.orelse)
        return None

    def visit_If(self, node: ast.If):
        """
        Records early-return or exception-raising guard clauses (such as role checks,
        permission checks, or input validation) while skipping positive route-dispatch
        branches (`if path == '/api/...'`).
        """
        is_guard_branch = any(
            isinstance(stmt, (ast.Return, ast.Raise)) for stmt in node.body
        )
        if is_guard_branch:
            cond_preview = safe_unparse(node.test, max_len=100)
            # Filter out positive URL route-matching branches in dispatchers
            is_route_match = (
                "path ==" in cond_preview or "path.startswith(" in cond_preview
            ) and "not " not in cond_preview
            if not is_route_match:
                self.current_symbol.guards.append(
                    GuardRecord(
                        kind="guard_clause",
                        preview=f"if {cond_preview}",
                        line=node.lineno,
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        callee_expr = self._extract_callee_name(node.func)
        if callee_expr:
            if callee_expr in ("isinstance", "issubclass"):
                self.current_symbol.guards.append(
                    GuardRecord(
                        kind="type_check",
                        preview=safe_unparse(node),
                        line=node.lineno,
                    )
                )

            arg_strs = [safe_unparse(a, max_len=60) for a in node.args]
            kw_strs = [
                f"{kw.arg}={safe_unparse(kw.value, max_len=40)}"
                for kw in node.keywords
                if kw.arg is not None
            ]
            dynamic = any(
                is_dynamic_expression(a, self.active_dynamic_vars) for a in node.args
            ) or any(
                is_dynamic_expression(kw.value, self.active_dynamic_vars)
                for kw in node.keywords
            )

            # Track dynamic list/collection mutations (e.g., conditions.append(f"action = '{x}'"))
            if dynamic and callee_expr.endswith((".append", ".extend")):
                container_var = callee_expr.split(".")[0]
                self.active_dynamic_vars.add(container_var)
                preview = f"L{node.lineno}: {callee_expr}({', '.join(arg_strs)})"
                self.current_symbol.dynamic_locals.append(preview)

            self.current_symbol.calls.append(
                CallSite(
                    callee_expr=callee_expr,
                    line=node.lineno,
                    args_preview=", ".join(arg_strs + kw_strs),
                    keywords=kw_strs,
                    is_dynamic_arg=dynamic,
                )
            )

        self.generic_visit(node)

    @staticmethod
    def _extract_callee_name(func_node: ast.AST) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts = []
            curr: ast.AST = func_node
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
                return ".".join(reversed(parts))
            if isinstance(curr, ast.Call):
                inner = ScopeAwareVisitor._extract_callee_name(curr.func)
                if inner:
                    parts.append(f"{inner}()")
                    return ".".join(reversed(parts))
            return ".".join(reversed(parts))
        return None

    def visit_Assert(self, node: ast.Assert):
        self.current_symbol.guards.append(
            GuardRecord(
                kind="assert",
                preview=safe_unparse(node),
                line=node.lineno,
            )
        )
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise):
        self.current_symbol.guards.append(
            GuardRecord(
                kind="raise",
                preview=safe_unparse(node),
                line=node.lineno,
            )
        )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value is not None:
            if is_dynamic_expression(node.value, self.active_dynamic_vars):
                self.current_symbol.returns_dynamic = True
        self.generic_visit(node)


IGNORE_DIRS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".pytest_cache",
}


def parse_file(file_path: Path, repo_root: Path) -> FileParseResult:
    rel_path = file_path.relative_to(repo_root).as_posix()
    module_name = compute_module_name(file_path, repo_root)

    try:
        source = file_path.read_text(encoding="utf-8")
        source_lines = source.splitlines()
        tree = ast.parse(source, filename=rel_path)
    except Exception as exc:
        return FileParseResult(
            file_path=rel_path,
            module_name=module_name,
            parse_error=f"{type(exc).__name__}: {exc}",
        )

    visitor = ScopeAwareVisitor(rel_path, module_name, source_lines)
    visitor.visit(tree)
    return visitor.result


def parse_repository(repo_path: Path) -> List[FileParseResult]:
    repo_root = Path(repo_path).resolve()
    results: List[FileParseResult] = []

    for path in sorted(repo_root.rglob("*.py")):
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        results.append(parse_file(path, repo_root))

    return results
