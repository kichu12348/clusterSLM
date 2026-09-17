import ast
from pathlib import Path


class FileInfo:

    def __init__(self, path):
        self.path = path
        self.imports = []

        self.classes = []
        self.functions = []
        self.calls = []
        self.call_map = {}


class Import:

    def __init__(self, module, level=0):
        self.module = module
        self.level = level

    def __repr__(self):
        return f"Import(module={self.module!r}, level={self.level})"


class Parser(ast.NodeVisitor):

    def __init__(self):
        self.info = None
        self.scope_stack = []

    def visit_Import(self, node):

        for alias in node.names:
            self.info.imports.append(Import(alias.name))

        self.generic_visit(node)

    def visit_ImportFrom(self, node):

        module = node.module or ""

        self.info.imports.append(Import(module, node.level))

        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.info.classes.append(node.name)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node):
        self.info.functions.append(node.name)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    # Extract async function names
    def visit_AsyncFunctionDef(self, node):
        self.info.functions.append(node.name)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    # Extract call expressions (e.g., subprocess.run)
    def visit_Call(self, node):
        call_name = None

        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                call_name = ".".join(reversed(parts))
            else:
                call_name = ".".join(reversed(parts))

        if call_name:
            # Determine who is making the call
            caller = ".".join(self.scope_stack) if self.scope_stack else "<module>"

            if caller not in self.info.call_map:
                self.info.call_map[caller] = []
            self.info.call_map[caller].append(call_name)

        self.generic_visit(node)


def parse_file(path):

    source = path.read_text(encoding="utf-8")

    tree = ast.parse(source, filename=str(path))

    parser = Parser()
    parser.info = FileInfo(path)

    parser.visit(tree)

    return parser.info


def discover_repository(repo_path):

    repo_path = Path(repo_path)

    files = []

    for path in repo_path.rglob("*.py"):

        if "__pycache__" in path.parts:
            continue

        try:
            files.append(parse_file(path))

        except SyntaxError as e:
            print(f"Skipping {path}: {e}")

    return files
