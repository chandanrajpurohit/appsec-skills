#!/usr/bin/env python3
"""
Django AppSec Static Audit Tool
Analyzes Django projects for common security vulnerabilities and misconfigurations using AST and pattern inspection.
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any

class IssueSeverity:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class SecurityIssue:
    def __init__(self, file_path: str, line_no: int, severity: str, title: str, description: str):
        self.file_path = file_path
        self.line_no = line_no
        self.severity = severity
        self.title = title
        self.description = description

    def __str__(self):
        color = {
            IssueSeverity.HIGH: "\033[91m",
            IssueSeverity.MEDIUM: "\033[93m",
            IssueSeverity.LOW: "\033[94m",
        }.get(self.severity, "\033[0m")
        reset = "\033[0m"
        return f"{color}[{self.severity}]{reset} {self.file_path}:{self.line_no} - {self.title}\n  └─ {self.description}"

class DjangoSecurityAuditor(ast.NodeVisitor):
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        self.issues: List[SecurityIssue] = []
        self.local_var_sources: Dict[str, ast.AST] = {}

    def check_regex_patterns(self):
        # Check settings.py patterns
        if self.file_path.endswith("settings.py"):
            # DEBUG = True check
            for i, line in enumerate(self.lines, 1):
                clean_line = line.split("#")[0].strip()
                if re.match(r"^DEBUG\s*=\s*True\b", clean_line):
                    self.issues.append(SecurityIssue(
                        self.file_path, i, IssueSeverity.HIGH,
                        "Hardcoded DEBUG = True",
                        "DEBUG should never be hardcoded to True. Use environment variables (e.g. DJANGO_DEBUG)."
                    ))
                if re.search(r"ALLOWED_HOSTS\s*=\s*\[.*['\"]\s*\*\s*['\"].*\]", clean_line):
                    self.issues.append(SecurityIssue(
                        self.file_path, i, IssueSeverity.HIGH,
                        "Wildcard in ALLOWED_HOSTS",
                        "ALLOWED_HOSTS = ['*'] allows HTTP Host Header attacks. Restrict to explicit hostnames."
                    ))

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.local_var_sources[target.id] = node.value
        self.generic_visit(node)

    def _is_dangerous_sql_node(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        if isinstance(node, ast.Name) and node.id in self.local_var_sources:
            return self._is_dangerous_sql_node(self.local_var_sources[node.id])
        return False

    def visit_Call(self, node: ast.Call):
        # 1. Check for raw SQL injection via raw() or execute()
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in ("raw", "execute", "extra"):
            if node.args:
                first_arg = node.args[0]
                if self._is_dangerous_sql_node(first_arg):
                    self.issues.append(SecurityIssue(
                        self.file_path, node.lineno, IssueSeverity.HIGH,
                        f"Potential SQL Injection in {func_name}()",
                        "Avoid f-strings, string formatting (%), concatenation (+), or .format() in SQL queries. Pass parameters via placeholders (%s)."
                    ))

        # 2. Check for mark_safe
        if func_name == "mark_safe":
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.issues.append(SecurityIssue(
                    self.file_path, node.lineno, IssueSeverity.MEDIUM,
                    "Dynamic variable passed to mark_safe()",
                    "mark_safe() disables XSS auto-escaping. Verify that user input is sanitized using nh3 or bleach before rendering."
                ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 3. Check for @csrf_exempt
        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            if dec_name == "csrf_exempt":
                self.issues.append(SecurityIssue(
                    self.file_path, node.lineno, IssueSeverity.MEDIUM,
                    "View decorated with @csrf_exempt",
                    "@csrf_exempt disables CSRF protection. Ensure this endpoint uses header-based auth (e.g. Bearer token) or signature verification."
                ))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        # 4. Check for DRF Serializers with fields = '__all__'
        if node.name.endswith("Serializer"):
            for stmt in node.body:
                if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
                    for meta_stmt in stmt.body:
                        if isinstance(meta_stmt, ast.Assign):
                            for target in meta_stmt.targets:
                                if isinstance(target, ast.Name) and target.id == "fields":
                                    if isinstance(meta_stmt.value, ast.Constant) and meta_stmt.value.value == "__all__":
                                        self.issues.append(SecurityIssue(
                                            self.file_path, meta_stmt.lineno, IssueSeverity.MEDIUM,
                                            "DRF Serializer exposes fields = '__all__'",
                                            "Mass-assignment risk: Serializers should explicitly list permitted fields to avoid exposing internal model attributes."
                                        ))
        self.generic_visit(node)

def audit_file(file_path: Path) -> List[SecurityIssue]:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return []

    auditor = DjangoSecurityAuditor(str(file_path), content)
    auditor.check_regex_patterns()

    try:
        tree = ast.parse(content, filename=str(file_path))
        auditor.visit(tree)
    except SyntaxError:
        pass

    return auditor.issues

def audit_directory(target_dir: str) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []
    target_path = Path(target_dir).resolve()

    ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", "migrations", "staticfiles"}

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                issues.extend(audit_file(file_path))

    return issues

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: python audit.py [TARGET_DIRECTORY]")
        print("Scans a Django repository for security anti-patterns.")
        sys.exit(0)

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Auditing Django project at: {target_dir} ...\n")

    issues = audit_directory(target_dir)

    if not issues:
        print("\033[92m[✓] No static security issues detected!\033[0m")
        sys.exit(0)

    print(f"Found {len(issues)} potential security issue(s):\n")
    for issue in issues:
        print(issue)
        print()

    high_count = sum(1 for i in issues if i.severity == IssueSeverity.HIGH)
    if high_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
