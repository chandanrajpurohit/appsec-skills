# Contributing to AppSec Skills

Thank you for contributing to open-source Application Security skills for AI agents!

Our goal is to create high-quality, framework-specific security runbooks, checklists, and audit scripts that empower AI coding agents to produce secure-by-default software.

---

## Adding a New Framework Skill

To contribute a skill for a new framework (e.g. `nextjs`, `fastapi`, `express`, `rails`, `spring`):

### 1. Directory Layout
Create a directory under `skills/<framework>/` following this structure:

```text
skills/<framework>/
├── SKILL.md                  # Required: Main entry point with YAML frontmatter
├── LICENSE.txt               # Required: Open source license terms
├── references/               # Required: Modular deep dives on specific vulnerabilities
│   ├── authz-idor.md
│   ├── injection.md
│   └── headers-hardening.md
├── scripts/                  # Recommended: Executable audit / helper script
│   └── audit.py
└── examples/                 # Required: Side-by-side vulnerable vs secure code
    ├── vulnerable_vs_secure.*
    └── secure_*.*
```

### 2. Standard `SKILL.md` Specification
The `SKILL.md` file must begin with YAML frontmatter:

```markdown
---
name: <framework>
description: >-
  Application security guide, audit checklist, and static scanner for <Framework> web applications.
  Use when writing, refactoring, or reviewing <Framework> views, models, routes,
  database queries, authentication, or production settings.
license: Complete terms in LICENSE.txt
---

# <Framework> Application Security

This skill guides AI agents in identifying, preventing, and remediating application security vulnerabilities across <Framework> applications.

**Helper Scripts Available**:
- `scripts/audit.py` - AST and pattern static security scanner for <Framework>

**Always run scripts with `--help` first** to see usage. DO NOT read the source until you try running the script first and find that a customized solution is absolutely necessary. These scripts can be very large and thus pollute your context window. They exist to be called directly as black-box scripts rather than ingested into your context window.

## Decision Tree: Choosing Your Approach
...
```

**Key Guidelines**:
- **Progressive Disclosure**: Keep `SKILL.md` focused on the decision tree, trigger logic, and high-level checklist. Put lengthy documentation in `references/*.md`.
- **Actionable for Agents**: Write instructions that agents can reason through step-by-step. Include before-and-after code snippets.
- **Automated Verification**: Include instructions for testing and validating security fixes.

---

## Guidelines for Code Examples
- Place examples in `skills/<framework>/examples/`.
- Provide side-by-side `vulnerable_vs_secure.*` implementations.
- Comment specifically on *why* the vulnerable pattern is dangerous and *how* the secure pattern mitigates the threat.

---

## Pull Request Checklist
Before submitting a PR:
- [ ] Create `skills/<framework>/` with `SKILL.md`, `LICENSE.txt`, `scripts/`, `examples/`, and `references/`.
- [ ] Ensure scripts are executable (`chmod +x scripts/*`) and support `--help`.
- [ ] Run scripts locally to confirm they exit cleanly and handle edge cases without crashing.
- [ ] Verify markdown formatting and relative links between `SKILL.md` and `references/`.
- [ ] Register the new skill in [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json).
- [ ] Add a symlink in `.agents/skills/<framework>`.
- [ ] Update the [`README.md`](./README.md) table with the new skill.
