> **Note:** This repository contains open-source Application Security (AppSec) skills for AI coding agents. For information about the Agent Skills standard, see [agentskills.io](https://agentskills.io).

# Application Security Skills

Skills are modular folders of instructions, scripts, references, and examples that AI coding agents (such as Claude Code, Google Antigravity, Codex, Cursor, and Copilot) load dynamically to perform specialized tasks.

Modern AI coding agents generate code quickly, but without framework-specific security constraints, they frequently introduce subtle, high-severity vulnerabilities:
- Constructing raw SQL queries via Python f-strings in Django ORMs (`.raw()`, `.extra()`, cursors).
- Introducing Broken Object Level Authorization (BOLA/IDOR) by omitting user-scoped or tenant-scoped querysets.
- Disabling auto-escaping via unvetted `mark_safe()` and `|safe` template filters.
- Mass-assignment risks through DRF serializers using `fields = '__all__'`.
- Misconfiguring production settings (`DEBUG = True`, wildcard `ALLOWED_HOSTS`, insecure cookies).
- Permitting unvalidated file uploads with executable extensions or spoofed MIME types.

This repository provides standardized, framework-wise Application Security skills to guide agents in writing secure-by-default code, auditing existing repositories, and fixing vulnerabilities.

---

## About This Repository

Each skill is completely self-contained in its own folder under [`skills/`](./skills) with:
- **`SKILL.md`**: The main instruction runbook with YAML frontmatter, decision trees, and workflows that the agent reads.
- **`scripts/`**: Executable static audit tools (`audit.py`) that agents can run autonomously with `--help`.
- **`examples/`**: Side-by-side `vulnerable_vs_secure` patterns and production-ready templates.
- **`references/`**: Modular deep-dive documentation loaded progressively by agents on-demand.
- **`LICENSE.txt`**: Terms of the open-source license.

---

## Available Skills

| Skill | Description | Automated Tools | Guides |
| :--- | :--- | :--- | :--- |
| [`django`](./skills/django) | Application security guide, audit checklist, and AST static scanner for Django & DRF web applications. | `scripts/audit.py` | [References](./skills/django/references) |

### Roadmap
- [ ] **Next.js**: Server Actions auth, RSC data leakage (`server-only`), CSP nonces, SSRF defense.
- [ ] **FastAPI**: Pydantic v2 mass-assignment, dependency injection auth, OpenAPI docs hardening.
- [ ] **Express / Node.js**: Prototype pollution, CORS, Helmet security headers, rate limiting.
- [ ] **Ruby on Rails**: Strong parameters, mass-assignment, session cookies, Brakeman checks.
- [ ] **Spring Boot**: Actuator exposure, Spring Security CSRF, SpEL injection.

---

## Repository Structure

Following the standard Agent Skills specification ([agentskills.io](https://agentskills.io)):

```text
appsec-skills/
├── .claude-plugin/
│   └── marketplace.json               # Claude Code plugin registry
├── .agents/skills/                    # Antigravity & local agent discovery
│   └── django -> ../../skills/django
├── spec/
│   └── agent-skills-spec.md           # Agent Skills standard pointer
├── template/
│   └── SKILL.md                       # Scaffolding template for new skills
├── skills/
│   └── django/
│       ├── SKILL.md                   # Main runbook & decision tree
│       ├── LICENSE.txt                # License terms
│       ├── scripts/
│       │   └── audit.py               # AST & pattern static security scanner
│       ├── examples/
│       │   ├── vulnerable_vs_secure.py# Side-by-side vulnerable vs secure code
│       │   └── secure_settings.py     # Hardened production settings template
│       └── references/                # Modular deep-dive security guides
│           ├── settings-hardening.md
│           ├── orm-sql-injection.md
│           ├── authz-idor.md
│           ├── xss-csrf-defense.md
│           ├── file-upload-security.md
│           └── api-drf-security.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Using Skills with AI Agents

### 1. Claude Code
Install or link the skills into your Claude Code setup:
```bash
# Add to your project's skills
cp -r skills/django .claude/skills/
# or use the marketplace plugin:
# .claude-plugin/marketplace.json
```

### 2. Google Antigravity
The skills are pre-configured in `.agents/skills/` for immediate workspace discovery:
```bash
# Project-specific:
mkdir -p .agents/skills
cp -r /path/to/appsec-skills/skills/* .agents/skills/

# Global machine installation:
mkdir -p ~/.gemini/config/skills
cp -r /path/to/appsec-skills/skills/* ~/.gemini/config/skills/
```

### 3. Cursor, Copilot & Other Agents
Reference the skill in your project's system rules or prompt:
```markdown
When generating or reviewing Django code, follow the guidelines in skills/django/SKILL.md.
```

---

## Creating New Skills

To contribute a skill for a new framework:
1. Copy [`template/SKILL.md`](./template/SKILL.md) to `skills/<framework>/SKILL.md`.
2. Populate the YAML frontmatter (`name`, `description`, `license: Complete terms in LICENSE.txt`).
3. Add `scripts/audit.py`, `examples/vulnerable_vs_secure.*`, and modular guides in `references/`.
4. Register the new skill in [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json).
5. See [CONTRIBUTING.md](./CONTRIBUTING.md) for full instructions.

---

## License

MIT License. See [LICENSE](./LICENSE) and individual skill [`LICENSE.txt`](./skills/django/LICENSE.txt) files for details.
