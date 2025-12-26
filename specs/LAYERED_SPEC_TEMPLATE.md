# Layered Specification Template

Use this template when instructing Claude Code to create a new layered specification.

## Quick Instruction for Claude Code

```
I need to create a layered specification for [FEATURE NAME] following the pattern in specs/mtls/.

The feature involves:
- [List key components/packages affected]
- [Infrastructure changes needed]
- [Estimated complexity: X hours]

Please create a layered spec structure with:
1. README.md as entry point
2. 00-architecture.md with design decisions and diagrams
3. Phase files (01-0X) for sequential implementation
4. operations-runbook.md for Day 2 operations
5. examples/ directory with code references

Follow the pattern established in specs/mtls/ including:
- Inline code for interfaces and small snippets
- Examples directory for complete implementations
- Success criteria for each phase
- Verification commands
- Mermaid diagrams where appropriate

See AGENT.md "Specification Documentation Standards" section for complete guidelines.
```

## Expected Directory Structure

```
specs/<feature-name>/
├── README.md                    # Entry point & navigation (250-400 lines)
├── 00-architecture.md           # Design decisions (400-800 lines)
├── 01-phase1-<name>.md         # Phase 1 implementation (250-500 lines)
├── 02-phase2-<name>.md         # Phase 2 implementation (250-500 lines)
├── 03-phase3-<name>.md         # Phase 3 implementation (250-500 lines)
├── ...                          # Additional phases as needed
├── operations-runbook.md        # Day 2 operations (300-500 lines)
├── ARCHIVE_*.md                 # Original spec if migrated
└── examples/                    # Complete code examples
    ├── <package1>/
    ├── <package2>/
    └── <package3>/
```

## When to Use This Pattern

✅ **Use layered specs when:**
- Implementation spans 3+ packages or components
- Requires infrastructure changes (Terraform, AWS resources)
- Involves architectural decisions with multiple approaches
- Takes 7+ hours to implement
- Benefits from phase-by-phase execution

❌ **Do NOT use for:**
- Simple bug fixes or single-file changes
- Documentation-only updates
- Trivial feature additions

## File Content Guidelines

### README.md
- Overview and benefits
- Prerequisites (tools, access, knowledge)
- Quick start (5 steps)
- File navigation table
- Phase-by-phase execution guide
- Troubleshooting
- Next steps

### 00-architecture.md
- Summary and goals
- Design decisions and trade-offs
- Architecture diagrams (Mermaid)
- Data models
- Key concepts
- References to examples

### Phase Files (01-0X)
- Clear goal and duration
- Prerequisites
- Success criteria (checkboxes)
- Implementation steps
- Code snippets (inline for interfaces)
- References to examples/
- Verification commands
- Next phase link

### operations-runbook.md
- Common procedures
- Emergency procedures
- Monitoring/alerting
- Troubleshooting
- Metrics
- AWS CLI commands

### examples/
- Complete interfaces (<100 lines)
- Reference files for large implementations (>100 lines)
- Organized by package structure
- Include import comments

## Code Organization

**Inline in specs:**
- Interface definitions (<100 lines)
- Struct definitions (<50 lines)
- Method signatures
- Small snippets (<30 lines)
- Mermaid diagrams
- Tables

**In examples/ directory:**
- Complete implementations (>100 lines)
- Full files (even if <100 lines)
- Large Terraform modules (>80 lines)
- CLI commands (>200 lines)

## Phase Organization Pattern

1. **Phase 1: Core Code** - Interfaces, logic, no infrastructure
2. **Phase 2: Integration** - Local testing, docker-compose
3. **Phase 3: Infrastructure** - Terraform, AWS resources
4. **Phase 4: Deployment** - Production, verification
5. **Phase 5: Cleanup** - Remove old code, docs

## Reference Implementation

See `specs/mtls/` for a complete example demonstrating all these patterns.

**Stats from mTLS spec:**
- 8 spec files (README + architecture + 5 phases + runbook)
- 12 example files
- 3,062 lines of focused documentation
- Each phase independently actionable
- Clear success criteria throughout

## Additional Resources

- Full guidelines: `AGENT.md` → "Specification Documentation Standards"
- Reference implementation: `specs/mtls/`
- Quick start: `specs/mtls/README.md`
