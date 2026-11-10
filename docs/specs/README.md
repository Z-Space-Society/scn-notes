# Specs, decisions and agreement

Status: Proposal, 2026-11-10 (quill). Not adopted until the repository
maintainers review and accept it.

`docs/specs/0001-spec-phase-b/` is the model: a design document that says what
will be built, why, what it will not do, and how it will be tested. The code
follows it. This note turns that one example into a repeatable process, so a
decision does not have to be reconstructed from an issue thread six months
later.

The process is deliberately small. It is for changes with a design worth
arguing about: a schema, a public route, an authorization rule, a data model, a
protocol. It is not for typo fixes, dependency bumps, or a patch that restores
the behaviour the README already promises.

## Four places, four jobs

| Where | Holds | Does not hold |
|---|---|---|
| GitHub issue | The problem, the reproduction, the links, the conversation | The chosen design |
| SCN Notes workspace note | The human discussion, member requests, the context an issue loses | The contract |
| `docs/specs/NNNN-spec-slug/` | The design of record: goal, non-goals, decisions, schema, routes, tests, open questions | Implementation detail that will change without changing behaviour |
| `docs/decisions/NNNN-slug.md` | A cross-cutting decision and the alternatives, in one place, with a date and deciders | A second copy of a spec |

A spec links its issue and its decision records. An issue links its spec once
one exists. The workspace note links both. One fact, one home.

## Lifecycle

| Status | Means | Leaves when |
|---|---|---|
| `Draft` | The author is still writing; not ready for a verdict | The author asks for review |
| `In review` | A PR is open, reviewers are named, open questions are visible | The reviewers agree, or the spec is withdrawn |
| `Agreed` | The design is settled; implementation may start | The implementation lands, or a later spec supersedes it |
| `Implemented` | The code is merged; the spec still describes it | A later spec supersedes it |
| `Superseded` | A later spec replaces it; the history stays | Never — it is the record |
| `Withdrawn` | Not going ahead; the reason is in the status line | Never |

The status line at the top of the spec carries the state, the date, and the
people who agreed:

```text
Status: Agreed, 2026-11-12 (Boris, Jacob)
```

A spec in `Draft` or `In review` may change freely. An `Agreed` spec changes
only to correct a factual error or to record a decision that the implementation
forced; both are noted in the spec's change history or the PR.

## Agreement

**A spec is agreed when both of these are true:**

1. The named reviewers have approved the spec PR; and
2. The status line says `Agreed`, with the date and their names.

An approval without the status line is not agreement. The status line without
the approval is not agreement. The merge commit is the durable record.

- Every spec names at least one maintainer and the author. Add a domain
  reviewer when the change touches their area (deployment, plugin, Corliss).
- **Silence is not agreement.** A review window is a prompt, not consent. If a
  reviewer cannot review, the author names another or the spec stays `In review`.
- **Open questions block agreement** unless they are explicitly deferred. A
  deferred question becomes a linked issue with an owner and a target, and the
  spec's `Open questions` section says where it went.
- A small change to an existing spec can be a PR against that spec with the same
  rule; it does not need a new number. A change of direction is a new spec.

**No implementation PR merges before the spec is `Agreed`**, with one exception:
a time-boxed spike, explicitly labelled, that does not merge to `main` and whose
only output is knowledge. If the spike changes the design, the spec is amended
first.

## Decisions

Two kinds:

- **Local decisions** live in the spec's `## Decisions` table: a date, the
  decision, who made it, and a link. The Phase B spec's document schema is this
  kind.
- **Cross-cutting decisions** get an ADR in `docs/decisions/`. They affect more
  than one spec or repository, or they supersede an earlier decision, or they
  are the kind of thing a future contributor will ask "why on earth?" about.
  `docs/decisions/0001-postgres-for-attachments.md` is the first example.

An ADR is one page:

```markdown
# NNNN: Title

Status: Proposed | Accepted | Superseded by NNNN
Date: YYYY-MM-DD
Deciders: names
Related: links

## Context
What forces the decision, in the reader's terms.

## Decision
What we will do.

## Alternatives
What we did not do, and why not.

## Consequences
What gets easier, what gets harder, and what to revisit.
```

- An accepted ADR is not rewritten. A later decision supersedes it: a new ADR
  number and a `Superseded by` line in the old one.
- If a conversation changes a decision, update the spec or ADR in the same PR,
  or in a preceding one. Do not leave the decision only in a chat or a note.
- The attachment decision is a good example: the first review of the feature
  note suggested Garage; the issue records the later choice of Postgres. The ADR
  is where that reversal is explained, so the note does not have to be edited to
  pretend it never said Garage.

## Implementation

- An implementation PR names the spec and the section it implements. A test
  that proves an access rule cites the section it is defending.
- A deviation from the spec is a spec change first, or the same PR with both
  changes. The code does not silently become the specification.
- When behaviour a member sees changes, `README.md` changes in the same PR. The
  README is the current contract; the spec is the design that got there.
- `/v1/` changes are additive. A breaking change is `/v2/`, served beside
  `/v1/`, never an edit to `/v1/`. The same rule applies to MCP tools: a new tool
  or a new field is additive; a changed meaning is a new tool.
- If the implementation finds the spec wrong, stop and amend the spec. A spec
  that no longer describes the code is worse than no spec, because people trust
  it.

## Files and naming

```text
docs/
  specs/
    0001-spec-phase-b/
      0001-spec-phase-b.md
    0002-spec-attachment-storage/
      0002-spec-attachment-storage.md
    README.md                 this file
  decisions/
    0001-postgres-for-attachments.md
    README.md                 the index, if the list gets long
```

- Four digits, one short slug, directory and file share the number. Match
  `0001-spec-phase-b` for now; the number is what links a spec to its decisions
  and issues.
- A spec's headings follow the Phase B model: Goal, Non-goals, Current state,
  Decisions, the design sections, Configuration, Module layout, Test plan, Open
  questions, Rollout. A section that does not apply is omitted, not left empty.
- Use the repository's prose style: say why a rule exists and what breaks
  without it, not just what the code does.

## Review checklist

- [ ] The problem, the goal and the non-goals are clear.
- [ ] Every decision has a date, a decider and an alternative considered.
- [ ] Authorization and privacy are stated, not implied.
- [ ] Storage, migration and rollback are stated.
- [ ] Ops cost is stated: backup, WAL, size, monitoring.
- [ ] The test plan proves the negative cases, not only the happy path.
- [ ] Open questions are resolved or deferred to linked issues.
- [ ] Reviewers are named and have approved.
- [ ] The status line says `Agreed` with the date and names.

## What this is not

- Not a heavyweight RFC process. A two-line fix does not need a spec.
- Not a reason to delay a security fix. Fix the bug, then write the spec for the
  design that prevents the next one.
- Not a promise that a spec is immutable. It is a record of what was agreed,
  and it changes when the agreement changes.
