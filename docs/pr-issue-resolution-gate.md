# Claw Code 2.0 PR and Issue Resolution Gate

This gate was added to the Claw Code 2.0 Ultragoal after the explicit requirement:

> all PRs should be merged and all issues should be resolved if resolvable and correct.

## Scope

Before the Claw Code 2.0 Ultragoal can be marked complete:

1. Every open GitHub PR at the current final-gate snapshot must be triaged.
2. PRs that are correct, compatible with Claw Code 2.0 direction, and pass required verification must be merged.
3. PRs that are stale, incorrect, duplicative, unsafe, spam, or outside Claw Code scope must not be merged; each needs a recorded rationale.
4. Every open GitHub issue at the current final-gate snapshot must be triaged.
5. Issues that are resolvable and correct must be fixed or explicitly linked to a merged fix.
6. Issues that are spam, duplicates, incorrect, unactionable, externally blocked, or not Claw Code work must be closed or labeled/commented with rationale when repository policy allows.
7. The final completion audit must use a fresh GitHub snapshot, not only the planning snapshot.

## Current live snapshot

A fresh non-destructive snapshot was captured locally during G011 W3 execution:

- Command: `gh pr list --state open --limit 1000 --json number,title,state,updatedAt,url`
- Command: `gh issue list --state open --limit 1000 --json number,title,state,updatedAt,url,labels`
- Captured on: 2026-05-15T02:39:41Z during the active Ultragoal run.
- Observed counts: 51 open PR records and 1000 open issue records from GitHub CLI list calls.
- Most recent open PR in the snapshot: #3040, `fix: recognize OPENAI_API_KEY as valid auth for OpenAI-compatible endpoints`, updated 2026-05-14T11:35:23Z.
- Most recent open issue in the snapshot: #3039, `How to install skills?`, updated 2026-05-14T08:14:36Z.
- The issue snapshot hit the configured `--limit 1000`, so the final gate must treat the issue count as at least 1000 unless a higher-limit export or paginated ledger is captured.

These command outputs are evidence inputs, not final proof. The final gate must refresh them and compare deltas before any completion claim.

## Anti-slop triage templates

Use `docs/anti-slop-triage.md` plus the repository templates before acting on the live snapshot:

- `.github/ISSUE_TEMPLATE/anti_slop_triage.yml` records the initial issue classification, evidence, and non-destructive next action.
- `.github/PULL_REQUEST_TEMPLATE.md` adds PR classification, verification, and resolution-gate checklist items.

The anti-slop classifications are: `actionable-bug`, `actionable-docs`, `actionable-feature`, `duplicate`, `spam-or-promotion`, `generated-slop-or-hallucinated`, `unsafe-or-security-sensitive`, `not-reproducible-yet`, and `externally-blocked`.

Automation lanes may recommend labels, comments, defer/close rationales, or merge candidates, but must not merge or close remote PRs/issues without maintainer-owned approval.


## G012 W4 live issue reconciliation snapshot

A fresh, non-mutating issue snapshot was captured for the G012 final gate from
this worker worktree. The claim-safe task lifecycle is currently blocked because
team task `5` is assigned to Worker-4 in the description but still has
`owner: worker-1`; therefore this worker did **not** close, label, comment on,
or otherwise mutate remote issues from this lane.

Fresh commands run from `origin https://github.com/ultraworkers/claw-code` on
HEAD `2e93264`:

- `gh issue list --state open --limit 5000 --json number --jq 'length'` →
  `1350` open issues.
- `gh pr list --state open --limit 5000 --json number --jq 'length'` →
  `51` open PRs.
- `gh issue list --state open --limit 5000 --json number,title,createdAt,updatedAt,labels,author,url`
  captured the issue metadata used for the classification below.

### Issue classification ledger

| Bucket | Count | Representative issues | Final-gate action | Rationale / evidence |
| --- | ---: | --- | --- | --- |
| Recent external actionable review | 9 | #3039, #3023, #3022, #3020, #3007, #3006, #3005, #3004, #3003 | Defer/route with evidence; do not close automatically | These are real user reports or proposals. Existing G002/G009/G010/G011 work covers parts of #3007, #3004/#3033, #3039, and provider/docs items, but maintainer approval is required before closing remote issues. |
| Owner-authored roadmap/docs/feature trackers | 11 | #3038, #3037, #3036, #3035, #3034, #3033, #3032, #3031, #3030, #3029, #3028 | Mark as linked to G009-G011 evidence or defer as roadmap | The repo now has docs for navigation/file context, local OpenAI-compatible providers and skills, Windows install/release, ACP/Zed/JSON-RPC status, and ecosystem ops UX. Items that request future product surfaces (provider setup wizard, auto-compact retry, `claw serve`, marketplace) remain roadmap/deferred rather than safe final-gate closures. |
| Older potentially actionable issues | 11 | #2980, #2979, #2820, #2819, #1601, #933, #416, #375, #32, #31, #5 | Defer for owner batch triage | These need maintainer/product decisions or separate repro work. Some are broadly addressed by current docs/policy files, but closing them from an automation lane would overclaim. |
| Spam or low-signal flood | 628 | Repeated `经验+3`, `合影`, WeChat/QQ group ads, promotional links | Close/label only under maintainer-owned bulk moderation | These are not Claw Code engineering work and are safe candidates for spam/invalid moderation, but this worker did not mutate remote state. |
| Older low-signal or owner-triage-needed | 691 | #2997 plus many March 2026 low-context comments/promotions/questions | Defer for maintainer-owned bulk triage | Mixed low-signal and unclear reports remain open. They are not safely resolvable by code changes in this final gate without per-issue owner policy decisions. |

### Correct/resolvable issue findings

- #3039 (`How to install skills?`) is addressed by current docs in
  `USAGE.md` and `docs/local-openai-compatible-providers.md`, which document
  `/skills install <path>`, `/skills list`, discovered names, local skill roots,
  and provider credential checks. Closure should wait for maintainer confirmation
  or a response to the reporter.
- #3038 is intentionally deferred: `docs/g011-ecosystem-ops-ux-verification-map.md`
  records marketplace/plugin boundaries and the explicit remote marketplace
  deferral after core UX stabilization.
- #3037 and #3036 are addressed by README/USAGE links plus
  `docs/local-openai-compatible-providers.md`, including Ollama, llama.cpp,
  vLLM, OpenAI-compatible routing, and multi-provider positioning.
- #3035 is partially addressed by `/resume latest` docs and
  `docs/g010-session-hygiene-verification-map.md`; any remaining compacted
  session UX work should stay linked to the session-hygiene roadmap rather than
  be auto-closed.
- #3033/#3004 are addressed only as explicit deferrals by
  `docs/g011-acp-json-rpc-status-contract.md`; no ACP/Zed daemon or JSON-RPC
  engine API is claimed yet.
- #3032/#3030/#3005/#3020 remain provider-diagnostics/setup follow-ups.
  Existing provider docs reduce support ambiguity, but final-gate automation
  should not claim remote closure without reproductions or maintainer sign-off.
- #3007 has regression coverage in `tests/test_security_scope.py` and
  `rust/crates/runtime/src/file_ops.rs`; closure still requires maintainer review
  because the live issue can include shell-expansion edge cases beyond the
  covered symlink/path-scope tests.
- #3003 should be checked against repository ignore/source-control policy before
  closure; this worker did not find or make a code change in the claimed lane.

### Remote-action gate

No issue was closed, labeled, or commented on by this worker. The safe final-gate
recommendation is:

1. Maintainer/leader fixes the Worker-4 task claim conflict before any further
   lifecycle transition.
2. Close or label the 628 spam/low-signal issues in a maintainer-owned bulk
   moderation lane.
3. Link #3039/#3037/#3036/#3028 to the merged docs evidence if maintainers
   agree the docs answer the reports.
4. Keep future-product items (#3038, #3033, #3031, #3030, #3004) open or move
   them to a roadmap/project board with explicit deferral rationale.

## Required final evidence

The final report must include:

- Fresh `gh pr list --state open` and `gh issue list --state open` snapshots.
- A PR ledger with one row per PR: merge / reject / defer, reason, verification, commit/merge reference.
- An issue ledger with one row per issue: fixed / duplicate / spam / invalid / deferred-with-rationale / externally-blocked, reason, and linked evidence.
- Verification that no correct, mergeable PR remains unmerged without rationale.
- Verification that no resolvable, correct issue remains open without a fix or rationale.

## Non-goals

This gate does not require merging unsafe, unverified, incompatible, spam, or incorrect contributions. It requires explicit evidence-backed triage and action for everything that is correct and resolvable.
