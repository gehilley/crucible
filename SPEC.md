# Crucible v2 Spec

Oct 21, 2026 · @George Hilley

Crucible is an immutable, independently held record of every interaction between a researcher and an AI system during a piece of research, captured with no action by the researcher, sealed on an independent service, disclosed by stage (private, reviewer, public), and readable later for review, attribution, and retrospective assessment. If the user has to do anything after installation, it is a bug.

**Strategy.** The operator's strategy is not part of this specification. It lives in a private document, `STRATEGY.md` in the operator's private repository, and nothing in this specification depends on it. A marker such as [S1] points to the passage there that bears on the text beside it.

## 1. What v1 taught

V1 built a working capture client, hash chain, notary and verifier by August 2026, then spent three months building a governance process around the client instead of building the service. The process grew until its own operator could not verify what he was ratifying, and it stopped. That outcome is the most important finding of v1, and v2 is designed around it.

**Findings that survive and bind v2:**

1. **An operator-executed maintenance floor is an adoption ceiling of zero.** V1 measured this on its own operator. Any step that requires a human act after installation will not be taken, so the system must run unseen or not at all.
2. **Verification that consumes the verifier is an attack surface.** A process that generates review obligations faster than a human can discharge them is defeated by exhaustion, not forgery. V2 budgets human attention as a finite resource and spends none of it in the capture path.
3. **Hashes alone are not a record.** A hash chain proves a log was not altered; a reviewer cannot evaluate a hash. The content itself must be captured and sealed, with disclosure controlled by the service, not by what was omitted at capture.
4. **Independence is the only thing that makes the record worth anything.** Tools stay local; the service is collective and run by neither the researcher, the publisher, nor the model vendor. Git is deliberately history-rewritable, so temporal ordering cannot live there.
5. **A silent gap is worse than a loud failure.** V1's live-smoke alarm was red for eleven weeks against a placeholder address and nobody saw it. Capture failure must be the one thing that interrupts the user. Every record must state what it could not see rather than imply it saw everything.
6. **The corrector perturbs the system at roughly one defect per fix.** Measured twice. Tests are written red-first against planted known answers, and a fix is not accepted on the fixer's word.
7. **"Anchored" is a claim in a receipt, never an exit code.** Verified at the time is not verifiable from the record; only the second counts.
8. **The production service must run from a released artifact, never a working tree.** V1's notary ran from the mainline checkout, so an ordinary merge could change production code with no release act and no record.
9. **Claims live in the record or do not exist.** A finding discussed in conversation and not written down was lost in v1 and had to be regenerated. Nothing in v2 is true because someone said it.
10. **The chat surface has no hooks and cannot be isolated from memory.** Reasoning done there is uncapturable and its prior state is unverifiable. This is the gap the platform vendor must close; the client cannot work around it.

**What v1 did that v2 does not do:** census every manual step; classify acts into buckets; split rows; require operator acceptance of instruments through the real installation path; extract a standard from the implementation before the implementation serves a single outside user; run multi-round non-author review on planning documents. Each was defensible on its own. Together they were the ceiling.

## 2. The system at a glance

&#91;embedded content: Crucible v2 architecture · client, service, readers\]

The client on the researcher's machine captures and seals every hookable event and sends it to a service nobody in the loop controls; the service holds the record, moves it through disclosure stages on external triggers, and serves it to reviewers, the public, and later models. All judgment lives on the right; none lives on the left.

## 3. Client

The client is deliberately dumb: capture, seal, send, retry, and alarm. It holds no policy, makes no judgments, and has no interface beyond installation and a single failure notice.

**Installation.** One command. It installs the hooks for every supported surface it finds on the machine, generates the researcher's keypair, registers the public key with the service, and starts a background sender. It asks for the service address and nothing else; there is no default service, so a misconfigured client cannot silently talk to the wrong one. After that command the researcher never runs another.

**Capture.** On every hookable event (session start and end, each prompt and response, each tool call and its result, each file read or write by the agent, each external fetch), the client records the full content, not a digest of it. Captured content includes the model identifier and version string the surface reports, the injected context the surface exposes (system prompt, memory files, project files, retrieved documents) where the platform makes it available, and `could_not_see(<what>)` where it does not. Tool results larger than a size limit are stored whole up to the limit and digested beyond it, with the truncation recorded as such.

**Sealing.** Each event is appended to a per-session chain: `h_n = H(h_{n-1} || canonical(event_n))`. Content is encrypted client-side under a per-session key, which is wrapped to the researcher's key and to the service's custody key. The service can therefore stage disclosure without the researcher's cooperation, and the researcher can read their own record without the service.

**Sending.** The sender ships sealed events to the service as they occur and retries on failure with a local queue. The service returns a signed receipt per batch that binds the chain head to a server timestamp. A receipt is the only evidence of anchoring; the client's exit status is not.

**Alarm.** If the queue cannot drain for longer than a configured interval, or a hook that should have fired did not, the client interrupts the user once with a single line saying capture is broken and since when. This is the only user-facing message the client has. It is never suppressed.

**Surfaces.** V2 ships with Claude Code (hooks exist). The architecture assumes other agentic coding tools will expose equivalent hooks and treats each as a thin adapter. The consumer chat surface is not supported until the platform vendor provides hooks; the client records its absence as a gap in the session record, not as silence. [S5]

**What the client never does:** ask the user to confirm, classify, rate, review, or sign anything; hold a copy of any key it does not need; modify the record; decide what is worth capturing.

## 4. The record

A record is one research session's chain of events, plus the receipts that anchor it. Records are grouped into a **study** by the researcher's declaration at the start (one line: a question and what is already known), which is itself the first event.

**Event.** Every event has: a sequence number; a monotonic client timestamp; an event type from a closed vocabulary (`session.start`, `session.end`, `prompt`, `response`, `tool.call`, `tool.result`, `file.read`, `file.write`, `fetch`, `context.injected`, `gap`); the actor (`human`, `model:<id>`, `tool:<name>`); the content, or a digest plus a truncation note; and the chain hash. A `gap` event records something the client knows it could not capture (`could_not_see(reason)`) and is a first-class part of the chain, never an omission.

**Chain.** Per session, hash-linked. The session's first event carries the previous session's final head for the same study, so a study is one chain across sessions. The service's receipt binds each head to a server timestamp and the service's signing key.

**Evidence classes.** Each event carries the class the client can honestly claim: `witnessed` (captured by a hook at the moment it occurred), `sealed` (captured from an artifact the hook could read, such as a file on disk, but not the act that produced it), `reconstructed` (supplied after the fact by a person or a later process, with the supplier named). A record is only as strong as its weakest class on the path to any claim, and the read side must display that.

**Envelope and body.** Each event is two parts. The envelope is plaintext: sequence number, timestamp, event type, actor, evidence class, content size, truncation note, the sequence number of the most recent human event (so run lengths between human interventions are computable without content), and chain hash. The body is the content, sealed as §3 describes. The service and the read side can compute anything that depends only on envelopes (how much of a study each actor performed, event rates, gaps) at any disclosure stage without decrypting a body. Decryption is reserved for disclosure. The chain hash covers both parts, so an envelope cannot be altered without breaking the chain. (Added 2026-10-28, so that figures computed from envelopes need no access to sealed content.) [S9]

**Honesty rule.** Every verdict the system produces about a record is four-valued: `pass`, `fail`, `could_not_check(reason)`, `not_applicable(reason)`. `could_not_check` is never rendered as pass, never counted toward a pass rate, and never hidden behind a summary.

**Containment.** Whether content belongs to a record is determined by digest, never by file path. Paths move; digests do not.

**Immutability.** Nothing in a record is ever edited or deleted. A correction is a new event that references the one it corrects. The service refuses any write that is not an append.

## 5. Service

The service is the product. It is where the hard problems live, and it is the only part a journal, funder, or reader ever touches.

**Ingest.** Accepts sealed events from registered clients, verifies each batch's chain continuity against the stored head, and returns a signed receipt binding the new head to a server timestamp. Rejects any batch that breaks the chain and tells the client why. Never accepts a rewrite.

**Custody.** Holds ciphertext and the service-wrapped session keys. Can decrypt for disclosure without the researcher's participation, which is what makes staged disclosure enforceable rather than voluntary. The custody key is held in an HSM or equivalent, and every decryption is itself an appended, signed event in the service's own audit chain.

**Independence.** The service is operated by an entity that is not the researcher, not the researcher's institution, not a publisher, and not a model vendor. Its protocol and reference implementation are open; anyone may run one, and a record names which service holds it. Nothing built above the service ever controls the record. [S1]

**Deployment.** The production service runs from a tagged, digested release in its own environment. Deploying a new release is a recorded act with a release event in the service's audit chain. No production process ever imports from a working tree. The release covers the service image and its dependencies; the platform beneath it (operating system, container runtime, TLS terminator) patches itself, and each platform change is appended to the service's audit chain as a host entry (reading accepted 2026-10-24).

**Liveness.** The service runs a scheduled self-check that writes a known event through a real client against the real endpoint and verifies the receipt. If that check has not passed in a configured interval, the service surfaces it on its public status page and to the operator. A quiet failure is a design defect, not an operational one.

**Scale.** Phase 0 runs one small instance, but no design choice in it may prevent the service from later serving many researchers, many institutions, and more than one operator: the journal is an append-only object store rather than a local file, ingest is stateless behind the journal, and signing keys live in a managed key service rather than on a host. Managed cloud services are used for these where they exist. Scaling itself is not phase 0 work; not foreclosing it is.

**What the service never does:** judge correctness; score anyone; alter or redact a record; release content before its disclosure stage permits; depend on the researcher for any action after installation.

## 6. Disclosure

A study's record moves through four stages. Every transition is triggered by an external event the service can verify, never by a form the researcher fills in.

| Stage | Who can read | Entered when | Evidence the service checks |
| --- | --- | --- | --- |
| Private | The researcher only | Study declared (first event) | Client registration |
| Under review | Named reviewers and editor, read-only | A submission is registered against the study | Submission ID from a journal or preprint server, bound to the study's chain head by the submitting researcher's signature |
| Published | Anyone, read-only | A DOI or equivalent is registered against the study | The DOI resolves and its metadata names the study's chain head |
| Retained | Anyone, read-only, permanently | Automatic on publication | None; retention is the terminal state |

A study that is never submitted stays private indefinitely. A study whose submission is rejected returns to private, with the review-stage reads retained in the service's audit chain so the reviewers' access is itself on record. A withdrawn publication stays published: the record of what was claimed is the point.

**What a reviewer gets.** Read access to the decrypted record for the study, the chain verification result, the evidence-class profile, and the list of gaps. Nothing else is interpreted for them. Reviewer access is logged and the log is part of the record.

**What publication releases.** The full decrypted record, the receipts, and the service's verification. Anyone can re-run verification against the published chain and the service's public signing key.

**Binding the manuscript to the record.** The submitting researcher includes the study's chain head in the manuscript's data-availability statement. That one line is the whole of what a journal policy needs to require.

## 7. Read side

Everything that interprets a record runs here, after the fact, over an immutable store. It can be as elaborate as anyone wants because it never touches the researcher, and because a wrong analysis can be re-run without changing what it analyzed.

**Verification (ships in v2).** Replays a study's chain, checks every receipt against the service's key, and reports one of: intact; broken at event N; `could_not_check` with the reason. Reports the evidence-class profile (what fraction witnessed, sealed, reconstructed) and lists every gap event. This is the only read-side function the service itself must provide.

**Review view (ships in v2).** A reviewer-facing rendering of the record: the timeline of sessions, each prompt and response, each tool call and what it touched, the files as they stood at each write, the declared question and foreknowledge at the top. Searchable. No scoring, no summary, no model-generated commentary.

**Attribution (after v2).** Who did what: which claims in the manuscript trace to which events, and whether the originating actor was the human or the model. The record supplies the information; assigning credit is a judgment with a different set-point for every reader, and the system does not encode one.

**Retrospective assessment (after v2).** A later, stronger model reads the record and reports where the earlier model's reasoning was wrong, where the human corrected it, where the human was wrong, and what neither caught. Because the record is immutable and the assessor is named and dated, the assessment is itself a record and can be reassessed. The memory-contamination finding from v1 applies here: an assessor whose context includes the study's conclusions is not an independent check, and the assessment must state what the assessor was given.

**Derived labels (after v2).** Any classification of an event that depends on its content, above all whether a model event was execution of what the human specified or a judgment the human did not specify, is made on the read side after disclosure, never at capture. A derived label is itself a record: it names the classifier (a person, or a model with its version string), the date, the events it labels, and what the classifier was given. It can be re-run by a later classifier, and two runs may disagree on the record. A badge or dashboard that shows a derived figure shows the classifier's name beside it. (Added 2026-10-28.)

**Attack-surface audit (after v2).** Mechanical sweeps over records for known patterns: results that were not produced by any recorded tool call; files written outside any recorded session; model outputs that changed a number without a recorded computation; gaps clustered around the events that produced the headline result. Each pattern is a plant with a known answer before it is a sweep. [S4]

## 8. Build rules

These exist to stop v2 from becoming v1. They are constraints on how the work runs, and they are short on purpose.

1. **One builder, one operator, one spec.** The builder is a single Claude Code session per phase. The operator is George. This document is the spec; the operator's strategy is a separate, private document (see Strategy, at the top). There are no directives, standing rules, amendments, errata, censuses, or buckets. A change to the spec is an edit to this document with a dated note at the bottom.
2. **The operator's time is the scarcest resource and is budgeted.** Each phase asks the operator for at most three decisions, listed in advance in the phase's section below. A phase that needs a fourth decision stops and the builder reports why the spec was insufficient. The builder never generates a ruling batch.
3. **No governance of governance.** Nothing audits the build process. The build is audited by whether its acceptance test passes, and the acceptance test is run by a stranger, not by the builder and not by the operator.
4. **Tests are red-first against planted known answers.** A fix is accepted when its plant goes green and the full suite stays green. The builder does not review its own fix; a fresh session does, once. There is no second round.
5. **Nothing is true because it was said.** A finding, a decision, or a measurement exists when it is in the repository. Conversations are not a system of record. This applies to the operator's conversations with the advisory instance as much as to the builder's.
6. **Record first, standard never.** No standard is extracted from v2 until a researcher who is not the operator has used it for a complete study. If a mandate is ever written, the reference implementation is the thing that ran, not a document about it.
7. **The advisory instance proposes; it does not expand.** When the chat-surface advisor (this instance or its successor) notices a gap, it files one sentence in the open-questions section, or in the strategy document's for a strategy gap, and stops. It does not draft process to close it.
8. **Stop conditions are stated before starting.** Each phase names what "done" is and what "abandon" is. If the operator cannot state in one sentence what the system currently does, the phase has failed its own spec and stops.

## 9. Build plan

Four phases, each with one acceptance test and the operator decisions it needs listed up front. V1 code is salvage: the hook client, chain, notary and verifier are reused where they fit the spec and rewritten where they do not. Nothing under v1's `docs/package`, `docs/standard`, or its directive corpus is carried forward; it is archived as the record of v1.

| Phase | Builds | Acceptance test | Operator decisions (max 3) |
| --- | --- | --- | --- |
| 0. Salvage | A fresh repository; v1's client, chain and verifier ported; v1's notary pinned to a release and redeployed; the dead liveness check replaced | A stranger with a laptop installs the client from a README in under an hour, runs one Claude Code session, and the service verifies the record intact | Service hostname (log.cruciblehub.org, decided 2026-10-24); what to do with v1's existing anchors store (archive, decided 2026-10-24); where liveness alerts reach the operator (email, decided 2026-10-24) |
| 1. Content capture | Full-content events; client-side sealing; service custody; the alarm; the `gap` event; the study declaration | The operator runs a real study session over a week without touching the client; the record contains every prompt, response, tool call and file write, states its gaps, and the operator does not remember the client exists | Size limit for stored tool results; whether file reads are captured whole or by digest |
| 2. Disclosure and review | The four-stage state machine; submission and DOI binding; the review view; reviewer access logging | A colleague with no relationship to the project is named reviewer on a study, opens the review view, and can state in writing what the model did and what the human did for one claim in the manuscript, without asking the operator anything | Which journal or preprint server's submission IDs to bind to first [S10]; whether review-stage access is per reviewer or per editor |
| 3. Outside user | Packaging, documentation, and a second service instance run by someone else | A researcher outside the operator's group completes a study start to finish, submits it with the chain head in the data-availability statement, and a reviewer verifies it against a service the operator does not run | Who runs the second instance; the name of the thing |

Each phase ends with a one-paragraph report in the repository stating what the system now does, in the operator's words. If the operator cannot write that paragraph, the phase is not done.

**What is not planned.** Attribution scoring, retrospective assessment, and attack-surface sweeps are read-side work for after phase 3. They are designed against a real corpus of records, not in advance of one. [S6]

## 10. Open questions

**Open questions.** One line each. A question that needs more than a line is filed here as its first line and left for the phase that reaches it.

- Who operates the first independent service instance, and under what governance, so that it is neither the operator's nor a vendor's. [S7]
- Whether a study's declaration (question plus foreknowledge) is one line or two, and whether anything else is ever required of the researcher at start.
- How the manuscript-to-record binding survives a journal that will not print a chain head in a data-availability statement.
- Whether reconstructed-class evidence should be accepted into a record at all, or only referenced from outside it.
- What the service's retention commitment is, in years. [S7]

* How the service image gets security fixes after the phase that built it ends, when no builder is running. (Filed 2026-10-24 from the phase 0 decision report.)
* How long the write-once journal is retained and in which Object Lock mode, once the retention commitment above is answered. (Filed 2026-10-24.)
  - 2026-10-26, phase 0 only: the operator accepted a ten-year lock in governance mode on both write-once buckets (journal and v1 archive) as the retention decision for phase 0. This is a dated note against the question, not its answer.
* [S8]
* [S9]

---

*Change log.* 2026-10-21: first draft, written from the v1 record after the operator declared v1 closed. 2026-10-24: phase 0 adds a third decision, the operator alert channel, because §5 Liveness names none; §5 Deployment gains the platform-patching reading; §5 gains a Scale paragraph at the operator's direction; three open questions filed in §10 from the phase 0 decision report. 2026-10-26: a dated note in §10 records phase 0's retention (ten years, governance mode) against the open retention question. 2026-10-28: §4 gains the envelope-and-body split and the last-human-event index so automation level is computable from plaintext metadata at any stage; §7 gains Derived labels; an open question filed in §10 [S9]. 2026-10-30: the operator's strategy moved to a private document (`STRATEGY.md`); markers such as [S1] point to it; §10 is retitled, and the reason in §4's dated 2026-10-28 note is reworded.
