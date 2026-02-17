# AGENTS.md

This file defines **normative development rules** for this repository.

All RFC 2119 keywords (**MUST**, **MUST NOT**, **SHOULD**, etc.) are to be interpreted as described in **BCP 14**: RFC 2119 + RFC 8174. ([RFC Editor][1])

---

## 0. Scope and authority model

1. This repository is (currently) **spec-first**. Code, packages, and tooling MAY be introduced later, but the primary artifact is a **single** ReSpec-authored specification: `./index.html`.

2. The agent (including GPT-5.3-Codex) MUST treat itself as a **non-authoritative contributor**. It can propose interpretations and architectures, but it MUST:
   - Separate **what law/standards say** from **what we want to be true**.
   - Preserve falsifiability: claims about “qualified”, “notified”, “listed”, “certified”, “recognized”, “mandated”, etc. MUST be backed by an authoritative source that a verifier can independently check (e.g., EUR-Lex, EC eIDAS dashboard, ETSI/CEN publications, national trusted lists / LOTL).

3. Do not “win arguments by wording”. The point of this repo is to drive toward **verifiable trust** (cryptographic proofs + auditable registries), and to reduce the gap between “legal trust” and “technical trust” without pretending the gap does not exist.

4. This AGENTS.md is normative for all automated agents and human contributors. If other docs conflict, **AGENTS.md wins** unless a later PR explicitly updates AGENTS.md.

---

## 1. Generals

- **NEVER USE MEMORY CACHE.**
- **ALWAYS READ CURRENT FILE STATE FROM DISK OR THE ACTIVE CODE EDITOR BUFFER.**
- **AGENT MEMORY IS A FORBIDDEN STATE / REALITY SOURCE.**
- When uncertain about behavior, **prefer primary specifications and vendor documentation over assumptions.**
- Do not invent behavior. Verify it.

### 1.1 Preservation rule (critical for this repo)

This repository is intentionally heavy on references, long-form reasoning, and “argument text”.

- When refactoring, the agent MUST NOT delete information “because it looks redundant” or “because it feels wrong”.
- The agent MAY:
  - Reorder sections,
  - Extract into sub-sections,
  - Rewrite for clarity,
  - Add missing definitions and cross-references,
  - Add “Interpretation” vs “Mandate” labeling,
  - Add TODOs and issue markers,
  - Add citations and authoritative links,
  - Add explicit dispute notes.

- The agent MUST keep **all original informational content** present in the file unless a task explicitly authorizes removal.

---

## 2. Repository mission

This repository is a **spec-first attempt** to define **GDIS: Global Digital Identity Scheme**.

GDIS is **not** claimed to be a legally-recognised term in any jurisdiction. It is a _web-first technical profile_ that:

1. Treats “digital identity” as **data + a binding + a presentation/verification mechanism** (stable core across jurisdictions). ([pages.nist.gov][2])
2. Requires the _root_ identity anchor to be a **physical identity item** issued under a **governance area** and **mandated/recognized** within that governance area (i.e., legal/administrative binding exists _somewhere_, and we don’t pretend it doesn’t).
3. Requires that physical item to contain:
   - a **chip-backed private key** (or equivalent protected key custody), and
   - **endpoint data** needed to verify legitimacy within the governance area (verification method discovery + status checking).

4. Derives a **GDIS identifier** from the physical document’s **MRZ** (Machine Readable Zone) + a **PID hash** extracted from MRZ-compatible data, and binds it to governance verification via a signed statement. (MRZ is a standardized construct in ICAO Doc 9303; do not invent MRZ semantics.) ([ICAO][3])
5. Materializes the binding as a **VC issued to a DID**, where the DID controller is a **GQSCD**-class device (globally-available end-user device profile) per the GQSCD spec. ([z-base.github.io][4])
6. Requires publication of identifier + verification material in a **decentralized event log** replicated across **N hosts**:
   - **Anyone can join and host** (open replication set).
   - The person decides what hosts receive publication.
   - Governance MAY require mandatory minimum host URLs where the document MUST be posted as a minimum, **but MUST NOT treat that minimum as a maximum** (no artificial ceiling / cartel-by-schema).

7. Defines a **Web Profile** as primary interoperability (W3C/IETF formats and web-deployable protocols), with jurisdictional adapters described explicitly as compatibility layers, not as ontological truth.

Worldview constraint (this repo’s “motive force”): **trust comes from verifier-checkable evidence** (cryptographic proofs + explicit registries), not from client claims, UI “approved lists”, or governance vibes.

---

## 3. Terminology discipline

This repo lives in a swamp of overloaded words. Don’t add more fog.

1. **Differentiate “digital identity” meanings by scope.** The NIST definition is intentionally service-context scoped (“unique representation … in an online transaction”). The UK guidance is more “wallet/document representation” scoped. Both can be simultaneously true, because they’re describing different layers. ([pages.nist.gov][2])

2. **Separate legal recognition from technical assurance**:
   - “Legally qualified” ≠ “cryptographically strong”.
   - The spec may claim “technically comparable” but MUST NOT claim “legally equivalent” unless the law text explicitly supports it.

3. **Be precise about EU terms (when referenced)**:
   - eIDAS defines “electronic identification”, “electronic identification means”, and “person identification data”. If you use those terms, anchor them to Article 3 definitions, not vibes. ([EUR-Lex][5])

4. Use descriptive names over political names. If a word is misleading (e.g., “blockchain”), write the invariant instead.

---

## 4. GDIS: normative model constraints

### 4.1 Physical identity anchor (mandate vs proposal split)

- **Mandate (jurisdictional)**: the physical identity item is issued under a governance area and has whatever legal/administrative force that governance area claims. GDIS MUST model that as an _external fact_ and MUST NOT pretend cryptography creates legal mandate.
- **Proposal (GDIS)**: GDIS formalizes how to convert that anchor into:
  - a stable identifier derivation (MRZ/PID-hash based),
  - a verification endpoint binding,
  - and a portable evidence bundle that verifiers can validate independently.

### 4.2 Cryptographic binding and controller requirements

- The DID controller for the GDIS VC MUST be a **GQSCD**-class device/controller profile.
  Framework item: [https://z-base.github.io/gqscd/](https://z-base.github.io/gqscd/) ([z-base.github.io][4])

- The VC issuance MUST produce verifier-checkable evidence for:
  - issuer authenticity,
  - subject binding,
  - status/revocation freshness,
  - and replay resistance where applicable.

### 4.3 Decentralized event log replication invariants

- Replication MUST be **open participation**: anyone can run a host/origin that gossips verification materials.
- Governance MAY require minimum publication targets, but MUST NOT impose a closed or exclusive replication set.
- The spec MUST define:
  - event ordering/causality model,
  - integrity (hash chaining / Merkle proofs / signature chaining),
  - rotation semantics (key rotation is an event, signed by prior authority where possible),
  - and verifier rules for resolving conflicts (explicit, mechanical).

### 4.4 Threat model honesty

- The agent MUST assume the client environment is potentially hostile unless the trust boundary is cryptographically enforced.
- “Approved software lists” and “certified components” can be governance mechanisms, but they do not magically create technical guarantees by themselves.
- The agent MUST NOT imply that allowlists prevent access by non-compliant clients unless a cryptographic mechanism enforces that property.

---

## 5. Web-first profile rule (MANDATORY)

If EN/CEN/ETSI defines schemas, containers, or interface formats: **acknowledge them, but do not make them the primary profile**.

Instead:

1. Define a **Web Profile** as the primary interoperability profile.
2. Define an **EU Compatibility Profile** (and other jurisdiction compatibility profiles) as mapping layers.

The Web Profile MUST prefer globally deployed web / internet standards for:

- cryptographic containers
- credential formats
- transport protocols
- publication and discovery mechanisms

Acceptable building blocks (examples; not an endorsement of any single stack):

- W3C Digital Credentials API. ([W3C][6])
- WebAuthn / FIDO as a hardware authenticator bridge into the web platform. ([W3C][7])

Hard constraint:

- The spec MUST be “web first”: formats and flows that work in browsers and common developer stacks are the baseline.
- Hardware/security requirements MUST be stated in **physical reality terms** (what must be true about key custody, tamper resistance, user intent, etc.), not as jurisdiction-only paperwork artifacts.

---

## 6. Specification discipline (`index.html`)

When working on `(cwd | root | .)/index.html`:

This applies only when `index.html` exists or a task explicitly asks to create it. Otherwise, do not create or modify it.

### 6.1 Single-file ReSpec rule (NO MODULES)

- The specification MUST be authored as a **single** ReSpec document: `./index.html`.
- Do not split the spec across multiple markdown includes, folders, or module files.
- If content becomes large, refactor by:
  - tightening definitions,
  - using ReSpec sections,
  - moving non-normative background into appendices **within the same file**,
  - and using issue markers (`<p class="issue">`) rather than spawning file trees.

### 6.2 Authoring tool

Use ReSpec.

Canonical references:

```
https://respec.org/docs/
https://respec.org/docs/#using-respec
https://github.com/speced/respec
https://www.w3.org/community/reports/reqs/
```

Script commonly used in `index.html`:

```
https://www.w3.org/Tools/respec/respec-w3c
```

### 6.3 Normative vs informative

This repo attracts “law people” and “crypto people” and both groups are allergic to different ambiguities.

Therefore:

- Any statement about **legal effect** MUST be in a section labeled “Mandate (law/standards)” or equivalent.
- Any architecture proposal MUST be labeled “Design proposal” / “Interpretation” / “Working theory”.
- Any strong claim about “qualification”, “recognition”, “issuer validity”, “PID issuer/provider”, “notified scheme”, “trusted list”, etc. MUST be traceable to:
  - an article/recital in EUR-Lex, OR
  - an EC-operated registry/dashboard view, OR
  - a published ETSI/CEN norm, OR
  - an implementing act/delegated act.

### 6.4 Editing rule for “argument blobs”

The current drafts tend to contain “argument blobs”. The agent SHOULD refactor them into:

- definitions (`<dfn>`),
- numbered lifecycle steps,
- threat model bullets,
- “Mandate vs Proposal” sections,

while preserving every informational statement (see Preservation rule).

---

## 7. Verification

Run the smallest set of checks that covers your change.

- If you change runtime logic or public API: `npm run test`.
- If you touch benchmarks or performance-sensitive code: `npm run bench`.
- If you modify TypeScript build config or emit-related logic: `npm run build`.
- If you change formatting or add files: `npm run format`.

If a required command cannot run in the current environment, state that explicitly and explain why.

### 7.1 Spec verification (when the repo is spec-only)

When changes affect `index.html` (ReSpec):

- Prefer to run a local ReSpec build (or whatever build tooling the repo later introduces).
- If no build tooling exists yet, do at minimum:
  - Validate the HTML is well-formed.
  - Ensure ReSpec config parses.
  - Ensure all references remain intact.
  - Ensure there is a clear separation between normative and informative material.

---

## 8. Architecture rules (apply ONLY when the repo contains `src/` tooling)

The spec comes first, but tools may exist later. When (and only when) there is a `src/` directory, these rules become active.

### 8.1 Minimal Surface Area

Every directory under `src/` represents a single logical unit.

Each unit:

- MUST contain at most one root-level `.ts` file.
- MUST export at most one top-level class OR one top-level function.
- SHOULD remain under ~100 lines of executable logic (imports and type-only declarations excluded).
- The ~100 line budget counts executable statements only and excludes imports, type-only exports, comments, and blank lines.
- MUST have a single, clear responsibility.

If complexity grows:

- Extract a subdirectory.
- Or prefer an external dependency.

Large files are a design failure, not an achievement.

### 8.2 Package Preference Rule

Reimplementation of common infrastructure logic is forbidden.

- Prefer mature, audited packages over ad-hoc boilerplate.
- Do not reimplement encoding, parsing, crypto primitives, validation frameworks, etc.
- Local code MUST focus on domain logic, not infrastructure recreation.

If boilerplate appears repeatedly, dependency evaluation is mandatory.

Dependency evaluation MUST consider maintenance activity within the last 12 months, license compatibility, known security advisories, API stability, and real-world adoption. Record the decision in change notes or the PR description.

### 8.3 Helpers

If helpers are unavoidable:

- They MUST reside under a `.helpers/` directory.
- They MUST be minimal and narrowly scoped.
- They MUST NOT evolve into a general-purpose utility framework.
- They MUST NOT contain domain logic.

A growing `.helpers/` directory indicates architectural drift.

Domain logic means business rules, policy decisions, and data model validation specific to this package. It excludes encoding/decoding, crypto, serialization, I/O, and generic data plumbing.

### 8.4 Types

Reusable structural types MUST be isolated.

Structure:

```
.types/
TypeName/
type.ts
```

Rules:

- Each reusable type gets its own folder.
- The file MUST be named `type.ts`.
- No executable logic is allowed in `.types/`.
- Types define contracts, not behavior.

### 8.5 Errors

Errors MUST be explicit, semantic, and typed.

Structure:

```
.errors/
class.ts
```

Pattern:

```ts
export type PackageNameCode = 'SOME_ERROR_CODE' | 'ANOTHER_ERROR_CODE'

export class PackageNameError extends Error {
  readonly code: PackageNameCode

  constructor(code: PackageNameCode, message?: string) {
    const detail = message ?? code
    super(`{@scope/package-name} ${detail}`)
    this.code = code
    this.name = 'PackageNameError'
  }
}
```

Rules:

- Error codes MUST be semantic string literals.
- Error codes MUST be SCREAMING_SNAKE_CASE and use short domain prefixes when needed (example: `CRYPTO_INVALID_KEY`).
- Throwing raw `Error` is forbidden.
- Every thrown error MUST map to an explicit error code.
- Error messages MUST include package scope.

Errors are part of the public contract.

### 8.6 Forbidden Patterns

- No multi-responsibility modules
- No utility dumping grounds
- No silent boilerplate replication
- No implicit global state
- No hidden cross-layer imports

Architecture must remain explicit and auditable.

Example disallowed: `.helpers/` importing from `src/domain/*`, or `.types/` importing from runtime code.

---

## 9. Framework items (MUST keep; add carefully)

- GQSCD (controller device profile used by GDIS):
  [https://z-base.github.io/gqscd/](https://z-base.github.io/gqscd/) ([z-base.github.io][4])

---

## 10. Reference corpus (MUST NOT delete; reorganise only)

Raw reference links are preserved below as **data**, not as an endorsement of any single governance model. Keep them intact; add to them carefully.

```
Initial Mandate
- Directive 1999/93/EC on a Community framework for electronic signatures — https://eur-lex.europa.eu/eli/dir/1999/93/oj
- Regulation (EU) No 910/2014 on electronic identification and trust services (eIDAS) — https://eur-lex.europa.eu/eli/reg/2014/910/oj
- Regulation (EU) 2024/1183 establishing the European Digital Identity Framework (eIDAS amendment) — https://eur-lex.europa.eu/eli/reg/2024/1183/oj

- eIDAS: repeal of Directive 1999/93/EC — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018#d1e1459-1
- European Council Conclusions on Digital Single Market & cross-border digital trust — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018

Supplemental (contextual background)
- eSignature Directive (Directive 1999/93/EC) — Wikipedia entry — https://en.wikipedia.org/wiki/Electronic_Signatures_Directive
- eIDAS Regulation (EU 910/2014) — Wikipedia entry — https://en.wikipedia.org/wiki/EIDAS

Values & Goals
- EU Digital Identity Wallet overview (European Commission) — https://commission.europa.eu/topics/digital-economy-and-society/european-digital-identity_en
- European Digital Identity (EUDI) Regulation policy page — https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation
- EU Digital Identity Wallet (digital-building-blocks site) — https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/694487738/EU%2BDigital%2BIdentity%2BWallet%2BHome
- Regulation (EU) 2024/1183 (Official Journal) — https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng
- eIDAS Regulation background & goals (Digital Strategy page) — https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation
- EU Digital Identity Wallet (Wikipedia) — https://en.wikipedia.org/wiki/EU_Digital_Identity_Wallet

Hard Requirements (disputable only with explicit reasoning)
- eIDAS Regulation (consolidated) — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018
- eIDAS Amendment Regulation (EU) 2024/1183 — https://eur-lex.europa.eu/eli/reg/2024/1183/oj

- QSCD Security Assessment Standards Decision (EU) 2016/650 — https://eur-lex.europa.eu/eli/dec_impl/2016/650/oj

- Remote QSCD Requirements (EU) 2025/1567 — https://eur-lex.europa.eu/eli/reg_impl/2025/1567/oj
- QTSP Requirements (EU) 2025/2530 — https://eur-lex.europa.eu/eli/reg_impl/2025/2530/oj
- CAB Accreditation (EU) 2025/2162 — https://eur-lex.europa.eu/eli/reg_impl/2025/2162/oj

- Qualified Validation Services (EU) 2025/1942 — https://eur-lex.europa.eu/eli/reg_impl/2025/1942/oj
- Signature Validation Rules (EU) 2025/1945 — https://eur-lex.europa.eu/eli/reg_impl/2025/1945/oj
- Qualified Preservation Services (EU) 2025/1946 — https://eur-lex.europa.eu/eli/reg_impl/2025/1946/oj

- Qualified Certificates Standards (EU) 2025/1943 — https://eur-lex.europa.eu/eli/reg_impl/2025/1943/oj
- Identity Verification Standards (EU) 2025/1566 — https://eur-lex.europa.eu/eli/reg_impl/2025/1566/oj

- QEAA Attestations (EU) 2025/1569 — https://eur-lex.europa.eu/eli/reg_impl/2025/1569/oj
- QERDS Interoperability (EU) 2025/1944 — https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj

- EUDI Wallet Integrity (EU) 2024/2979 — https://eur-lex.europa.eu/eli/reg_impl/2024/2979/oj
- EUDI Wallet Protocols (EU) 2024/2982 — https://eur-lex.europa.eu/eli/reg_impl/2024/2982/oj

- Wallet Security Breach Rules (EU) 2025/847 — https://eur-lex.europa.eu/eli/reg_impl/2025/847/oj
- Wallet Relying Party Registration (EU) 2025/848 — https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj
- Certified Wallet Notification (EU) 2025/849 — https://eur-lex.europa.eu/eli/reg_impl/2025/849/oj

- ETSI EN 319 401 — https://www.etsi.org/deliver/etsi_en/319400_319499/319401/03.01.01_60/en_319401v030101p.pdf
- ETSI EN 319 411-2 — https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.00_20/en_31941102v020600a.pdf
- ETSI EN 319 421 — https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf

- CEN EN 419 241-1 — https://standards.iteh.ai/catalog/standards/cen/0a3d58ed-04b4-4d14-a69e-2647c47e26ba/en-419241-1-2018
- CEN EN 419 221-5 — https://standards.iteh.ai/catalog/standards/cen/3e27cc07-2782-4c65-81b7-474d858a471c/en-419221-5-2018

- EU Trusted Lists — https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists
- QSCD Notifications — https://eidas.ec.europa.eu/efda/browse/notification/qscd-sscd

Infra / Language
- ECMA-262 — https://tc39.es/ecma262/
- WHATWG Infra — https://infra.spec.whatwg.org/
- Infra Extension — https://www.w3.org/TR/xmlschema11-2/
- Base64Url — https://base64.guru/standards/base64url
- JSON — https://www.rfc-editor.org/rfc/rfc8259
- URI — https://www.rfc-editor.org/rfc/rfc3986

Formal Alternatives
- SEDI — https://le.utah.gov/~2026/bills/static/SB0275.html
- UN — https://untp.unece.org/docs/specification/Architecture/
- ICC — https://iccwbo.org/news-publications/policies-reports/the-icc-guide-to-authenticate-certificates-of-origin-for-international-business/

Identifiers / Credentials
- DID Use Cases — https://www.w3.org/TR/did-use-cases/
- DID Core v1.0 — https://www.w3.org/TR/did-core/
- DID Core v1.1 — https://www.w3.org/TR/did-1.1/
- DID Test Suite — https://w3c.github.io/did-test-suite/
- DID Extensions — https://www.w3.org/TR/did-extensions/

- VC Data Model v2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- VC Overview — https://www.w3.org/TR/vc-overview/
- VC Test Suite — https://w3c.github.io/vc-test-suite/
- Distributed Ledger Technologies — https://en.wikipedia.org/wiki/Distributed_ledger

JSON-LD / RDF
- JSON-LD 1.1 — https://www.w3.org/TR/json-ld11/
- JSON-LD API — https://www.w3.org/TR/json-ld11-api/
- RDF Concepts — https://www.w3.org/TR/rdf11-concepts/
- RDF Schema — https://www.w3.org/TR/rdf-schema/
- Schema Org — https://schema.org/docs/schemas.html

WebCrypto
- Web Cryptography Level 2 — https://www.w3.org/TR/webcrypto-2/

JOSE
- JWS — https://www.rfc-editor.org/rfc/rfc7515.html
- JWE — https://www.rfc-editor.org/rfc/rfc7516.html
- JWK — https://www.rfc-editor.org/rfc/rfc7517.html
- JWA — https://www.rfc-editor.org/rfc/rfc7518.html
- JWT — https://www.rfc-editor.org/rfc/rfc7519.html
- JWS Unencoded Payload — https://www.rfc-editor.org/rfc/rfc7797.html
- JWT BCP — https://www.rfc-editor.org/rfc/rfc8725.html
- JWT/JWS Updates — https://www.rfc-editor.org/rfc/rfc9864.html
- JOSE Cookbook — https://www.rfc-editor.org/rfc/rfc7520.html
- JWK Thumbprint — https://www.rfc-editor.org/rfc/rfc7638.html
- EdDSA for JOSE — https://www.rfc-editor.org/rfc/rfc8037.html
- IANA JOSE Registries — https://www.iana.org/assignments/jose/jose.xhtml

Infrastructure
- HTTP — https://datatracker.ietf.org/doc/html/rfc9110
- IPFS & IPNS — https://docs.ipfs.tech/

Ideas
- KERI — https://trustoverip.github.io/kswg-keri-specification/
- ACDA — https://trustoverip.github.io/kswg-acdc-specification/
- CESR — https://trustoverip.github.io/kswg-cesr-specification/
- SELF — https://docs.self.xyz/
```

---

## 11. Philosophy

Small modules.
Explicit contracts.
Typed errors.
Spec-first reasoning.
Dependency over reinvention.
No hidden state.

Architecture is a constraint system, not a suggestion.

### 11.1 Clarification (because “modules” is overloaded)

- “modules” above refers to **code units under `src/`** (if/when they exist).
- The specification itself MUST remain a **single** ReSpec file (`./index.html`) per §6.1.

---

## 12. Non-normative residue (kept for preservation)

```
::contentReference[oaicite:0]{index=0}
```

[1]: https://chatgpt.com/c/6991dc4a-72a0-8394-844f-af750f7fb6f5 'EUDI vs SEDI Debate'
[2]: https://chatgpt.com/c/69907277-9adc-838a-93d2-b05f1d4c4112 'EUDI vs SEDI Debate'
[1]: https://www.rfc-editor.org/info/rfc2119?utm_source=chatgpt.com 'Information on RFC 2119 » RFC Editor'
[2]: https://pages.nist.gov/800-63-3/sp800-63-3.html?utm_source=chatgpt.com 'NIST Special Publication 800-63-3'
[3]: https://www.icao.int/publications/Documents/9303_p7_cons_en.pdf?utm_source=chatgpt.com 'Doc 9303
Machine Readable Travel Documents
Eighth'
[4]: https://z-base.github.io/gqscd/ 'Globally Qualified Signature Creation Device (GQSCD) Core'
[5]: https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng?utm_source=chatgpt.com 'EUR-Lex - 02014R0910-20241018 - DE - EUR-Lex'
[6]: https://www.w3.org/TR/digital-credentials/all/?utm_source=chatgpt.com 'Cover page | digital-credentials | W3C standards and drafts | W3C'
[7]: https://www.w3.org/TR/webauthn-3/?utm_source=chatgpt.com 'Web Authentication: An API for accessing Public Key Credentials - Level 3'
