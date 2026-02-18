# AGENTS.md

This file defines **normative development rules** for this repository.

All RFC 2119 keywords (**MUST**, **MUST NOT**, **SHOULD**, etc.) are to be interpreted as described in **BCP 14**: RFC 2119 + RFC 8174. ([RFC Editor][1])

---

## 0. Scope and authority model

1. This repository is **spec-first**.

   The canonical specification is a **single** ReSpec-authored document:
   - `./index.html` (the GQTS Core specification)

   The canonical interface description is:
   - `./openapi.yaml` (OpenAPI 3.1+; the normative API surface)

   Generated HTML documentation is derivative output:
   - `./openapi/` (generated OpenAPI HTML site)
   - (optional) other generated artifacts as explicitly added later

2. The agent (including GPT-5.\*-Codex) MUST treat itself as a **non-authoritative contributor**. It can propose interpretations and architectures, but it MUST:
   - Separate **what standards/law say** from **what we want to be true**.
   - Preserve falsifiability: claims about “qualified”, “notified”, “listed”, “certified”, “recognized”, “mandated”, etc. MUST be backed by an authoritative source that a verifier can independently check.

3. Do not “win arguments by wording”. The point of this repo is to drive toward **verifier-checkable trust** (cryptographic proofs + mechanically defined registries/logs), not governance vibes.

4. This AGENTS.md is normative for all automated agents and human contributors. If other docs conflict, **AGENTS.md wins** unless a later PR explicitly updates AGENTS.md.

---

## 1. Generals (reality discipline)

- **NEVER USE MEMORY CACHE.**
- **ALWAYS READ CURRENT FILE STATE FROM DISK OR THE ACTIVE CODE EDITOR BUFFER.**
- **AGENT MEMORY IS A FORBIDDEN STATE / REALITY SOURCE.**
- When uncertain about behavior, requirements, or legal meaning, **prefer primary sources** (IETF/W3C specs, EUR-Lex/OJ, ETSI/CEN publications, vendor docs) over assumptions.
- Do not invent behavior. Verify it.

### 1.1 Preservation rule (critical for this repo)

This repository is intentionally heavy on references, invariants, and “argument text”.

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
- The agent MUST keep **all original informational content** present in a file unless a task explicitly authorizes removal.

---

## 2. Repository mission and system decomposition

### 2.1 Framework naming (DO NOT CONFUSE)

- **GIDAS (Global Identity, Authentication, and Trust Services)** is the _framework umbrella_.
- **GDIS (Global Digital Identity Scheme)** is a _component_ under GIDAS: it specifies how a natural person can be synthesized into verifiable digital identity material.
- **GQTS (Globally Qualified Trust Service) Core** is a _component_ under GIDAS: it specifies how verification material is hosted durably, tamper-evidently, interoperably, and in an open-participation replicated way.

This repo is about **GQTS Core**.

### 2.2 What GQTS Core MUST define

GQTS Core MUST define:

1. A **durable publication model** for verification material (availability semantics, caching semantics, replay semantics).
2. A **tamper-evident event history** model (append-only history; divergence detection; explicit merge semantics).
3. An **open replication set** model (anyone can host; no closed lists by schema).
4. A **web-first interoperability profile** (things that work with normal HTTP stacks, browsers, and common developer tooling).
5. A **mechanical verifier algorithm**: how a verifier fetches, validates, detects conflicts, and chooses a valid head.

Working theory constraint (repo motive force): **trust comes from verifier-checkable evidence**, not from allowlists, UI claims, or “authority says so”.

---

## 3. Terminology discipline (don’t add fog)

1. Every normative term MUST be defined (prefer ReSpec `<dfn>` in `index.html`).
2. “Distributed” ≠ “decentralized”. A distributed system can still be centralized.
3. Avoid political nouns (“blockchain”) unless the invariant is written directly in the same breath.
4. Separate legal status from technical assurance:
   - “Legally qualified” ≠ “cryptographically strong”.
   - “Certified component list” ≠ “technical enforcement” unless enforced cryptographically.

---

## 4. GQTS Core: normative model constraints

### 4.1 Well-known discovery path (MANDATORY DEFAULT)

GQTS Core SHOULD use `/.well-known/` for discovery. The default discovery namespace is:

`/.well-known/gidas/gqts/<kind>/<id>`

Where:

- `<kind>` is an enumerated token set (NOT open-ended):
  - `type` — host capability and profile metadata
  - `event` — event log material (by namespace/topic)
  - `scheme` — governance/pids/scheme metadata (when applicable)

- `<id>` is either:
  - `<uuid>` (for non-governance-scoped logs), OR
  - `<governance-code>` (for governance-scoped namespaces)

Rules:

- The spec MUST define the allowed character set and normalization rules for `<governance-code>`.
- The spec MUST define content types per endpoint (e.g., JSON, CBOR, etc.) and versioning strategy.
- The spec MUST define caching validators (ETag semantics) for immutable vs append-only resources.

### 4.2 Tamper-evident event history invariants (NON-NEGOTIABLE)

GQTS MUST provide a tamper-evident history per namespace/topic such that:

- History is **append-only** (corrections are new events, not edits).
- Divergence is detectable (heads/commitments differ).
- Merge is explicit (a merge is itself an event referencing parents/heads).
- Verification is mechanical (no “trust me” steps).
- Replication is opportunistic (hosts fetch/compare heads and only do heavy work on mismatch).

Efficiency rule:

- A host MUST NOT trigger heavy merge work unless a **history head / commitment** differs.
- Fetch SHOULD be conditional to avoid wasting compute/bandwidth.

### 4.3 Open participation replication (minimum is not maximum)

- Replication MUST be open participation: anyone can run a host/origin that gossips verification materials.
- A governance area MAY require a minimum publication target set, but MUST NOT define a maximum or exclusive set by schema.

### 4.4 Threat model honesty

- Client environments are assumed hostile unless the trust boundary is cryptographically enforced.
- “Approved lists” are governance signals, not technical enforcement.
- The spec MUST NOT imply allowlists prevent access by non-compliant clients unless a cryptographic mechanism enforces that property.

---

## 5. Interface discipline (OpenAPI is normative)

### 5.1 OpenAPI as the normative interface

- All endpoints MUST be formally described in `./openapi.yaml` as **OpenAPI 3.1+**.
- `openapi.yaml` is the **source of truth** for endpoints (NOT prose in `index.html`).

### 5.2 Sync vs async semantics (the reality-based rule)

This repo uses a simple semantic split:

- **GET** endpoints are synchronous: the response is the requested representation (or a conditional “not modified” response).
- **POST** endpoints MAY be _logically async_ even if transported over HTTP:
  - For “ingest/gossip/publish” operations, POST SHOULD return `202 Accepted` plus a correlation id (or event id).
  - The actual propagation/merge effects MUST be modeled as event history changes (fetchable/verifiable).

If a POST endpoint is truly synchronous (rare), it MUST justify why it cannot be expressed as “append event; observe via history”.

### 5.3 ReSpec cross-linking rule (MANDATORY)

`./index.html` (ReSpec) MUST reference the OpenAPI surface by **relative link**:

- In prose: link to `./openapi/` (rendered HTML) and `./openapi.yaml` (source).
- Normative sections describing protocol behavior MUST include stable anchors that point to the relevant OpenAPI operationIds and schema components.

Hard rule:

- ReSpec MUST NOT duplicate endpoint semantics that are already normative in OpenAPI.
- ReSpec MAY explain invariants, security properties, and verifier algorithms that interpret OpenAPI-delivered data.

---

## 6. Specification discipline (`./index.html`)

### 6.1 Single-file ReSpec rule (NO MODULES)

- The specification MUST be authored as a **single** ReSpec document: `./index.html`.
- Do not split the spec across multiple markdown includes, folders, or module files.
- If content becomes large, refactor by:
  - using ReSpec sections,
  - moving non-normative background into appendices **within the same file**,
  - using issue markers rather than spawning file trees.

### 6.2 Authoring tool

Use ReSpec.

Canonical references:

- https://respec.org/docs/
- https://github.com/speced/respec
- https://www.w3.org/Tools/respec/respec-w3c

### 6.3 Normative vs informative separation

- Any statement about **legal effect** MUST be in a clearly labeled “Mandate (law/standards)” section.
- Any architecture proposal MUST be labeled “Design proposal” / “Working theory”.
- Any strong claim about “qualification”, “recognition”, “issuer validity”, etc. MUST be traceable to an authoritative source.

---

## 7. Toolchain (MANDATORY) — OpenAPI authoring + HTML output at repo root

### 7.1 VS Code authoring experience (Redocly)

The default “ReSpec-but-for-OpenAPI” authoring experience is **Redocly’s OpenAPI stack**:

- Use the Redocly OpenAPI VS Code extension for validation, `$ref` navigation, and doc preview.
- Keep `redocly.yaml` at repo root when using custom rulesets.

Rules:

- OpenAPI MUST be written in YAML (do not introduce JSON variants unless explicitly decided).
- Multi-file `$ref` is allowed, but `./openapi.yaml` MUST remain the canonical entrypoint.

### 7.2 Generating HTML docs at repo root

The OpenAPI documentation MUST be generated into a path that is hosted correctly on GitHub Pages and linkable from ReSpec using **relative links**.

Normative output layout (default):

- `./openapi.yaml` (canonical source)
- `./openapi/index.html` (generated docs)
- `./openapi/` assets as needed (generated)

Rules:

- The generated HTML MUST be deterministic from `openapi.yaml` (no manual edits).
- Links from `index.html` → `openapi/` MUST be relative (`./openapi/`), NOT root-absolute (`/openapi/`).
- Local development MUST serve the repo via a local HTTP server from repo root (NOT `file://`).

### 7.3 GitHub Pages hosting constraints

- The repository MUST be hostable via GitHub Pages using either:
  - publishing source = repo root (`/`) OR
  - publishing source = `/docs` folder
    (choose one and make it consistent; do not half-do both)

- If GitHub Pages/Jekyll processing breaks the site or rewrites paths, the repo MUST include a `.nojekyll` file at the publishing root.

---

## 8. Verification

Run the smallest set of checks that covers your change.

At minimum, when changing OpenAPI:

- Lint: `redocly lint openapi.yaml`
- Build HTML: `redocly build-docs openapi.yaml --output=openapi/index.html`

When changing ReSpec:

- Serve locally and ensure the document renders and internal links resolve.
- Ensure the OpenAPI references in ReSpec still resolve via relative links.

If a required command cannot run in the current environment, state that explicitly and explain why.

---

## 9. Framework items (MUST keep; add carefully)

- **GIDAS (Global Identity, Authentication, and Trust Services)**  
  Umbrella framework that decomposes identity/authentication/trust services into mechanically specified components with verifier-checkable invariants, avoiding governance-by-vibes and avoiding schema cartels.

- **GDIS (Global Digital Identity Scheme)**  
  Component under GIDAS describing how physical identity evidence is deterministically transformed into verifiable digital identity material, including binding, verification endpoint discovery, and publication of verification material.  
  https://z-base.github.io/gdis/

- **GQSCD (Globally Qualified Signature Creation Device)**  
  Controller device profile used by GDIS. Defines verifiable technical security properties for signature-capable user devices, including hardware, firmware, OS, and application layers. Not a legal certification — a machine-verifiable technical profile.  
  https://z-base.github.io/gqscd/

- **GQTS (Globally Qualified Trust Service) Core**  
  Component under GIDAS defining how verification material is hosted durably, tamper-evidently, and interoperably, with open replication participation and explicit conflict/merge rules.  
  (This repository)

---

## 10. Reference corpus (MUST NOT delete; reorganise only)

Raw reference links are preserved below as **data**, not as an endorsement of any single governance model. Keep them intact; add to them carefully.

````GQTS / Event logs / Replication- Well-Known URIs (/.well-known/) — [https://www.rfc-editor.org/rfc/rfc8615](https://www.rfc-editor.org/rfc/rfc8615)
- OpenAPI Specification v3.1 — [https://spec.openapis.org/oas/v3.1.0.html](https://spec.openapis.org/oas/v3.1.0.html)
- Redocly OpenAPI VS Code Extension — [https://redocly.com/docs/vscode](https://redocly.com/docs/vscode)
- Redocly CLI build-docs — [https://redocly.com/docs/cli/commands/build-docs/](https://redocly.com/docs/cli/commands/build-docs/)
- GitHub Pages: configure publishing source (root or /docs) — [https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
- GitHub Pages: .nojekyll to bypass Jekyll processing — [https://docs.github.com/github/working-with-github-pages/troubleshooting-jekyll-build-errors-for-github-pages-sites](https://docs.github.com/github/working-with-github-pages/troubleshooting-jekyll-build-errors-for-github-pages-sites)Event log candidates (do not collapse into one; compare properties)- CEL Spec (Cryptographic Event Log) — [https://w3c-ccg.github.io/cel-spec/](https://w3c-ccg.github.io/cel-spec/)
- did:webvh — [https://identity.foundation/didwebvh/v1.0/](https://identity.foundation/didwebvh/v1.0/)
- JSON Web History (JWH) — [https://z-base.github.io/json-web-history/](https://z-base.github.io/json-web-history/)Initial Mandate- Directive 1999/93/EC on a Community framework for electronic signatures — [https://eur-lex.europa.eu/eli/dir/1999/93/oj](https://eur-lex.europa.eu/eli/dir/1999/93/oj)

- Regulation (EU) No 910/2014 on electronic identification and trust services (eIDAS) — [https://eur-lex.europa.eu/eli/reg/2014/910/oj](https://eur-lex.europa.eu/eli/reg/2014/910/oj)

- Regulation (EU) 2024/1183 establishing the European Digital Identity Framework (eIDAS amendment) — [https://eur-lex.europa.eu/eli/reg/2024/1183/oj](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)

- eIDAS: repeal of Directive 1999/93/EC — [https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018#d1e1459-1](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018#d1e1459-1)

- European Council Conclusions on Digital Single Market & cross-border digital trust — [https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018)Supplemental (contextual background)- eSignature Directive (Directive 1999/93/EC) — Wikipedia entry — [https://en.wikipedia.org/wiki/Electronic_Signatures_Directive](https://en.wikipedia.org/wiki/Electronic_Signatures_Directive)
- eIDAS Regulation (EU 910/2014) — Wikipedia entry — [https://en.wikipedia.org/wiki/EIDAS](https://en.wikipedia.org/wiki/EIDAS)Values & Goals- EU Digital Identity Wallet overview (European Commission) — [https://commission.europa.eu/topics/digital-economy-and-society/european-digital-identity_en](https://commission.europa.eu/topics/digital-economy-and-society/european-digital-identity_en)
- European Digital Identity (EUDI) Regulation policy page — [https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation](https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation)
- EU Digital Identity Wallet (digital-building-blocks site) — [https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/694487738/EU%2BDigital%2BIdentity%2BWallet%2BHome](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/694487738/EU%2BDigital%2BIdentity%2BWallet%2BHome)
- Regulation (EU) 2024/1183 (Official Journal) — [https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng](https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng)
- eIDAS Regulation background & goals (Digital Strategy page) — [https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)
- EU Digital Identity Wallet (Wikipedia) — [https://en.wikipedia.org/wiki/EU_Digital_Identity_Wallet](https://en.wikipedia.org/wiki/EU_Digital_Identity_Wallet)Hard Requirements (disputable only with explicit reasoning)- eIDAS Regulation (consolidated) — [https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018)

- eIDAS Amendment Regulation (EU) 2024/1183 — [https://eur-lex.europa.eu/eli/reg/2024/1183/oj](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)

- QSCD Security Assessment Standards Decision (EU) 2016/650 — [https://eur-lex.europa.eu/eli/dec_impl/2016/650/oj](https://eur-lex.europa.eu/eli/dec_impl/2016/650/oj)

- Remote QSCD Requirements (EU) 2025/1567 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1567/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1567/oj)

- QTSP Requirements (EU) 2025/2530 — [https://eur-lex.europa.eu/eli/reg_impl/2025/2530/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/2530/oj)

- CAB Accreditation (EU) 2025/2162 — [https://eur-lex.europa.eu/eli/reg_impl/2025/2162/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/2162/oj)

- Qualified Validation Services (EU) 2025/1942 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1942/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1942/oj)

- Signature Validation Rules (EU) 2025/1945 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1945/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1945/oj)

- Qualified Preservation Services (EU) 2025/1946 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1946/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1946/oj)

- Qualified Certificates Standards (EU) 2025/1943 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1943/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1943/oj)

- Identity Verification Standards (EU) 2025/1566 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1566/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1566/oj)

- QEAA Attestations (EU) 2025/1569 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1569/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1569/oj)

- QERDS Interoperability (EU) 2025/1944 — [https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj)

- EUDI Wallet Integrity (EU) 2024/2979 — [https://eur-lex.europa.eu/eli/reg_impl/2024/2979/oj](https://eur-lex.europa.eu/eli/reg_impl/2024/2979/oj)

- EUDI Wallet Protocols (EU) 2024/2982 — [https://eur-lex.europa.eu/eli/reg_impl/2024/2982/oj](https://eur-lex.europa.eu/eli/reg_impl/2024/2982/oj)

- Wallet Security Breach Rules (EU) 2025/847 — [https://eur-lex.europa.eu/eli/reg_impl/2025/847/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/847/oj)

- Wallet Relying Party Registration (EU) 2025/848 — [https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj)

- Certified Wallet Notification (EU) 2025/849 — [https://eur-lex.europa.eu/eli/reg_impl/2025/849/oj](https://eur-lex.europa.eu/eli/reg_impl/2025/849/oj)

- ETSI EN 319 401 — [https://www.etsi.org/deliver/etsi_en/319400_319499/319401/03.01.01_60/en_319401v030101p.pdf](https://www.etsi.org/deliver/etsi_en/319400_319499/319401/03.01.01_60/en_319401v030101p.pdf)

- ETSI EN 319 411-2 — [https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.00_20/en_31941102v020600a.pdf](https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.00_20/en_31941102v020600a.pdf)

- ETSI EN 319 421 — [https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf](https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf)

- CEN EN 419 241-1 — [https://standards.iteh.ai/catalog/standards/cen/0a3d58ed-04b4-4d14-a69e-2647c47e26ba/en-419241-1-2018](https://standards.iteh.ai/catalog/standards/cen/0a3d58ed-04b4-4d14-a69e-2647c47e26ba/en-419241-1-2018)

- CEN EN 419 221-5 — [https://standards.iteh.ai/catalog/standards/cen/3e27cc07-2782-4c65-81b7-474d858a471c/en-419221-5-2018](https://standards.iteh.ai/catalog/standards/cen/3e27cc07-2782-4c65-81b7-474d858a471c/en-419221-5-2018)

- EU Trusted Lists — [https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists](https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists)

- QSCD Notifications — [https://eidas.ec.europa.eu/efda/browse/notification/qscd-sscd](https://eidas.ec.europa.eu/efda/browse/notification/qscd-sscd)Infra / Language- ECMA-262 — [https://tc39.es/ecma262/](https://tc39.es/ecma262/)
- WHATWG Infra — [https://infra.spec.whatwg.org/](https://infra.spec.whatwg.org/)
- Infra Extension — [https://www.w3.org/TR/xmlschema11-2/](https://www.w3.org/TR/xmlschema11-2/)
- Base64Url — [https://base64.guru/standards/base64url](https://base64.guru/standards/base64url)
- JSON — [https://www.rfc-editor.org/rfc/rfc8259](https://www.rfc-editor.org/rfc/rfc8259)
- URI — [https://www.rfc-editor.org/rfc/rfc3986](https://www.rfc-editor.org/rfc/rfc3986)
- HTTP — [https://datatracker.ietf.org/doc/html/rfc9110](https://datatracker.ietf.org/doc/html/rfc9110)
- RegExp -- [https://datatracker.ietf.org/doc/html/rfc9485](https://datatracker.ietf.org/doc/html/rfc9485)
- RegExp Api --  [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions)Formal Alternatives- SEDI — [https://le.utah.gov/~2026/bills/static/SB0275.html](https://le.utah.gov/~2026/bills/static/SB0275.html)
- UN — [https://untp.unece.org/docs/specification/Architecture/](https://untp.unece.org/docs/specification/Architecture/)
- ICC — [https://iccwbo.org/news-publications/policies-reports/the-icc-guide-to-authenticate-certificates-of-origin-for-international-business/](https://iccwbo.org/news-publications/policies-reports/the-icc-guide-to-authenticate-certificates-of-origin-for-international-business/)Identifiers / Credentials- DID Use Cases — [https://www.w3.org/TR/did-use-cases/](https://www.w3.org/TR/did-use-cases/)

- DID Core v1.0 — [https://www.w3.org/TR/did-core/](https://www.w3.org/TR/did-core/)

- DID Core v1.1 — [https://www.w3.org/TR/did-1.1/](https://www.w3.org/TR/did-1.1/)

- DID Test Suite — [https://w3c.github.io/did-test-suite/](https://w3c.github.io/did-test-suite/)

- DID Extensions — [https://www.w3.org/TR/did-extensions/](https://www.w3.org/TR/did-extensions/)

- VC Data Model v2.0 — [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)

- VC Overview — [https://www.w3.org/TR/vc-overview/](https://www.w3.org/TR/vc-overview/)

- VC Test Suite — [https://w3c.github.io/vc-test-suite/](https://w3c.github.io/vc-test-suite/)

- Distributed Ledger Technologies — [https://en.wikipedia.org/wiki/Distributed_ledger](https://en.wikipedia.org/wiki/Distributed_ledger)JSON-LD / RDF- JSON-LD 1.1 — [https://www.w3.org/TR/json-ld11/](https://www.w3.org/TR/json-ld11/)
- JSON-LD API — [https://www.w3.org/TR/json-ld11-api/](https://www.w3.org/TR/json-ld11-api/)
- RDF Concepts — [https://www.w3.org/TR/rdf11-concepts/](https://www.w3.org/TR/rdf11-concepts/)
- RDF Schema — [https://www.w3.org/TR/rdf-schema/](https://www.w3.org/TR/rdf-schema/)
- Schema Org — [https://schema.org/docs/schemas.html](https://schema.org/docs/schemas.html)WebCrypto- Web Cryptography Level 2 — [https://www.w3.org/TR/webcrypto-2/](https://www.w3.org/TR/webcrypto-2/)JOSE- JWS — [https://www.rfc-editor.org/rfc/rfc7515.html](https://www.rfc-editor.org/rfc/rfc7515.html)
- JWE — [https://www.rfc-editor.org/rfc/rfc7516.html](https://www.rfc-editor.org/rfc/rfc7516.html)
- JWK — [https://www.rfc-editor.org/rfc/rfc7517.html](https://www.rfc-editor.org/rfc/rfc7517.html)
- JWA — [https://www.rfc-editor.org/rfc/rfc7518.html](https://www.rfc-editor.org/rfc/rfc7518.html)
- JWT — [https://www.rfc-editor.org/rfc/rfc7519.html](https://www.rfc-editor.org/rfc/rfc7519.html)
- JWS Unencoded Payload — [https://www.rfc-editor.org/rfc/rfc7797.html](https://www.rfc-editor.org/rfc/rfc7797.html)
- JWT BCP — [https://www.rfc-editor.org/rfc/rfc8725.html](https://www.rfc-editor.org/rfc/rfc8725.html)
- JWT/JWS Updates — [https://www.rfc-editor.org/rfc/rfc9864.html](https://www.rfc-editor.org/rfc/rfc9864.html)
- JOSE Cookbook — [https://www.rfc-editor.org/rfc/rfc7520.html](https://www.rfc-editor.org/rfc/rfc7520.html)
- JWK Thumbprint — [https://www.rfc-editor.org/rfc/rfc7638.html](https://www.rfc-editor.org/rfc/rfc7638.html)
- EdDSA for JOSE — [https://www.rfc-editor.org/rfc/rfc8037.html](https://www.rfc-editor.org/rfc/rfc8037.html)
- IANA JOSE Registries — [https://www.iana.org/assignments/jose/jose.xhtml](https://www.iana.org/assignments/jose/jose.xhtml)Infrastructure- IPFS & IPNS — [https://docs.ipfs.tech/](https://docs.ipfs.tech/)Ideas- KERI — [https://trustoverip.github.io/kswg-keri-specification/](https://trustoverip.github.io/kswg-keri-specification/)
- ACDA — [https://trustoverip.github.io/kswg-acdc-specification/](https://trustoverip.github.io/kswg-acdc-specification/)
- CESR — [https://trustoverip.github.io/kswg-cesr-specification/](https://trustoverip.github.io/kswg-cesr-specification/)
- SELF — [https://docs.self.xyz/](https://docs.self.xyz/)```

---

## 11. Philosophy

Explicit contracts.
Spec-first reasoning.
Dependency over reinvention.
No hidden state.

Architecture is a constraint system, not a suggestion.

---

## 12. Non-normative residue (kept for preservation)

```([respec.org][1])```

[1]: https://www.rfc-editor.org/info/bcp14 'Information on BCP 14'
```Toolchain/source pointers that informed the constraints above: ReSpec docs ([respec.org][1]), OpenAPI 3.1 spec ([OpenAPI Initiative Publications][2]), Redocly VS Code + CLI build-docs ([redocly.com][3]), GitHub Pages publishing roots and `.nojekyll` behavior ([GitHub Docs][4]), and `/.well-known/` reservation ([RFC Editor][5]).[1]: https://respec.org/docs/?utm_source=chatgpt.com "ReSpec Documentation"[2]: https://spec.openapis.org/oas/v3.1.0.html?utm_source=chatgpt.com "OpenAPI Specification v3.1.0"[3]: https://redocly.com/docs/vscode?utm_source=chatgpt.com "Redocly OpenAPI VS Code extension"[4]: https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site?utm_source=chatgpt.com "Configuring a publishing source for your GitHub Pages site - GitHub Docs"[5]: https://www.rfc-editor.org/rfc/rfc8615?utm_source=chatgpt.com "RFC 8615: Well-Known Uniform Resource Identifiers (URIs)"
````
