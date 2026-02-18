# Globally Qualified Signature Creation Device (GQSCD) Core — Deep Research Report

## Executive summary

“GQSCD Core” is currently published as an Editor’s Draft specification that defines how _end‑user devices_ (hardware, firmware, OS, and application components) can provide **cryptographically verifiable** signature‑creation properties aligned to “qualified signature” security objectives (explicitly mapped to EU-style requirements). citeturn35view0turn35view1

The spec is explicit that it is **technical only** and **does not itself grant legal qualification**. Instead, it positions itself as a _baseline_ that must be extended by platform-specific “implementing specifications” and accompanied by auditable evidence artifacts suitable for certification and (in the EU context) notification workflows. citeturn35view0turn35view1

The anchor legal target it maps to is the eIDAS Annex II objective set for a **Qualified Electronic Signature Creation Device (QSCD)**: confidentiality of signature-creation data, uniqueness/non-derivability, protection against forgery and misuse, presentation of data prior to signing and non-alteration, plus strict constraints on server-side generation/management and backup duplication (QTSP-only, minimal copies, equal security). citeturn38view0

Architecturally, GQSCD Core’s most distinctive move is to treat qualification-like properties as a **zero-trust verification** problem: decisions should be based on **per-transaction evidence** and policy evaluation rather than “labels,” network location, or relying-party assertions. Its threat model is not gentle: it explicitly includes network adversaries, malicious local processes, UI overlay/tapjacking, rollback attempts, and dishonest relying parties, and it requires cryptographic verification of evidence rather than trust theatre. citeturn35view1

In practical cryptographic terms, the GitHub corpus around the spec strongly suggests a convergence on: (a) **hardware-backed non-exportable keys** (e.g., secure element/TPM/FIDO authenticator class), (b) **explicit user-intent binding** to the exact payload digest (protected confirmation patterns), and (c) portable evidence formats that web ecosystems can consume. citeturn35view1turn35view3turn35view2

The hard problem is not “can we sign”; it is **can we prove—across platforms and over time—that the signature was created under constraints equivalent to Annex II**. In existing ecosystems, even determining QSCD compliance during validation can be non-trivial, and some validation policies explicitly allow outcomes where QSCD status cannot be determined. citeturn10search0

**Steffen-style critiques (high-level):**

- **Attestation is a fragile root of trust.** A “zero-trust verification model” still collapses to whoever controls attestation roots, revocation, and device identity semantics; this is particularly sensitive when the spec simultaneously claims “digital sovereignty” and interoperability as design objectives. citeturn35view0turn35view1
- **User intent is semantic, but the device verifies bytes.** Protected confirmation frequently binds to a digest or prompt text; the gulf between what the user _thinks_ they sign and what the device _actually_ signs is where high-value attacks live. citeturn35view1turn35view3
- **Annex II language is inherently squishy (“reasonably assured”, “currently available technology”).** Any attempt at a global, web-first “core” risks underspecifying the needed assurance boundary, and implementers will fill gaps inconsistently unless testable profiles become normative. citeturn38view0turn35view0

## GitHub Pages corpus review

### Method and coverage limits

You requested “exhaustively covering all pages on github.io.” Taken literally, that is unbounded (GitHub Pages is effectively a hosting substrate for much of the public web). What is feasible—and what this research did—is: **exhaustively cover the GQSCD Core GitHub Pages site**, then **systematically locate and analyze other github.io material that is directly relevant** (QSCD/remote signing/SCAL2/EUDI wallet context), using link traversal and targeted discovery. citeturn35view0turn7search2turn9view0

### GitHub Pages (github.io) URLs examined

```text
https://z-base.github.io/gqscd/
https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/2.5.0/
https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.9.0/annexes/annex-2/annex-2-high-level-requirements/
https://swedenconnect.github.io/technical-framework/
https://open-eid.github.io/SiVa/siva/appendix/validation_policy/
https://open-eid.github.io/SiVa/siva2/appendix/validation_policy/
https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/
https://open-eid.github.io/allkirjastamisteenus/business-description/
https://open-eid.github.io/allkirjastamisteenus/json-technical-description/
https://open-eid.github.io/allkirjastamisteenus/technical-description/
https://open-eid.github.io/libdigidocpp/manual.html
https://peculiarventures.github.io/ExamplePDFs/signed/aatl_technical_requirements_v2.0.pdf
```

Supporting GitHub corpus highlights:

- The **GQSCD Core spec itself** defines scope, profiles (Web Profile + EU Compatibility Profile), evidence terminology, explicit threat model, and multiple reference configuration profiles (e.g., smartphone profile using verified boot + rollback protections + protected confirmation; laptop profile using UEFI secure boot + TPM measured boot + trusted intent path). citeturn35view0turn35view1turn35view3
- The **EUDI Wallet Architecture & Reference Framework** corpus includes requirements tying wallet-based qualified signing components to existing remote-signing standards and SCAL2 (see the explicit SCAL2 + ETSI requirements in Annex 2). citeturn7search2turn11search14
- The **Sweden Connect technical framework** publishes a concrete protocol pattern for **Signature Activation Data (SAD)** carried as a signed JWT (JWS), which is explicitly motivated by SCAL2 and prEN/CEN 419241 family considerations. citeturn9view0turn8view0
- The **Open‑EID** GitHub pages demonstrate operational realities: hash-based container “hashcode form” workflows, explicit SHA‑256/SHA‑512 hashing needs, and validation policies that grapple with determining QSCD properties in practice. citeturn10search6turn10search0turn10search3

## Definition and normative scope

**Dimension (1): precise definition and scope of “GQSCD Core” (standards, normative references).**

### What GQSCD Core is (and is not)

GQSCD Core defines “how hardware, firmware, operating system, and application components on an end-user device can provide verifiable signature-creation properties aligned to qualified-signature security objectives.” citeturn35view0

It is explicit that: (a) it is a **technical** specification; (b) it **does not itself grant legal qualification**; and (c) it is intended to be extended by platform-specific implementing specifications and evidence workflows. citeturn35view0turn35view1

### The core normative target: eIDAS Annex II-style QSCD objectives

eIDAS Annex II requirements for qualified signature creation devices include, at minimum:

- confidentiality of signature creation data (reasonably assured),
- practical uniqueness of signature creation data,
- non-derivability and protection against forgery using currently available technology,
- protection of signature creation data against use by others,
- non-alteration of data to be signed and presentation to the signatory prior to signing,
- and constraints on server-side key generation/management and backup duplication (QTSP-only; equal security; minimal copies). citeturn38view0

This is what a GQSCD Core implementation is trying to make **verifiable** on commodity end-user devices, then map into Annex II traceability. citeturn35view0turn38view0

### Certification and notification context (EU framing)

eIDAS establishes a pipeline around Annex II conformance: devices must meet Annex II, are certified for conformity, and Member States notify the Commission of certified devices and cancellations; the Commission maintains a list. citeturn37view2turn38view0

GQSCD Core explicitly positions implementer evidence as aligned with “Article 30/31 and Annex II evidence expectations,” and it references a 2025 implementing regulation on QSCD notification information. citeturn35view0turn35view3turn27search21

### Adjacent standards in scope: remote signing systems

GQSCD Core sits in a landscape where “qualified signature creation” is split into two system families:

1. **End-user device signing** (the GQSCD Core focus).
2. **Server signing / remote QSCD** models: CEN EN 419241-1 defines security requirements for “Trustworthy Systems Supporting Server Signing (TW4S)” composed at least of a server signing application and a signature creation device (or remote SCDev). citeturn12search3  
   In parallel, ETSI TS 119 431-1 defines policy and security requirements for trust service provider components operating a remote QSCD/SCDev and references the CEN remote signing standards set. citeturn12search2

A critical ecosystem signal: even an EU Digital Identity Wallet requirements annex explicitly demands SCAL2 and ETSI TS 119 431/432 family support for the _remote_ QES part of wallet solutions (showing that “qualified signing” in practice is expected to be server-based in many deployments). citeturn7search2turn12search2

### Standards comparison table

| Topic                | eIDAS Annex II baseline                                                                                                                                                                 | Remote signing standards family                                                                                                        | GQSCD Core contribution                                                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Device objective set | Annex II specifies high-level security goals for QSCDs (confidentiality, uniqueness, non-derivability, sole control, presentation/non-alteration, QTSP constraints). citeturn38view0 | EN 419241 defines system requirements for server signing systems (SSA + SCDev / remote SCDev). citeturn12search3                    | Defines cross-platform invariants + evidence artifacts + Annex II traceability mapping; not legal qualification itself. citeturn35view0turn35view1             |
| Operational model    | Local device or delegated (QTSP-managed) but Annex II governs both. citeturn38view0                                                                                                  | TSP-operated signing environment with signature activation modules and protocols (ETSI/CEN scope). citeturn12search2turn12search19 | End-user device profile with web-first interoperability (WebCrypto/WebAuthn/JOSE/COSE referenced) + EU compatibility mapping layer. citeturn35view0turn35view1 |
| Key custody & backup | QTSP-only for managed keys; duplication only for backup with strict limits. citeturn38view0                                                                                          | Remote QSCD governance, including signature activation modules and policies. citeturn12search2turn12search19                       | Hardware-backed non-exportable keys + evidence of origin/constraints; emphasizes per-transaction evidence. citeturn35view1turn35view3                          |

### Steffen-style critiques

**Steffen-style critique: the spec’s “global” ambition collides with legal reality.** The spec repeatedly emphasizes separating “technical validity” from “legal recognition,” which is intellectually honest—but also means implementers can build something technically strong that is still _legally worthless_ in a target market unless certification/notification regimes explicitly accept the evidence model. citeturn35view0turn37view2

**Steffen-style critique: Annex II is not a test suite.** “Reasonably assured” and “currently available technology” are moving targets; any global core needs _explicitly testable_ profiles or it devolves into vendor marketing with citations. citeturn38view0turn35view0

## Architecture and threat model assumptions

**Dimension (2): architecture and threat model assumptions.**

### The verification-centric architecture

GQSCD Core formalizes:

- **evidence**: cryptographically verifiable artifacts about key origin/device properties/execution state used in trust decisions,
- **evidence records**: machine-verifiable artifact sets substantiating property claims,
- a **zero-trust verification model**: decision-making based on per-transaction evidence and policy evaluation, not on implicit trust in network location or labels. citeturn35view1

At a conceptual level, the model is: “signing” is not a single API call; it is a pipeline where verifiers check **(signature + evidence + policy)**, then decide whether the signature counts as “qualified-like” in their acceptance regime. citeturn35view0turn35view1

### Threat model assumptions (explicit)

Implementations MUST model attacker capabilities including:

- network control,
- malicious local process execution,
- UI overlay/tapjacking,
- rollback attempts,
- dishonest relying-party behavior. citeturn35view1

Conformance reports must list the trusted computing base and excluded assumptions. The spec also forbids treating UI labels, allowlists, or relying-party declarations as sufficient evidence without cryptographic verification. citeturn35view1

### Architecture diagram

```mermaid
flowchart LR
  RP[Relying Party / Verifier] -->|Sign request (payload hash + policy)| DEV[End-user Device<br/>GQSCD Core Components]
  DEV -->|Signature + Evidence Record| RP

  subgraph DEV[End-user device boundary]
    APP[Signing App / Browser]
    OS[OS Security Services]
    TCB[Hardware-backed Key Store / Secure Element / TPM / Authenticator]
    UI[Trusted Confirmation Path]
    BOOT[Secure Boot + Anti-rollback]
    APP --> OS --> TCB
    APP --> UI
    BOOT --> OS
  end

  RP -->|Validate chains + policy| V[Verification Engine]
  V -->|Optional status checks| TL[Trusted List / Certification Status]
  V -->|Optional evidence publication| LOG[Transparency / Evidence Log]
```

### Steffen-style critiques

**Steffen-style critique: “zero-trust verification” still centralizes trust; it just moves it.** If evidence verification requires vendor attestation roots and revocation channels, then trust concentrates in platform vendors and their PKI. The spec’s sovereignty rhetoric is not automatically realized by using per-transaction evidence; it depends on who controls roots, metadata semantics, and failure modes. citeturn35view0turn35view1

**Steffen-style critique: dishonest relying parties are included, but the solution is underspecified.** “Don’t trust relying-party declarations” is correct but incomplete: the verifier is _often the relying party_. Without standardized third-party verification services or external auditability (e.g., transparency logs with clear dispute semantics), this becomes self-certification with extra steps. (This is an inference based on the architecture; the spec provides the warning but not a governance mechanism.) citeturn35view1turn35view0

image_group{"layout":"carousel","aspect_ratio":"1:1","query":["Trusted Platform Module chip close-up","FIDO2 security key YubiKey photo","smartphone secure element diagram","secure enclave chip infographic"],"num_per_query":1}

## Cryptographic primitives and key management

**Dimension (3): cryptographic primitives and key management (algorithms, entropy/RNG, key lifecycle, backup/escrow).**

### Key custody model expectations

GQSCD Core’s threat/mitigation table treats **key exfiltration** as a primary threat and requires “hardware-backed key custody” and denial of raw private-key export. citeturn35view1

In its taxonomy of qualified software components, it gives concrete evidence expectations for hardware-backed key origin and constraints (e.g., attestation certificate chains and authorization lists for Android-class systems; TPM artifacts for PC-class). citeturn35view3turn35view2

### User authorization and “intent binding”

For UI deception, the spec’s required mitigation is binding a user intent ceremony to the **exact payload digest and policy**, not merely “the user authenticated recently.” citeturn35view1

It treats protected confirmation as an exemplar of this pattern: a token bound to an approved message digest or prompt binding, verifiable by the relying party. citeturn35view3turn35view2

### Algorithm evidence in the GitHub corpus

The GitHub corpus includes concrete cryptographic format choices that matter operationally:

- Sweden Connect’s Signature Activation Data is explicitly a **JWT** that “must have the form of a signed JWS,” with examples using **RS256** in the JWS header. citeturn9view0
- Open‑EID’s Digital Signature Gateway integration material makes SHA‑256 and SHA‑512 hashing a first‑class requirement for “hashcode form” signing flows. citeturn10search6turn10search3

A key implication: in real systems adjacent to “qualified signing,” you will routinely have **multiple cryptographic layers** (document/container hashing, signature creation, activation/authorization tokens, evidence signatures), and the weakest link often becomes the _least reviewed_ layer (e.g., SAD JWT verification logic rather than the actual RSA/ECDSA operation). citeturn9view0turn10search6

### RNG, entropy, and nonce hygiene (why this is non-negotiable)

Even tiny biases or leakages in ephemeral secrets can be fatal. The modern “LadderLeak” line of work demonstrates ECDSA private key compromise from less than one bit of nonce leakage in certain implementations. citeturn34search11  
This is directly relevant to any QSCD-like design because “hardware-backed key storage” does not automatically guarantee “good nonce generation under side-channel pressure.”

### Backup/escrow and duplication constraints

eIDAS Annex II is unusually explicit about backup duplication when a QTSP manages signing data: duplication is permitted **only for backup purposes**, must be at the same security level as the original, and must not exceed the minimum needed for service continuity. citeturn38view0

This matters for GQSCD Core in two ways:

1. if keys are managed on-device (end-user device profile), _backup semantics should be constrained_ to avoid turning “device keys” into exportable secrets by another name;
2. if keys are managed by a service (remote/managed model), backup becomes a regulated security control, not an engineering convenience. citeturn38view0turn35view0

### Steffen-style critiques

**Steffen-style critique: “hardware-backed” is not a security level.** The phrase covers a spectrum from strong secure elements to weakly isolated TEEs; unless profiles define measurable extraction resistance and side-channel posture, teams will claim “hardware-backed” while shipping keys that are practically recoverable. (This is an inference grounded in widely-known implementation variability; the spec’s own approach acknowledges the need for platform-specific implementing specs.) citeturn35view0turn35view3

**Steffen-style critique: key-lifecycle evidence is underemphasized.** The hard part is not generating a key; it is proving (a) it was generated in the claimed boundary, (b) it was never exportable, (c) it was gated by user intent for every use, and (d) it was correctly destroyed/rotated on lifecycle events. GQSCD Core gestures at lifecycle controls, but implementers will need testable “evidence of deletion/rotation” patterns or this will be unverifiable policy. citeturn35view3turn35view0

## Implementation pitfalls and attack surface

**Dimension (4): implementation details and common pitfalls (side-channels, timing, fault attacks, firmware updates).**  
**Dimension (7): attack surface and concrete exploit scenarios (high-level, non-actionable).**

### Where implementations typically fail first

The _cryptographic primitive_ is rarely the failure. The classic failures are almost always in the boundary conditions:

- **Timing leakage**: Kocher’s foundational timing attacks show that measuring private-key operation timing can reveal secrets in RSA/DH/DSA families. citeturn34search0
- **Fault attacks**: Boneh–DeMillo–Lipton style fault attacks show that induced computational errors can disclose RSA secrets; the literature makes clear that fault resistance is not optional when attackers can perturb computation. citeturn34search5turn34search9
- **Non-traditional side channels** (e.g., acoustic): practical key extraction against RSA implementations has been demonstrated using low-bandwidth acoustic leakage under realistic conditions. citeturn34search2

A GQSCD Core implementation that uses commodity execution environments without robust countermeasures is structurally vulnerable to these classes, regardless of compliance paperwork.

### Firmware/OS update and rollback controls

The spec treats rollback as a first-class threat and requires anti-rollback plus signed update provenance. It provides concrete reference profiles:

- smartphone: verified boot + rollback indexes + version binding + protected confirmation,
- laptop/desktop: UEFI secure boot + TPM measured boot and quote verification. citeturn35view1turn35view3

It also makes a critical certification observation: strong enforcement primitives exist, but legal qualification depends on certification of the exact evaluated firmware/boot-chain target and conformity assessment outcomes—so rollback counters and boot measurements should be treated as certification artifacts, not incidental engineering details. citeturn35view3

### High-level exploit scenarios

1. **Consent laundering via UI deception**
   - Scenario: Malware overlays the signing UI, showing the user one “document summary” while the signing operation signs a different payload digest.
   - Why this works: “user authenticated” is not “user approved these bytes.”
   - Spec-mapped mitigation: bind user intent to the exact payload digest; use protected confirmation mechanisms where the verified token is tied to the approved content/digest. citeturn35view1turn35view3

2. **Rollback-to-vulnerable-chain attack**
   - Scenario: An attacker coerces a device into running an older OS/firmware that has a known exploit path to bypass key-use policy or capture confirmations.
   - Spec-mapped mitigation: anti-rollback and signed update provenance; verifiable boot state evidence (e.g., measured boot quotes for PCs). citeturn35view1turn35view3

3. **Evidence confusion and stale attestation**
   - Scenario: A verifier accepts an evidence record that is syntactically valid but semantically wrong (wrong key, wrong relying party, wrong policy epoch, or stale state).
   - Mitigation pattern (as implied by both the GQSCD and Sweden Connect corpus): strict claim binding (audience/issuer/request IDs), freshness limits, and explicit verification steps; do not treat labels as evidence. citeturn35view1turn9view0

4. **Side-channel key recovery in weakly isolated signing environments**
   - Scenario: Attackers harvest timing/fault/acoustic leakage during repeated signing operations or oracle-like uses.
   - Mitigation: constant-time implementations, fault detection/resistance, isolated hardware execution, and constraining signing oracles. The feasibility of these attacks is not speculative; the literature is mature. citeturn34search0turn34search5turn34search2

### Steffen-style critiques

**Steffen-style critique: “measured boot” is not runtime integrity.** Measuring boot state and quoting PCRs can prove _what booted_, not _what is currently executing correctly_. Without a credible story for runtime compromise (kernel exploits, malicious processes, UI overlay), you only shift the adversary to post-boot. (Inference consistent with the threat model, which explicitly includes malicious local processes and UI overlay.) citeturn35view1turn35view3

**Steffen-style critique: protected confirmation can bind the wrong thing.** The spec’s own table notes confirmation tokens can be bound to “prompt text and challenge.” If the prompt text is not a canonical representation of the actual signed bytes (and it rarely is), you can satisfy “token checks” and still not satisfy “user understood what was signed.” citeturn35view3turn35view1

## Interoperability, compliance, deployment challenges, mitigations, and gaps

**Dimension (5): interoperability and compliance with eIDAS and related regs.**  
**Dimension (6): usability and deployment challenges.**  
**Dimension (8): mitigation strategies and best practices.**  
**Dimension (9): gaps, ambiguities, recommendations.**

### EU interoperability reality: remote signing is a first-class path

Even in the _wallet_ context, EU-facing requirements point strongly toward remote QES components that must comply with SCAL2 and support ETSI remote signing standards (TS 119 431-1/2, TS 119 432) and related application requirements. citeturn7search2turn12search2

This is reinforced by the broader remote signing standards overview showing how server signing systems, signature activation modules, and protocols fit together. citeturn12search19turn12search3

So, GQSCD Core’s end-user-device focus is best understood as one leg of a bifurcated ecosystem:

- **end-user device verifiable signing** (what GQSCD tries to normalize), and
- **remote/qualified service signing** (dominant in many regulated deployments). citeturn35view0turn7search2turn12search19

### Practical interoperability pain: “qualified-ness” is hard to validate consistently

Open‑EID’s SiVa validation policy is a concrete example of how real validation regimes deal with ambiguity: some policy variants consider certificates acceptable even if SSCD/QSCD compliance cannot be determined (or treat it as warning-level), and stricter variants require determinability via trusted list qualification info (with exceptions). citeturn10search0turn10search1

This matters for GQSCD Core: if the ecosystem cannot reliably consume qualification evidence today, a new evidence format must be:

- easier to validate than existing heuristics, not harder,
- unambiguous under canonicalization,
- and privacy-preserving enough to be deployable at scale. citeturn10search0turn35view0

### Deployment and usability constraints (what will slow adoption)

Open‑EID’s integration documents illustrate the operational friction points that recur across jurisdictions:

- systems may need to work in “hashcode form” so documents do not leave the relying party’s premises,
- integrators must compute fixed digests (SHA‑256/SHA‑512),
- containers need careful manipulation rules,
- and device-specific integration (e.g., ID-cards, web eID, PKCS#11) becomes the long tail. citeturn10search6turn10search3

The Sweden Connect protocol corpus shows another practical integration story: a signature service and delegated authenticating authority exchange SAD/SADRequest, with explicit verification steps binding audience/issuer/request ID/document count to signer intent. This is exactly the “plumbing” that tends to fail via misbinding bugs or undervalidated claims. citeturn9view0

### Mitigation strategies and best practices

The following best practices fall out of the combined evidence set (spec + eIDAS Annex II + operational GitHub corpus + attack literature):

- **Evidence must be cryptographically bound and minimally sufficient.** Bind audience, request identifiers, freshness windows, and payload digests; reject on any mismatch. citeturn9view0turn35view1
- **Treat rollback resistance as an assurance primitive, not a feature.** Anti-rollback counters, secure boot states, and measurement artifacts should be part of the evidence record and the certification boundary. citeturn35view3turn35view1
- **Assume side channels exist; design so they don’t matter.** Constant-time operations and fault resistance are not “crypto library details”; they are qualification-critical properties, backed by decades of empirical attack literature. citeturn34search0turn34search5turn34search2
- **Don’t invent a new “backup” story.** If you are in a QTSP-managed key model, Annex II constrains duplication. If you are in a device-key model, resist “cloud backup” that functionally exports signing secrets. citeturn38view0turn35view0

### Gaps and ambiguities

1. **Standardization status gap**  
   The GQSCD Core document is a draft baseline. That is not a flaw; it is a status. But implementers must not confuse “spec conformance” with “qualified” legal status. The spec itself warns against that. citeturn35view0

2. **Evidence semantics gap**  
   The spec’s approach depends on evidence records being consistently interpretable across verifiers. Existing validation ecosystems already struggle with determinability of QSCD-related properties (as SiVa shows). Without strict schemas, canonical encodings, and versioning rules, interoperability collapses into “works on my verifier.” citeturn10search0turn35view0

3. **Scope boundary ambiguity**  
   eIDAS explicitly frames QSCD certification scope as limited to hardware/system software managing and protecting signature creation data, excluding signature creation applications. GQSCD Core is deliberately “end-to-end component profile,” which risks scope mismatch with how certification bodies/evaluators are structured. citeturn36view1turn35view0

4. **Remote vs local split**  
   Authoritative guidance sources may explicitly exclude remote services from device-focused QSCD evaluation documents, underscoring an institutional split in evaluation culture. That split is a deployment obstacle for any “unified” core. citeturn17view3

### Recommendations

**For standards authors (including any future GQSCD implementing specifications):**

- Define **testable profiles** (not just “examples”) for: algorithm suites, entropy sources, anti-rollback evidence formats, and intent-binding semantics. (This recommendation is motivated by the explicit threat model and Annex II goals.) citeturn35view1turn38view0
- Specify a canonical “what the user approved” object that is provably equivalent to “what was signed” in verifier logic; otherwise UI deception remains the dominant practical attack. citeturn35view1turn35view3

**For implementers:**

- Treat SAD/JWT/evidence verification as a **high-assurance component**: most production failures are misbinding and verification bypass, not crypto breaks. Use strict verification checklists like the Sweden Connect SAD verification steps as a baseline pattern. citeturn9view0
- Design for hostile environments from day one: rollback, UI overlay, and local malicious processes are in-scope attackers in the GQSCD threat model; if your design assumes “the OS is honest,” you are not implementing the spec you think you are. citeturn35view1

### Steffen-style critiques

**Steffen-style critique: the sovereignty claim is aspirational, not demonstrated.** The spec’s stated “decentralization and digital sovereignty” goal is philosophically attractive, but in practice most evidence chains depend on platform vendors and their attestation roots. Without explicit multi-root governance, transparent revocation, and verifier diversity, “decentralized” becomes “multiple centralized silos.” citeturn35view0turn35view1

**Steffen-style critique: if you can’t standardize verification, you don’t have a standard.** A “core” that produces evidence records is only as strong as the weakest verifier implementation. If verifier policy is complex, under-specified, or proprietary, the ecosystem will fragment into incompatible “qualified-ish” islands—exactly what the EU ecosystem has spent a decade trying to eliminate. citeturn35view0turn7search2turn38view0
