# Global Digital Identity Scheme Core

## Executive summary

“Global Digital Identity Scheme (GDIS) Core” (as defined at `z-base.github.io/gdis/`) specifies a web-first _identity binding profile_ that begins with a physically issued identity document (a “governance area” artifact) and produces verifier-checkable cryptographic evidence. Its core mechanics are: (a) extract a versioned set of PID fields from MRZ-compatible document data, canonicalize with JSON Canonicalization Scheme (JCS), hash with SHA‑256 to form a stable `pidHash`; (b) bind that hash to a normalized verification endpoint URI (also SHA‑256 hashed) and issue a W3C Verifiable Credential (VC) addressed to a Decentralized Identifier (DID) controlled by a “GQSCD controller”; (c) publish signed append-only events in a decentralized, open-participation event log replicated by arbitrary “hosts,” with deterministic conflict-resolution rules for verifiers. citeturn31view2turn39view0turn23view0turn8view1turn8view2

The specification attempts to separate **legal recognition** from **mechanical cryptographic verification**: any claim of “mandated/recognized/qualified/notified/trusted” status must be supported by authoritative registries or law (e.g., EU trusted lists and dashboards), and GDIS must not claim legal equivalence without explicit legal grounding. citeturn31view2turn9view5

The strongest security-critical dependency inside GDIS Core is its requirement that the subject DID controller satisfy a _GQSCD controller profile_ (defined in the related `z-base.github.io/gqscd/` document). That profile emphasizes hardware-backed non-exportability, attestation evidence, trusted user-intent ceremonies, and anti-rollback / signed update provenance—i.e., it tries to pull end-user device signing behavior toward “QSCD-like outcomes” while explicitly stating it does **not itself** confer legal qualified status. citeturn31view2turn30view1turn39view0

**Steffen-style critiques (hard, security-expert-first objections):**

- **Steffen-style critique: “Hashing MRZ/PID does _not_ make it safe to publish.”** GDIS uses a _stable_ `pidHash` derived from MRZ/PID fields as the primary subject key in an open event log. MRZ-derived identifiers are structurally predictable and have repeatedly been shown to enable offline guessing/brute-force in ePassport contexts because key material/inputs are low-entropy and policy-dependent (document number issuance patterns, etc.). A public, globally consistent hash becomes a _global correlator_ and can enable mass enumeration (“is this person registered?”), targeted lookups, and cross-context linking—despite “no raw MRZ on-log.” citeturn31view2turn29search0turn35view0turn22view1
- **Steffen-style critique: “Your conflict resolution is gameable unless you define what ‘time’ means and what event IDs commit to.”** GDIS resolves conflicts by preferring “latest `createdAt`,” then lexicographically smallest `eventId` on ties. If timestamps are attacker-controlled or only weakly validated (common in decentralized systems), `createdAt` becomes a knob. If `eventId` can be influenced by signature malleability/choice or by altering non-semantic fields, it becomes a second knob. Determinism is not the same as safety. citeturn31view2turn39view0turn8view0
- **Steffen-style critique: “Open-participation replication without a concrete anti-spam/eclipsing design is a fantasy.”** The spec itself flags “portable host gossip anti-spam” as an open issue, but without strong admission control or verifiable resource costs, the open host set becomes an easy DoS surface and an eclipse vector against verifiers. citeturn39view1
- **Steffen-style critique: “You’re implicitly rebuilding a PKI + transparency log—without fully specifying either.”** GDIS relies on HTTPS endpoints under `/.well-known/gidas/` plus issuer signatures plus replicated events. But endpoint trust, revocation freshness, registry correctness, and transparency/auditability rules are only partially nailed down; the spec leans on “governance endpoints” and “evidence artifacts” without fully standardizing evidence formats, timestamping/trust anchors, or audit proofs. citeturn31view2turn39view0turn37search1
- **Steffen-style critique: “You cite Self as inspiration, then ignore the key privacy lesson.”** The referenced Self documentation explicitly discusses dictionary-attack resistance by incorporating high-entropy passport data (e.g., DG2 photo) into commitments/nullifiers; GDIS v1 anchors on MRZ/PID-only hashing. That is a privacy regression if you ever publish the hash globally. citeturn34view0turn31view2

Unspecified assumptions (material to conclusions): the target platform(s) for the subject controller (mobile SE/TEE vs desktop TPM vs external authenticator), the DID method(s) permitted, verifier network model (public internet vs restricted federation), attacker capability model (local malware? physical device possession? hostile issuers? hostile governance endpoint operators?), and whether the decentralized event log is globally public or access-controlled—are not fixed by the text and must be treated as _unspecified until profiled_. citeturn31view2turn30view1

## GitHub Pages corpus analyzed

### GitHub Pages crawl results and pages examined

All GitHub Pages (`github.io`) URLs examined for this report (full URLs):

```text
https://z-base.github.io/gdis/
https://z-base.github.io/gqscd/
https://z-base.github.io/   (returned 404 Not Found during retrieval)
https://eu-digital-identity-wallet.github.io/
https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/2.5.0/
https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.7.0/architecture-and-reference-framework-main/
```

### What the GitHub Pages corpus actually defines

GDIS Core defines (normatively) the actors (Subject/Issuer/Verifier/Host), the lifecycle, PID-hash derivation procedure (MRZ normalization → PID extraction → JCS canonicalization → SHA‑256), endpoint normalization per RFC 3986, binding digest construction, VC-to-DID binding requirements, open event log replication requirements, event ordering/rotation/revocation representation, and deterministic conflict resolution. citeturn31view2turn39view0turn8view2turn8view1

GDIS also defines conformance classes (“GDIS Issuer,” “GDIS Host,” “GDIS Verifier”) and mandates that conformant implementations publish conformance reports including supported versions, test evidence, and explicit security assumptions (clock/freshness policies, trust anchor inputs). citeturn39view0turn39view1

The related GQSCD Core document defines the _controller security profile_ that GDIS requires for the subject DID controller. It is positioned as a technical baseline (not a legal qualification grant), and it emphasizes evidence artifacts, device attestation, trusted user-intent ceremonies, non-exportable hardware-backed keys, secure boot/anti-rollback, and explicit threat-model reporting. citeturn30view1turn38view3

The EU Digital Identity Wallet Architecture and Reference Framework (ARF) material (hosted via a GitHub Pages front-end that redirects into the `eudi.dev` site, but sourced from the GitHub Pages URL) provides context for EU implementing regulations and the “toolbox” approach; it explicitly frames ARF documents as non-binding narrative guidance, with the legally binding requirements being the adopted regulation and implementing/delegated acts. citeturn33view1turn33view2

## Definition and normative scope of GDIS Core

### Precise definition and boundaries

**GDIS Core’s stated definition:** a “web-first identity binding profile” that begins at a physically issued identity item in a governance area and produces verifier-checkable cryptographic evidence, while keeping legal recognition anchored in jurisdictional registries and separating it from purely mechanical cryptographic verification. citeturn31view2

**Normative outputs and artifacts:**

- `pidHash`: SHA‑256 hash of JCS-canonicalized PID JSON extracted from MRZ-compatible document data (v1: `mrzHash` is an alias equal byte-for-byte). citeturn31view2turn8view1
- `endpointHash`: SHA‑256 hash of the normalized endpoint URI (normalization referenced to RFC 3986). citeturn31view2turn8view2
- `bindingDigest`: SHA‑256 over a domain-separated tuple `("gdis:v1" || pidHash || endpointHash)` (domain separation is explicit in the string prefix). citeturn31view2
- A “GDIS binding credential” as a W3C Verifiable Credential issued to a DID, signed using W3C Data Integrity or JOSE/COSE-compatible containers (JWS/COSE structures referenced). citeturn31view2turn23view1turn23view0turn23view2turn8view0turn8view3
- Signed append-only “events” replicated by “hosts,” containing digests, signatures, pidHash, sequence, predecessor references, timestamps, and explicit key rotation / revocation events; verifiers must apply deterministic conflict resolution. citeturn31view2turn39view0

### Normative references and what they imply

GDIS Core explicitly anchors its normative language to IETF BCP 14 keywords (RFC 2119 / RFC 8174). citeturn39view2 It uses:

- **IETF URI semantics** (RFC 3986) for endpoint normalization. citeturn39view2turn8view2
- **IETF JSON Canonicalization Scheme** (RFC 8785) to define deterministic canonical bytes before hashing. citeturn39view2turn8view1
- **IETF HTTP semantics** (RFC 9110) as transport baseline. citeturn39view0
- **JOSE/COSE signature containers** (RFC 7515, RFC 9052) as acceptable proof containers. citeturn39view0turn8view0turn8view3
- **W3C DID Core** and **W3C VC DM 2.0** + **VC Data Integrity 1.0** for identity and credential data models. citeturn39view0turn23view0turn23view1turn23view2
- **ICAO Doc 9303** for MRZ semantics (MRZ semantics must not be replaced by ad hoc interpretations). citeturn31view2turn22view1turn22view2

GDIS also defines `/.well-known/gidas/…` endpoints as mandatory for normative interoperability. This is conceptually aligned with the IETF “well-known” mechanism, which defines `/.well-known/` as a standardized path prefix for site-wide metadata discovery. citeturn31view2turn37search1  
**Steffen-style critique:** GDIS uses `/.well-known/gidas/…` without stating whether it is registered (or intended to be registered) in the IANA well-known URI registry process implied by RFC 8615. If it is not formally registered, collisions and “lookalike / squatting” risks become social-technical attack surfaces (especially as implementers begin shipping clients that hardcode the path). citeturn31view2turn37search1

### Relationship to EU eIDAS and EUDI Wallet rules

GDIS includes an “EU Compatibility Profile” described as a mapping layer on top of the “primary web profile,” referencing EU implementing regulations for wallet integrity/core functionalities and protocols/interfaces. citeturn39view0turn16view0turn19view0

From the EU legal side (primary sources), the eIDAS framework exists as Regulation (EU) No 910/2014 (and consolidated versions), and the 2024 amendment establishing the European Digital Identity Framework is Regulation (EU) 2024/1183. citeturn10view0turn10view1turn11view0  
EU implementing regulations relevant to wallet behavior include:

- Commission Implementing Regulation (EU) 2024/2979 (integrity and core functionalities of EUDI wallets). citeturn16view0
- Commission Implementing Regulation (EU) 2024/2982 (protocols and interfaces to be supported). citeturn19view0
- Commission Implementing Regulation (EU) 2024/2977 (PID and electronic attestations of attributes). citeturn21view0

The EUDI wallet protocols/interfaces implementing act explicitly references ISO/IEC 18013‑5:2021 and ISO/IEC TS 18013‑7:2024 in its annex. citeturn19view0  
**Steffen-style critique:** This is a direct interoperability tension. GDIS’s “web profile” is W3C DID/VC-first, whereas EU-mandated protocols/interfaces are explicitly tied (at least in part) to ISO mDL families. Treating EU mapping as “just a layer” is an engineering understatement: it can force concrete format/protocol commitments that change privacy and threat properties, not merely renaming fields. citeturn39view0turn19view0turn33view2

## Architecture and threat model assumptions

### System architecture as defined by GDIS Core

GDIS defines four principal actors: subject, issuer, verifier, and host. The lifecycle is: inspect physical identity item, extract and hash PID fields, bind to governance endpoint, issue a VC to the subject DID, publish event log material to a “publication set” of hosts, and have verifiers resolve and validate events, endpoint freshness, and conflict resolution mechanically. citeturn31view2turn39view0

image_group{"layout":"carousel","aspect_ratio":"16:9","query":["passport MRZ close up example","electronic passport NFC chip illustration","verifiable credentials decentralized identifier diagram"],"num_per_query":1}

```mermaid
flowchart LR
  subgraph Physical
    Doc[Physical ID document\n(MRZ + chip evidence)]
  end

  subgraph Client
    Subj[Subject wallet/controller\n(GQSCD controller profile)]
  end

  subgraph Governance
    Iss[Issuer / governance authority]
    EP[Verification endpoint\n/.well-known/gidas/*]
  end

  subgraph Log
    H1[Host A]
    H2[Host B]
    Hn[Host N]
  end

  Ver[Verifier\n(policy + deterministic rules)]

  Doc -->|inspect + read| Iss
  Iss -->|compute pidHash + endpointHash\nissue VC| Subj
  Iss -->|publish signed events| H1
  Iss -->|publish signed events| H2
  Subj -->|select publication set| Hn
  H1 <-->|gossip/replicate| H2
  H2 <-->|gossip/replicate| Hn
  Ver -->|fetch events| H1
  Ver -->|fetch endpoint status| EP
  Ver -->|validate VC/DID proofs,\nendpoint freshness,\nconflict resolution| Ver
```

### Threat model honesty and explicit assumptions

GDIS explicitly demands “threat model honesty”: implementations must assume hostile client/network environments unless security boundaries are cryptographically enforced. Minimum modeled threats include key exfiltration, endpoint spoofing, replay, event-log inconsistency, and governance policy abuse where “mandatory minimum hosts” are misused as an exclusive maximum set. citeturn39view0turn39view1

This framing is aligned with a “zero trust” mindset (verify decisions using explicit evidence rather than implicit trust), a concept formalized in widely used security guidance. citeturn24view1turn30view1

### Steffen-style critique: the missing “adversarial issuer” and “adversarial governance endpoint”

GDIS heavily constrains _verifier mechanics_ (hashing rules, deterministic conflict resolution), but it does not fully specify how verifiers should reason about a compromised issuer key, a malicious delegated issuer, or a compromised governance endpoint operator—beyond “freshness policy” and “issuer authenticity.” citeturn31view2turn39view0  
In real deployments, those are not edge cases; they are the first place systems fail. EU trust-service policy standards explicitly treat organizational controls, incident handling, and supervision as core requirements because purely cryptographic correctness is not enough when operators are compromised or negligent. citeturn27view0turn9view5

## Cryptographic primitives and key management

### Cryptographic primitives explicitly used by GDIS

GDIS v1 hard-codes a specific _shape_ of cryptographic computation:

- Canonicalization: JCS (RFC 8785). citeturn31view2turn8view1
- Hashing: SHA‑256 for `pidHash`, `endpointHash`, and binding digest construction (examples and normative steps). citeturn31view2
- Credential proof containers: W3C VC Data Integrity and/or JOSE/COSE (JWS / COSE Structures are referenced). citeturn39view0turn23view2turn8view0turn8view3
- Transport: HTTP semantics (RFC 9110) and HTTPS requirement for endpoints. citeturn31view2turn39view0

**Steffen-style critique:** GDIS names JOSE/COSE broadly but does not publish a tight algorithm profile (e.g., a constrained set of `alg` values and key types) inside the core. JWS in particular has long emphasized security considerations around algorithm agility, validation rules, and subtle implementation pitfalls. A “bring your own algorithms” model is how ecosystems die: not with a bang, but with verifier divergence and downgrade/interop hacks. citeturn8view0turn39view0

### PID hash privacy: MRZ-derived identifiers are a known weak anchor

GDIS insists that MRZ semantics come from ICAO Doc 9303. citeturn31view2turn22view1 ICAO materials and the ePassport ecosystem show that MRZ-derived material (document number, dates, etc.) is often structured and guessable enough that _offline exploitation is realistic_ when the derived values are exposed.

- Academic work on cracking ePassport Basic Access Control (BAC) keys highlights “low entropy” driven by passport numbering policies and predictable MRZ-derived inputs. citeturn29search0turn29search12
- Common Criteria security targets for e-documents explicitly call out that BAC keys are derived from subsets of printed MRZ data and require careful entropy assessment due to dependencies (e.g., consecutive document numbers). citeturn35view0

**Steffen-style critique (core privacy flaw):** Publishing a stable `pidHash` (MRZ/PID-derived) in an open, replicated event log is functionally equivalent to publishing a globally consistent, guessable surrogate identifier. Hashing is not encryption; if the preimage space is human-structured, adversaries win by guessing. GDIS’s own privacy section (“store hashes”) is not sufficient protection when the hash is stable and globally searchable. citeturn31view2turn35view0turn29search0

### Key lifecycle and custody expectations (via GQSCD linkage)

GDIS outsources its _most sensitive key-management property_—control of the subject DID—to the GQSCD controller profile. citeturn31view2turn30view1 That profile insists implementations model key exfiltration and require hardware-backed non-exportability with controller attestation evidence. citeturn30view1turn39view0

From vendor primary documentation, hardware-backed key custody can provide **non-exportability** and policy-bound usage constraints, but it is not magic:

- Android Keystore documentation explicitly states keys can remain non-exportable while being used for operations, and that usage can be gated by policy such as user authentication. citeturn42search4
- Android key attestation is designed to let relying parties verify hardware-backed key properties via attestation certificates. citeturn42search0
- Android Protected Confirmation exists specifically to bind user intent to sensitive operations via a hardware-protected UI path. citeturn42search3turn42search7
- Apple’s Secure Enclave is described as an isolated key manager intended to protect sensitive material even if the application processor kernel is compromised. citeturn42search1turn42search5

**Steffen-style critique (key custody ≠ key safety):** Hardware-backed non-exportability reduces _key theft_, but it does not automatically prevent _key misuse_ under local compromise unless you also have a trusted user-intent path and strict authorization policy. The GQSCD profile recognizes this by emphasizing intent ceremonies and anti-overlay/tapjacking modeling, but GDIS Core itself does not specify how GDIS-specific binding/signing actions must be tied to user intent. citeturn30view1turn39view0turn42search3

### Backup and escrow: unresolved and dangerous by default

GDIS does not specify backup/escrow for subject keys or identity state; it only specifies rotation and revocation events and requires that “key rotation” and “revocation” be represented in the event log. citeturn31view2turn39view0  
GQSCD Core flags that backup and recovery flows must preserve confidentiality and auditability, but it does not prescribe a concrete mechanism. citeturn38view3

**Steffen-style critique:** If you don’t specify recovery, implementers ship either (a) no recovery (catastrophic usability failure, permanent lockout), or (b) cloud backup of key material/state (catastrophic security regression, invisible centralization). Leaving this “to profiles” is reasonable only if the core also defines non-negotiable recovery security requirements and auditable evidence artifacts. As written, that boundary is too soft. citeturn39view0turn38view3

## Implementation details, common pitfalls, and attack surface

### Canonicalization and normalization pitfalls

GDIS requires canonicalization via JCS and endpoint normalization per RFC 3986 before hashing. citeturn31view2turn8view1turn8view2 These are correct choices _in principle_, but implementations commonly fail in edge cases:

- JCS requires strict, deterministic JSON serialization rules; any divergence (floating point encoding, Unicode normalization assumptions outside the spec, inconsistent object member ordering in intermediate representations) will cause hash mismatches and ecosystem fragmentation. citeturn8view1turn31view2
- URI normalization is famously subtle (percent-encoding equivalences, case normalization in scheme/host, dot-segment removal, internationalized domain handling). RFC 3986 gives the rules; implementers still get it wrong in practice, especially when libraries “helpfully” re-encode. citeturn8view2turn31view2

**Steffen-style critique:** In a system where `pidHash` is the lookup key and conflict-set partitioning key, a single canonicalization divergence is not a mere bug—it is a _consensus fork at the identity level_. Your “deterministic verifier” property collapses unless you ship conformance test vectors that include nasty canonicalization/normalization corner cases and require byte-for-byte match. GDIS requires conformance reports but does not (yet) publish the necessary canonical test suite payloads. citeturn39view0turn39view1turn8view1turn8view2

### Event log replication: DoS, eclipsing, and “open participation” reality

GDIS mandates open participation (“any operator MAY run a host”) and requires that subjects can add person-selected hosts beyond governance-required minimum hosts. citeturn31view2turn39view0

**Attack surface (high-level, non-actionable):**

- **Spam flooding:** adversaries run many hosts and inject high-volume invalid or semantically useless events, consuming bandwidth and storage.
- **Eclipse / isolation:** adversaries bias a verifier’s view by controlling the subset of hosts it can reach (network-level interference plus malicious host selection), feeding a consistent but incomplete history.
- **Split-view:** different verifiers see different “latest” states because of propagation timing and policy differences on “freshness,” leading to inconsistent accept/reject decisions.

GDIS acknowledges the missing anti-spam mechanism as an open issue (“portable host gossip anti-spam model”). citeturn39view1

```mermaid
flowchart TD
  A[Attacker-controlled hosts\n(many origins)] -->|flood/gossip| V[Verifier]
  A -->|selective connectivity| V
  H[Honest hosts] -->|gossip| V
  V -->|deterministic rules\nbut incomplete view| D[Wrong decision\n(split-view / stale status)]
```

**Steffen-style critique:** “Open participation” plus “no centralized host approval” is a nice slogan until you specify the resource model. Without either (1) strong cryptographic admission (e.g., governance-signed host operator attestations) or (2) a verifiable cost function (e.g., PoW/PoS-like resource proofs) or (3) bounded federation, the open host layer is an attacker-controlled substrate by default. GDIS currently punts this to future work. citeturn39view1turn31view2

### Side-channels, timing, and fault attacks: why “controller profile” matters

Even if GDIS itself mostly defines hashes and signatures, the real security failure modes are often in **device-side signing and key use**.

- Timing attacks against private-key operations have been known for decades; they exploit observable execution time differences to recover secrets if implementations are not constant-time. citeturn36search0
- Fault attacks target cryptographic computations by inducing errors; classic results show that single faulty computations (notably in CRT-RSA) can enable key recovery if errors are not detected/handled. citeturn36search1
- Practical side-channel extraction has extended beyond time and power, including acoustic emanations in real software stacks. citeturn36search2

Common Criteria-style threat catalogs for e-doc chips explicitly enumerate information leakage (DPA/DEMA), fault injection (DFA), and physical tampering as baseline concerns under enhanced attacker models. citeturn35view0

**Steffen-style critique:** GDIS’s security claims live and die where the subject keys are used. If implementers realize “GQSCD controller” as “some app key in a general OS keystore without a trusted UI path,” you get signatures that are non-exportable but trivially triggerable by malware. The GQSCD profile _tries_ to prevent this by emphasizing protected confirmation / trusted UI and explicit threat modeling; treat that as mandatory engineering, not optional “best practice.” citeturn30view1turn42search3turn42search7

### Firmware and update mechanisms: rollback as a silent defeat

GQSCD Core explicitly models rollback attacks and demands anti-rollback and signed update provenance (secure boot chain, etc.). citeturn30view1turn38view3 This aligns with broader platform security doctrine: once rollback is possible, the attacker’s optimal strategy is to force a vulnerable version and then perform known exploitation.

**Steffen-style critique:** A GDIS verifier that accepts “controller attestation” without verifying OS/firmware anti-rollback posture is making a runtime security decision based on a historical snapshot. You need _fresh, policy-evaluated evidence_ (or a reasoned bound on evidence freshness), otherwise attestation turns into “security theater with X.509.” citeturn30view1turn39view0turn42search0

## Interoperability, compliance relevance, and deployment realities

### Interoperability: standards alignment does not equal interop

GDIS anchors its “Primary Web Profile” on DID Core, VC DM 2.0, VC Data Integrity / JOSE/COSE, and HTTP semantics. citeturn39view0turn23view0turn23view1turn23view2turn8view0turn8view3  
This is internally coherent—_but_ interop failure modes tend to be:

- too many proof formats (VC Data Integrity vs JWS vs COSE) without strict profiles,
- different DID methods with different trust assumptions,
- verifier differences in canonicalization, clock skew, freshness rules, and status checking.

W3C DID Core itself highlights that DID methods vary widely and that DID correlation and resolver choice are privacy/security-relevant. citeturn23view0

**Steffen-style critique:** “Supports DID Core” is not a security claim. It’s like saying “supports URIs.” You must constrain DID methods (or constrain resolver trust models) in any real deployment profile, or else you get the worst of both worlds: decentralized ambiguity with centralized dependencies. citeturn23view0turn39view0

### EU compliance relevance (when claimed)

GDIS explicitly states EU terms should be anchored to Article 3 definitions when EU vocabulary is used, and it forbids claiming legal equivalence without legal text support. citeturn31view2turn39view0  
This is directionally aligned with how the EU treats qualified status: EU trusted lists have a constitutive effect for qualified trust services, and qualification is not something you infer from cryptography alone. citeturn9view5turn30view1

The EU wallet implementing acts (2024/2977, 2024/2979, 2024/2982) and the eIDAS amendment (2024/1183) establish that wallets, PID/attestations, and interface/protocol support have legally binding frameworks; they are not optional. citeturn11view0turn21view0turn16view0turn19view0

**Steffen-style critique:** If you want “EU compatibility,” you must be explicit about (a) which EU wallet protocols you support, (b) which PID/EAA formats you support, and (c) how you map GDIS’s event log and VC/DID binding into the EU’s compliance and certification story. Otherwise, “EU compatibility profile” is just marketing language in a spec wrapper. citeturn19view0turn21view0turn33view2

### Usability and deployment challenges

GDIS’s architecture presumes:

- reliable document inspection and MRZ/PID extraction;
- governance endpoint availability and robust freshness checks;
- end-user control over host publication set selection;
- verifiers implementing deterministic conflict resolution and policy rules.

Real-world friction points:

- **Provisioning and onboarding:** MRZ entry and NFC scan flows are error-prone; the spec references passport/eID ecosystems where chip reading requires BAC/PACE and certificate chain validation complexity. citeturn34view0turn22view1
- **Scaling verifiers:** verifiers need reliable host discovery, caching, and freshness policy management; any mismatch yields inconsistent results (a compliance nightmare). citeturn39view0turn31view2
- **Operational governance:** “mandatory minimum hosts” vs “person-selected hosts” implies governance and user choice simultaneously—hard to explain and hard to support. citeturn31view2turn39view0

## Gaps, ambiguities, and recommendations

### Key gaps identified in the specification text

GDIS itself flags several open issues: defining a stable canonical PID field set, defining anti-spam in the host gossip model without central admission control, defining a pairwise identifier blinding mode while preserving global dedup properties, and deciding whether transport includes only HTTP(S) or content-addressed channels (IPFS) as first-class options. citeturn39view1turn6view1

Those are not “nice-to-haves”; they are core to whether the system is secure and deployable.

### Steffen-style critiques consolidated

**Steffen-style critique: Stable `pidHash` is a system-level privacy footgun.**  
GDIS’s privacy section suggests storing hashes and using pairwise challenges, but the architecture still centers on a stable, globally reusable hash as the subject key in an open log. This is exactly the kind of “looks private on a slide, is linkable in production” design. citeturn31view2turn39view0

**Steffen-style critique: The spec implicitly admits the privacy flaw.**  
“Define optional pairwise identifier blinding mode” is an explicit admission that the current `pidHash` model is linkable. The hard problem is that “blinding while preserving global deduplication” is inherently in tension: global dedup wants global sameness; privacy wants contextual unlinkability. You cannot hand-wave that tension away. citeturn39view1turn34view1

**Steffen-style critique: You reference Self, but your v1 chooses the weaker commitment.**  
Self’s documentation explicitly discusses preventing dictionary attacks by incorporating high-entropy passport material (DG2 photo) into signed attributes/commitments and describes why some deterministic constructions remain linkable and hard to avoid without additional trust assumptions. GDIS v1’s MRZ-only hash is the opposite direction if the hash is public. citeturn34view0turn34view1turn31view2

### Recommendations for implementers

Implementers should treat GDIS Core as a _protocol skeleton_ that requires a hardened profile before production:

1. **Do not ship a public event log keyed solely by MRZ/PID-derived SHA‑256.** Add a privacy-preserving derivation mechanism (e.g., keyed hashing tied to governance/verifier scope, OPRF-based construction, or ZK-based commitments that incorporate high-entropy chip data) _or_ constrain the log to a strictly access-controlled federation with legal guardrails. The need for this is strongly supported by the long history of low-entropy MRZ-derived attack surfaces in passport systems. citeturn29search0turn35view0turn34view0
2. **Publish a strict algorithm and proof-format profile.** Constrain JOSE/COSE/DI choices into a small mandatory set; otherwise verifiers diverge. Leverage established cryptographic suite guidance where appropriate (e.g., ETSI cryptographic suites for trust services) instead of letting every implementer improvise. citeturn39view0turn41view0turn8view0
3. **Define hard conformance test vectors for canonicalization and URI normalization.** Include adversarial edge cases (Unicode, percent-encoding, JSON number forms) and require byte-for-byte compatibility. citeturn8view1turn8view2turn39view0
4. **Treat the host layer as adversarial.** Implement rate limits, resource accounting, and eclipse resistance; if you can’t, you need federation or signed host admission. GDIS’s open-issue list makes this explicit—don’t pretend it’s solved. citeturn39view1turn31view2
5. **Bind signing operations to trusted user intent.** Use platform protected confirmation / trusted UI where available; non-exportable keys are insufficient against malware-triggered signatures. citeturn42search3turn30view1turn42search4
6. **Specify recovery as a first-class security property.** Define audited recovery events, rotation semantics under compromise, and user experience requirements; otherwise you will either lock users out or centralize. citeturn39view0turn38view3

### Recommendations for standards authors (including GDIS/GQSCD maintainers)

1. **Formally define the PID field set and its versioning rules** (including jurisdiction mappings) and publish a canonical schema and test vectors as normative deliverables. citeturn39view1turn31view2
2. **Replace “createdAt”-based conflict tie-breaking with a cryptographically grounded ordering model**, or define what “time” evidence counts (e.g., timestamp tokens, secure time attestations) and what verifiers must reject. citeturn39view0turn30view1turn27view0
3. **Specify event ID computation and commitment boundaries** (what fields are covered, how canonicalized, whether signatures are inside/outside the eventId hash) to prevent tie-break grinding. citeturn31view2turn8view1turn8view0
4. **If `/.well-known/gidas/` is intended for broad deployment, align explicitly with the RFC 8615 registration model** and publish a stable media type + schema definition for discovery/status endpoints. citeturn31view2turn37search1
5. **Write the “EU compatibility profile” as a real profile**: enumerated EU acts, required protocols/interfaces, conformance mapping, and certification evidence expectations—because EU wallet rules are not optional and are explicitly tied to standards like ISO/IEC 18013‑5/-7. citeturn19view0turn33view2

### Comparative table: identity anchor strategies and privacy/security trade-offs

| Anchor strategy                                                      |                                           Global dedup? |                                                                                 Dictionary-attack resistance |                                                                       Cross-context linkability risk | Core dependency you must trust                                                                             |
| -------------------------------------------------------------------- | ------------------------------------------------------: | -----------------------------------------------------------------------------------------------------------: | ---------------------------------------------------------------------------------------------------: | ---------------------------------------------------------------------------------------------------------- |
| GDIS v1 `pidHash` = SHA‑256(JCS(PID-from-MRZ))                       |                      Yes (by design) citeturn31view2 |                        Weak if log is public and MRZ/PID space is guessable citeturn29search0turn35view0 |                                                   High (stable global identifier) citeturn39view0 | Correct canonicalization + endpoint security + issuer integrity citeturn31view2turn39view0             |
| Self-style commitment including higher-entropy chip data (e.g., DG2) | Yes/mostly (depends on construction) citeturn34view1 |                                  Stronger (explicitly argued to avoid dictionary attacks) citeturn34view0 |                                   Still non-zero (registration can be detectable) citeturn34view1 | TEE attestation, circuit correctness, registry integrity citeturn34view1                                |
| EU EUDI Wallet PID issuance under implementing acts                  |           Depends on ecosystem rules citeturn21view0 | Depends on formats/protocols; can be strong if selective disclosure is enforced by design citeturn11view0 | Depends on relying-party behavior; EU law pushes user control/logging citeturn11view0turn19view0 | Member State wallet + certification + mandated protocol support citeturn16view0turn19view0turn33view2 |

## Recommended next steps

### For implementers (short list)

- Freeze a **deployment profile**: pick DID method(s), proof format(s), algorithm suite(s), endpoint schemas, freshness policy, and host admission model; publish conformance tests and vectors. citeturn39view0turn23view0turn8view0
- Treat `pidHash` as **sensitive**: do not publish it in a globally public log without a privacy-preserving redesign (or strict access controls). citeturn29search0turn35view0turn31view2
- Make “GQSCD controller” real: require hardware-backed keys, attestation verification, and protected user-intent confirmation for any signature/authorization operation. citeturn30view1turn42search0turn42search3turn42search4

### For standards bodies and spec authors (short list)

- Standardize the missing pieces that decide safety: PID field set, event ID commitments, conflict ordering, anti-spam replication, and pairwise blinding (with a formally stated privacy/dedup trade-off). citeturn39view1turn39view0
- Align discovery endpoints with the **IETF well-known** ecosystem (registration and collision avoidance). citeturn37search1turn31view2
- If EU compatibility is a goal, publish a normative mapping to the relevant implementing acts and the ISO/IEC standards those acts point to. citeturn19view0turn21view0turn33view2
