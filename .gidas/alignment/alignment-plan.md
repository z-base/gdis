# Alignment Plan

## Canonical Term Owners
- proof artifact -> UNSPECIFIED (term missing from current snapshots)
- binding credential -> UNSPECIFIED (term missing from current snapshots)
- gdis binding credential -> GDIS-CORE#gdis-binding-credential
- verification material -> UNSPECIFIED (term missing from current snapshots)
- public verification material -> UNSPECIFIED (term missing from current snapshots)
- Device/key terms -> GQSCD-CORE (unless explicitly scoped as public verification material).
- Identity/PID terms -> GDIS-CORE.
- Log/publication terms -> GQTS-CORE.

## Canonical Clause Mapping
- getEndpointKindCatalog -> GQTS-CORE:REQ-GQTS-02
- getEventById -> GQTS-CORE:REQ-GQTS-07
- getEventHeadMeta -> GQTS-CORE:REQ-GQTS-04
- getEventLogView -> GQTS-CORE:REQ-GQTS-05
- getGdisPidIdentificationPolicy -> GDIS-CORE:REQ-GDIS-03
- getSchemeDescriptor -> GQTS-CORE:REQ-GQTS-01
- getTypeDescriptor -> GQTS-CORE:REQ-GQTS-03
- postEventIngest -> GQTS-CORE:REQ-GQTS-06

## Required Changes In SELF (GDIS-CORE)
- No non-canonical local term definitions detected in SELF snapshot.
- Explicitly state that wallet proof artifacts/claims remain private and are not stored by trust services.
- Keep GDIS credential issuance semantics, but leave publication mechanics for private artifacts as UNSPECIFIED.
- Ensure any GQTS-hosted OpenAPI operations use canonical requirement IDs and schema-equivalent Proof/DID document structures.
- Ensure each requirement ID has a stable anchor or explicit alias anchor.

## UNSPECIFIED
- OPRF/BBS profile details and blinded/unblinded flow details remain UNSPECIFIED unless separately profiled.
- Bad-node handling policy details beyond detect/flag/reject are UNSPECIFIED.
- Cross-repo peer edits are out of scope for this repo and remain UNSPECIFIED in this run.
