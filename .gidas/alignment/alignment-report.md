# Alignment Report

## Status
- COMPLETED: preconditions, deterministic indexes, cross-spec map, and alignment plan generated from local working trees.

## Alignment Focus Applied
- Wallet-private artifacts (`proof artifact`, binding credentials, VC claims) are treated as private and GDIS-owned concepts.
- Trust-public verification material (`verification material`, DID docs, key history) is treated as GQTS-owned publication state.
- GQTS log semantics are modeled as an append-only signed chain with bad-node conflict signaling.

## What Changed
- Read AGENTS.md and gidas-alignment.config.json preconditions.
- Generated spec-index.self.json for GDIS-CORE.
- Generated `spec-index.peers.json` for configured peer snapshots.
- Generated `cross-spec-map.json` with canonical ownership, new conflict classes, and gaps.
- Generated `alignment-plan.md` with SELF-specific edits and UNSPECIFIED items.
- Generated `codex-alignment-prompt.template.txt` ready to copy into peer repos.

## Duplicates Removed
- none detected in this generation step.

## Cross-References Added
- no spec text edits were applied by this generator; cross-reference actions are listed in `alignment-plan.md`.

## Metrics
- term_clusters_with_multiple_members: 0
- term_definition_conflicts: 0
- requirement_id_namespace_conflicts: 0
- operation_contract_conflicts: 1
- gaps_detected: 42

## Key Requirement ID Namespace Conflicts
- none

## Key Operation Contract Conflicts
- getEventById: GDIS-CORE GET /.well-known/gidas/gqts/event/{logId}/{eventId} -> 629c37284614988e4423fae71ab52f7f79b30a347904c9404ecf4744149cb1b7; GQTS-CORE GET /.well-known/gidas/gqts/event/{logId}/{eventId} -> 3437664a3321cdfe81317baf4e6a75dd04a37bba645fa0a572ac4aa15d2cc413

## Remaining Conflicts/Gaps
- See `cross-spec-map.json` (`conflicts[]`, `gaps[]`) and `alignment-plan.md` for UNSPECIFIED/TODO items requiring editorial decisions.
