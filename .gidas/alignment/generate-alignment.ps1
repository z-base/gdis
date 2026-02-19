Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Text {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
  $norm = $Text -replace '\s+', ' '
  return $norm.Trim().ToLowerInvariant()
}

function Normalize-Term {
  param([string]$Text)
  $norm = Normalize-Text $Text
  $norm = $norm -replace '[\p{P}]', ''
  $norm = $norm -replace '[_-]+', ' '
  if ($norm.EndsWith('s') -and $norm.Length -gt 3) {
    $norm = $norm.Substring(0, $norm.Length - 1)
  }
  return ($norm -replace '\s+', ' ').Trim()
}

function Strip-Html {
  param([string]$Html)
  if ([string]::IsNullOrEmpty($Html)) { return '' }
  $s = $Html -replace '<[^>]+>', ' '
  $s = $s -replace '&nbsp;', ' '
  $s = $s -replace '&amp;', '&'
  $s = $s -replace '&lt;', '<'
  $s = $s -replace '&gt;', '>'
  return ($s -replace '\s+', ' ').Trim()
}

function Get-Sha256 {
  param([string]$Text)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
  } finally {
    $sha.Dispose()
  }
}

function New-Slug {
  param([string]$Text)
  $s = Normalize-Text $Text
  $s = $s -replace '[^a-z0-9\s-]', ''
  $s = $s -replace '\s+', '-'
  $s = $s -replace '-+', '-'
  return $s.Trim('-')
}

function Get-NormativeKeywords {
  param([string]$Text)
  $keywords = @('MUST', 'MUST NOT', 'SHOULD', 'SHOULD NOT', 'MAY', 'SHALL', 'SHALL NOT', 'REQUIRED', 'OPTIONAL')
  $found = New-Object System.Collections.Generic.List[string]
  foreach ($kw in $keywords) {
    if ($Text -match "(?<![A-Za-z])$([Regex]::Escape($kw))(?![A-Za-z])") {
      $found.Add($kw)
    }
  }
  return $found
}

function Find-SectionId {
  param(
    [System.Collections.Generic.List[object]]$SectionOffsets,
    [int]$Index
  )
  $result = $null
  foreach ($s in $SectionOffsets) {
    if ($s.position -le $Index) {
      $result = $s.id
    } else {
      break
    }
  }
  if ($null -eq $result) { return 'unspecified' }
  return $result
}

function Parse-ReSpecIndex {
  param(
    [string]$SpecId,
    [string]$Repo,
    [string]$HomeUrl,
    [string]$IndexPath,
    [string]$OpenApiPath
  )

  $html = Get-Content -Raw $IndexPath
  $sectionMatches = [regex]::Matches($html, '<section\s+id="([^"]+)"', 'IgnoreCase')
  $sectionOffsets = New-Object System.Collections.Generic.List[object]
  foreach ($m in $sectionMatches) {
    $sectionOffsets.Add([pscustomobject]@{
        id       = $m.Groups[1].Value
        position = $m.Index
      })
  }

  $terms = New-Object System.Collections.Generic.List[object]
  $dfnRx = '<dt>\s*<dfn(?<attrs>[^>]*)>(?<term>.*?)</dfn>.*?</dt>\s*<dd>(?<def>.*?)</dd>'
  $dfnMatches = [regex]::Matches($html, $dfnRx, 'IgnoreCase,Singleline')
  foreach ($m in $dfnMatches) {
    $attrs = $m.Groups['attrs'].Value
    $termRaw = Strip-Html $m.Groups['term'].Value
    $defRaw = Strip-Html $m.Groups['def'].Value
    $importedFrom = $null
    if ($attrs -match 'data-cite="([^"]+)"') {
      $importedFrom = $Matches[1]
    }
    $anchor = ''
    if ($attrs -match 'id="([^"]+)"') {
      $anchor = $Matches[1]
    } elseif (-not [string]::IsNullOrWhiteSpace($importedFrom) -and $importedFrom -match '#(.+)$') {
      $anchor = $Matches[1]
    } elseif ($attrs -match 'data-lt="([^"]+)"') {
      $anchor = New-Slug (($Matches[1] -split '\|')[0])
    } else {
      $anchor = New-Slug $termRaw
    }
    $defNorm = Normalize-Text $defRaw
    $sectionId = Find-SectionId -SectionOffsets $sectionOffsets -Index $m.Index
    $terms.Add([pscustomobject]@{
        term_text                = $termRaw
        normalized_term          = Normalize-Term $termRaw
        term_id                  = $anchor
        anchor                   = "#$anchor"
        section_anchor           = "#$sectionId"
        definition_excerpt_hash  = Get-Sha256 $defNorm
        definition_text_excerpt  = if ($defRaw.Length -gt 240) { $defRaw.Substring(0, 240) } else { $defRaw }
        imported_from            = $importedFrom
      })
  }

  # Capture standalone <dfn> terms that are not expressed as <dt>/<dd> pairs
  # (for example, Annex clause labels in tables).
  $existingTermKeys = @{}
  foreach ($t in $terms) {
    $existingTermKeys["$($t.anchor)|$($t.normalized_term)"] = $true
  }
  $allDfnMatches = [regex]::Matches($html, '<dfn(?<attrs>[^>]*)>(?<term>.*?)</dfn>', 'IgnoreCase,Singleline')
  foreach ($m in $allDfnMatches) {
    $attrs = $m.Groups['attrs'].Value
    $termRaw = Strip-Html $m.Groups['term'].Value
    $importedFrom = $null
    if ($attrs -match 'data-cite="([^"]+)"') {
      $importedFrom = $Matches[1]
    }

    $anchor = ''
    if ($attrs -match 'id="([^"]+)"') {
      $anchor = $Matches[1]
    } elseif (-not [string]::IsNullOrWhiteSpace($importedFrom) -and $importedFrom -match '#(.+)$') {
      $anchor = $Matches[1]
    } elseif ($attrs -match 'data-lt="([^"]+)"') {
      $anchor = New-Slug (($Matches[1] -split '\|')[0])
    } else {
      $anchor = New-Slug $termRaw
    }

    $normalized = Normalize-Term $termRaw
    $termKey = "#$anchor|$normalized"
    if ($existingTermKeys.ContainsKey($termKey)) {
      continue
    }
    $existingTermKeys[$termKey] = $true

    $sectionId = Find-SectionId -SectionOffsets $sectionOffsets -Index $m.Index
    $terms.Add([pscustomobject]@{
        term_text                = $termRaw
        normalized_term          = $normalized
        term_id                  = $anchor
        anchor                   = "#$anchor"
        section_anchor           = "#$sectionId"
        definition_excerpt_hash  = Get-Sha256 ''
        definition_text_excerpt  = ''
        imported_from            = $importedFrom
      })
  }

  $clauses = New-Object System.Collections.Generic.List[object]
  $clauseRx = 'id="(?<anchor>(?:REQ-[A-Z0-9-]+|req-[a-z0-9-]+))"'
  $clauseMatches = [regex]::Matches($html, $clauseRx)
  foreach ($m in $clauseMatches) {
    $anchor = $m.Groups['anchor'].Value
    $excerptStart = [Math]::Max(0, $m.Index - 40)
    $excerptLen = [Math]::Min(400, $html.Length - $excerptStart)
    $excerpt = Strip-Html $html.Substring($excerptStart, $excerptLen)
    $clauseId = $anchor
    if ($anchor -match '^req-') {
      $reqMatch = [regex]::Match($excerpt, 'REQ-[A-Z0-9-]+')
      if ($reqMatch.Success) {
        $clauseId = $reqMatch.Value
      }
    }
    $clauses.Add([pscustomobject]@{
        clause_id               = $clauseId
        anchor                  = "#$anchor"
        kind                    = 'requirement'
        normative_keywords_used = @(Get-NormativeKeywords $excerpt)
        text_excerpt_hash       = Get-Sha256 (Normalize-Text $excerpt)
      })
  }

  $refs = New-Object System.Collections.Generic.List[object]
  $hrefMatches = [regex]::Matches($html, 'href="https://z-base.github.io/(gdis|gqscd|gqts)/?"')
  foreach ($m in $hrefMatches) {
    $refs.Add([pscustomobject]@{
        type  = 'href'
        value = ($m.Value -replace '^href="|"$', '')
      })
  }
  $labelMatches = [regex]::Matches($html, '\[(GDIS-CORE|GQSCD-CORE|GQTS-CORE)\]')
  foreach ($m in $labelMatches) {
    $refs.Add([pscustomobject]@{
        type  = 'label'
        value = $m.Groups[1].Value
      })
  }

  $openapi = $null
  if ($OpenApiPath -and (Test-Path $OpenApiPath)) {
    $openapiText = Get-Content -Raw $OpenApiPath
    $lines = Get-Content $OpenApiPath

    $operations = New-Object System.Collections.Generic.List[object]
    $schemas = New-Object System.Collections.Generic.List[object]
    $requirementMaps = New-Object System.Collections.Generic.List[object]

    $currentReqMap = $null
    foreach ($line in $lines) {
      if ($line -match '^(x-[a-z0-9-]+requirements):\s*$') {
        $currentReqMap = $Matches[1]
        continue
      }
      if ($null -ne $currentReqMap -and $line -match '^\s{2}([A-Z0-9-]+):\s*(.+)$') {
        $requirementMaps.Add([pscustomobject]@{
            map_key        = $currentReqMap
            requirement_id = $Matches[1]
            description     = $Matches[2]
          })
        continue
      }
      if ($null -ne $currentReqMap -and $line -notmatch '^\s{2}') {
        $currentReqMap = $null
      }
    }

    $currentPath = $null
    $currentMethod = $null
    $operation = $null
    $inOperation = $false

    function Commit-Operation {
      param([object]$Op, [System.Collections.Generic.List[object]]$Ops)
      if ($null -ne $Op -and -not [string]::IsNullOrWhiteSpace($Op.operationId)) {
        $hashInput = "{0}|{1}|{2}|{3}|{4}" -f $Op.method, $Op.path, $Op.operationId, (($Op.media_types | Sort-Object) -join ','), (($Op.schema_refs | Sort-Object) -join ',')
        $Op | Add-Member -NotePropertyName operation_contract_hash -NotePropertyValue (Get-Sha256 (Normalize-Text $hashInput))
        $Ops.Add($Op)
      }
    }

    foreach ($line in $lines) {
      if ($line -match '^  (/[^:]+):\s*$') {
        Commit-Operation -Op $operation -Ops $operations
        $operation = $null
        $currentPath = $Matches[1]
        $currentMethod = $null
        $inOperation = $false
        continue
      }

      if ($line -match '^\s{4}(get|post|put|delete|patch|head|options|trace):\s*$') {
        Commit-Operation -Op $operation -Ops $operations
        $currentMethod = $Matches[1]
        $operation = [pscustomobject]@{
          operationId = ''
          method = $currentMethod
          path = $currentPath
          requirement_key = $null
          x_requirement = $null
          media_types = New-Object System.Collections.Generic.List[string]
          schema_refs = New-Object System.Collections.Generic.List[string]
        }
        $inOperation = $true
        continue
      }

      if (-not $inOperation -or $null -eq $operation) {
        continue
      }

      if ($line -match '^\s{6}operationId:\s*(.+)$') {
        $operation.operationId = $Matches[1].Trim()
        continue
      }
      if ($line -match '^\s{6}(x-[a-z0-9-]+requirement):\s*(.+)$') {
        $operation.requirement_key = $Matches[1]
        $operation.x_requirement = $Matches[2].Trim()
        continue
      }
      if ($line -match '^\s{12}([A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+):\s*$') {
        $operation.media_types.Add($Matches[1])
        continue
      }
      if ($line -match "#/components/schemas/([A-Za-z0-9_.-]+)") {
        $operation.schema_refs.Add($Matches[1])
        continue
      }
    }
    Commit-Operation -Op $operation -Ops $operations

    $schemaSectionMatch = [regex]::Match($openapiText, '(?ms)^  schemas:\s*(?<body>.*)$')
    if ($schemaSectionMatch.Success) {
      $schemaBody = $schemaSectionMatch.Groups['body'].Value
      $schemaStartMatches = [regex]::Matches($schemaBody, '(?m)^    ([A-Za-z0-9_.-]+):\s*$')
      for ($i = 0; $i -lt $schemaStartMatches.Count; $i++) {
        $name = $schemaStartMatches[$i].Groups[1].Value
        $start = $schemaStartMatches[$i].Index
        $end = if ($i + 1 -lt $schemaStartMatches.Count) { $schemaStartMatches[$i + 1].Index } else { $schemaBody.Length }
        $block = $schemaBody.Substring($start, $end - $start)
        $schemas.Add([pscustomobject]@{
            name = $name
            json_pointer = "/components/schemas/$name"
            key_constraints_hash = Get-Sha256 (Normalize-Text (Strip-Html $block))
          })
      }
    }

    $openapi = [pscustomobject]@{
      operations = $operations
      schemas = $schemas
      requirement_maps = $requirementMaps
    }
  }

  return [pscustomobject]@{
    spec_id = $SpecId
    repo = $Repo
    commit_or_version = 'unspecified'
    home_url = $HomeUrl
    files = [pscustomobject]@{
      index_html = $IndexPath
      openapi_yaml = if ($OpenApiPath -and (Test-Path $OpenApiPath)) { $OpenApiPath } else { $null }
      agents_md = 'AGENTS.md'
    }
    terms = $terms
    clauses = $clauses
    cross_spec_references = $refs
    openapi = $openapi
  }
}

function Resolve-TermOwner {
  param([string]$NormalizedTerm, [object[]]$Members)

  $explicitOwners = @{
    'proof artifact' = 'GDIS-CORE'
    'binding credential' = 'GDIS-CORE'
    'gdis binding credential' = 'GDIS-CORE'
    'verification material' = 'GQTS-CORE'
    'public verification material' = 'GQTS-CORE'
    'did document' = 'GQTS-CORE'
    'key history' = 'GQTS-CORE'
    'web profile' = 'GQSCD-CORE'
    'eu compatibility profile' = 'GQSCD-CORE'
  }
  if ($explicitOwners.ContainsKey($NormalizedTerm)) {
    return $explicitOwners[$NormalizedTerm]
  }

  $deviceHints = @('device', 'controller', 'sole control', 'intent', 'qscd', 'tee', 'attestation', 'key')
  $identityHints = @('pid', 'mrz', 'identity', 'binding', 'proof artifact', 'credential', 'claim', 'gdis')
  $gqtsHints = @('event', 'log', 'host', 'scheme descriptor', 'service descriptor', 'replication', 'gqts', 'head digest', 'verification material', 'did document', 'publication', 'status')

  foreach ($h in $deviceHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GQSCD-CORE' }
  }
  foreach ($h in $identityHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GDIS-CORE' }
  }
  foreach ($h in $gqtsHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GQTS-CORE' }
  }

  # Cross-cutting fallback: pick the spec where the term was first declared.
  return $Members[0].spec_id
}

function Resolve-ClauseOwner {
  param([string]$OperationId)
  if ($OperationId -match '(?i)gdis|pid|identity|binding') { return 'GDIS-CORE' }
  return 'GQTS-CORE'
}

function Write-FailureArtifacts {
  param(
    [string]$ReportPath,
    [string]$PlanPath,
    [string]$Reason,
    [string[]]$Details
  )

  $reportLines = New-Object System.Collections.Generic.List[string]
  $reportLines.Add('# Alignment Report')
  $reportLines.Add('')
  $reportLines.Add('## Status')
  $reportLines.Add("- FAILED_CLOSED: $Reason")
  $reportLines.Add('')
  $reportLines.Add('## Details')
  if ($Details.Count -eq 0) {
    $reportLines.Add('- none')
  } else {
    foreach ($detail in $Details) {
      $reportLines.Add("- $detail")
    }
  }
  $reportLines.Add('')
  $reportLines.Add('Provide local peer snapshots and a valid `gidas-alignment.config.json`, then rerun `.gidas/alignment/generate-alignment.ps1`.')
  $reportLines | Set-Content -Encoding UTF8 $ReportPath

  $planLines = New-Object System.Collections.Generic.List[string]
  $planLines.Add('# Alignment Plan')
  $planLines.Add('')
  $planLines.Add('## Status')
  $planLines.Add("- BLOCKED: $Reason")
  $planLines.Add('')
  $planLines.Add('## Preconditions')
  foreach ($detail in $Details) {
    $planLines.Add("- $detail")
  }
  $planLines | Set-Content -Encoding UTF8 $PlanPath
}

function New-AlignmentPromptTemplate {
  return @'
SYSTEM / ROLE
You are GPT-5.3-Codex acting as a cross-repository alignment agent for these specs:
- z-base/gdis   (GDIS-CORE)
- z-base/gqts  (GQTS-CORE)
- z-base/gqscd (GQSCD-CORE)
Follow the AGENTS.md drafting posture (read it first) and the repo config for peer snapshots.

HARD CONSTRAINTS:
- Wallet-private vs Trust-public: Treat "proof artifacts" (credentials, PID binding VCs, attestations) as private to the wallet. Do NOT have GQTS or GQSCD restate or store private claims. GQTS only stores public verification material (keys, DID docs, status) in its tamper-evident log.
- Directed linear logs: Assume the GQTS history is an append-only, signed chain. The first event is the root key; each new verification method event must link by signature to the previous head. If a log entry conflicts, it should be flagged as a bad node (do not silently merge).
- No duplication of definitions: Replace duplicated term definitions with `data-cite` references to the canonical spec.

INPUT PARAMETERS (per repo)
SELF_SPEC_ID, SELF_REPO_FULL_NAME, SELF_HOME_URL as before.
Peer snapshots as before.

TASKS:
0. Preconditions: Read AGENTS.md and gidas-alignment.config.json. Ensure peer snapshots exist for all peers. Fail (alignment-report.md) if any are missing.
1. Deterministic index: Run scripts/cross-spec-align.mjs (or replicate its behavior) to compute `spec-index.self.json` and `spec-index.peers.json`.
2. Cross-spec mapping: Analyze `cross-spec-map.json`:
   - Term clusters: Merge same concepts. Enforce canonical ownership rules (device/key terms -> GQSCD; identity/PID terms -> GDIS; log/publication terms -> GQTS).
   - New term rules: "proof artifact" or "binding credential" = private, GDIS-owned; "verification material" = public, GQTS-owned.
   - Clause clusters: Map identical OpenAPI ops. Check no op is defined in two specs with different semantics.
   - Conflict detection:
     - If the same operationId has different request/response schemas, flag `operation-contract-conflict`.
     - If the same operation has different requirement IDs (`x-gqts-requirement`), flag `requirement-id-namespace-conflict`.
   - Gap detection:
     - If a term is used but not defined in SELF (and not imported via data-cite), flag undefined-term.
3. Alignment plan (alignment-plan.md):
   - List canonical term/anchor owners (include "proof artifact" as GDIS, "verification material" as GQTS).
   - List canonical clause mapping per operation.
   - Outline exactly what SELF repo must change:
     - E.g. "Replace local definition of `mechanical validity` with `data-cite="GQTS-CORE#mechanical-validity"`."
     - "In GDIS, keep the Verifiable Credential (PID binding) but mark its output as private (UNSPECIFIED how to publish)."
     - "In GQTS, ensure the event log is described as a signed linear chain (add or verify text to that effect)."
     - Mark any details that remain UNSPECIFIED.
4. Apply edits to SELF repo:
   - LocalBiblio: Ensure entries for GDIS-CORE, GQTS-CORE, GQSCD-CORE.
   - Definitions: For each non-canonical term in SELF, replace `<dfn>Term</dfn>` with `<dfn data-cite="OWNER_SPEC_ID#canonical-anchor">Term</dfn>` and minimal local note.
   - Verification vs Proof: Explicitly note in text that SELF does not store private wallet claims. (No actual data migration is needed, just cross-ref.)
   - OpenAPI: If SELF includes any GQTS-hosted endpoints, delete or rewrite them to use canonical IDs. Ensure `x-gqts-requirement` matches GQTS's numbering and verify schema equivalence (especially Proof and DID Document structure).
   - Anchors: Confirm every requirement ID has a stable anchor; add alias spans if needed.
5. Output:
   - proposed-changes.patch: a git diff of the above edits.
   - alignment-report.md: summarize changes made, duplicates removed, and any remaining conflicts (UNSPECIFIED).
   - alignment-plan.md: the plan from step 3.

FINAL OUTPUT (to user)
A concise explanation of changes, plus:
- Files changed.
- Summary of duplicates removed and cross-references added.
- Pointer to `.gidas/alignment/` with spec-index and map.
- The prompt template (above) is ready to copy into each repo for alignment.
'@
}

$selfRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$outDir = Join-Path $selfRoot '.gidas\alignment'
if (-not (Test-Path $outDir)) {
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$specIndexSelfPath = Join-Path $outDir 'spec-index.self.json'
$specIndexPeersPath = Join-Path $outDir 'spec-index.peers.json'
$crossMapPath = Join-Path $outDir 'cross-spec-map.json'
$reportPath = Join-Path $outDir 'alignment-report.md'
$planPath = Join-Path $outDir 'alignment-plan.md'
$promptTemplatePath = Join-Path $outDir 'codex-alignment-prompt.template.txt'

$agentsPath = Join-Path $selfRoot 'AGENTS.md'
if (-not (Test-Path $agentsPath)) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'missing AGENTS.md' -Details @('AGENTS.md must exist at repo root.')
  throw 'Missing AGENTS.md at repository root.'
}
$agentsContent = Get-Content -Raw $agentsPath
if ([string]::IsNullOrWhiteSpace($agentsContent)) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'empty AGENTS.md' -Details @('AGENTS.md is present but empty.')
  throw 'AGENTS.md is empty.'
}

$configPath = Join-Path $selfRoot 'gidas-alignment.config.json'
if (-not (Test-Path $configPath)) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'missing gidas-alignment.config.json' -Details @('Create `gidas-alignment.config.json` with SELF and peer snapshot paths.')
  throw 'Missing gidas-alignment.config.json.'
}

try {
  $config = Get-Content -Raw $configPath | ConvertFrom-Json
} catch {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'invalid gidas-alignment.config.json' -Details @('Config file is not valid JSON.')
  throw
}

if ($null -eq $config.self) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'invalid alignment config' -Details @('`self` block is required in gidas-alignment.config.json.')
  throw 'Missing config.self.'
}
if ($null -eq $config.peers -or $config.peers.Count -eq 0) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'invalid alignment config' -Details @('`peers` array is required in gidas-alignment.config.json.')
  throw 'Missing config.peers.'
}

$promptTemplate = New-AlignmentPromptTemplate
$promptTemplate | Set-Content -Encoding UTF8 $promptTemplatePath

$selfSpec = $config.self
$selfIndexPath = Resolve-Path (Join-Path $selfRoot ([string]$selfSpec.index)) -ErrorAction SilentlyContinue
if ($null -eq $selfIndexPath) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'missing self snapshot' -Details @("Cannot resolve SELF index path: $($selfSpec.index)")
  throw "Missing SELF index snapshot at $($selfSpec.index)."
}
$selfOpenApiPath = $null
if (-not [string]::IsNullOrWhiteSpace([string]$selfSpec.openapi)) {
  $resolvedSelfOpenApiPath = Resolve-Path (Join-Path $selfRoot ([string]$selfSpec.openapi)) -ErrorAction SilentlyContinue
  if ($null -ne $resolvedSelfOpenApiPath) {
    $selfOpenApiPath = $resolvedSelfOpenApiPath.Path
  }
}

$selfIndex = Parse-ReSpecIndex `
  -SpecId ([string]$selfSpec.spec_id) `
  -Repo ([string]$selfSpec.repo) `
  -HomeUrl ([string]$selfSpec.home_url) `
  -IndexPath $selfIndexPath.Path `
  -OpenApiPath $selfOpenApiPath

$peers = New-Object System.Collections.Generic.List[object]
$missingPeers = New-Object System.Collections.Generic.List[string]
foreach ($peer in $config.peers) {
  $peerIndexPath = Resolve-Path (Join-Path $selfRoot ([string]$peer.index)) -ErrorAction SilentlyContinue
  if ($null -eq $peerIndexPath) {
    $missingPeers.Add([string]$peer.spec_id)
    continue
  }
  $peerOpenApiPath = $null
  if (-not [string]::IsNullOrWhiteSpace([string]$peer.openapi)) {
    $resolvedPeerOpenApiPath = Resolve-Path (Join-Path $selfRoot ([string]$peer.openapi)) -ErrorAction SilentlyContinue
    if ($null -ne $resolvedPeerOpenApiPath) {
      $peerOpenApiPath = $resolvedPeerOpenApiPath.Path
    }
  }

  $peers.Add(
    (Parse-ReSpecIndex `
      -SpecId ([string]$peer.spec_id) `
      -Repo ([string]$peer.repo) `
      -HomeUrl ([string]$peer.home_url) `
      -IndexPath $peerIndexPath.Path `
      -OpenApiPath $peerOpenApiPath)
  )
}

$selfIndex | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $specIndexSelfPath
$peers | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $specIndexPeersPath

if ($missingPeers.Count -gt 0) {
  Write-FailureArtifacts -ReportPath $reportPath -PlanPath $planPath -Reason 'missing peer snapshots' -Details ($missingPeers | ForEach-Object { "Missing peer snapshot: $_" })
  throw "Missing peer snapshots: $($missingPeers -join ', ')"
}

$allSpecs = @($selfIndex) + @($peers.ToArray())
$termGroups = @{}
foreach ($spec in $allSpecs) {
  foreach ($term in $spec.terms) {
    if (-not $termGroups.ContainsKey($term.normalized_term)) {
      $termGroups[$term.normalized_term] = New-Object System.Collections.Generic.List[object]
    }
    $termGroups[$term.normalized_term].Add([pscustomobject]@{
        spec_id = $spec.spec_id
        term_text = $term.term_text
        anchor = $term.anchor
        definition_excerpt_hash = $term.definition_excerpt_hash
        imported_from = $term.imported_from
      })
  }
}

$canonicalTerms = New-Object System.Collections.Generic.List[object]
$conflicts = New-Object System.Collections.Generic.List[object]
foreach ($key in ($termGroups.Keys | Sort-Object)) {
  $members = $termGroups[$key]
  $owner = Resolve-TermOwner -NormalizedTerm $key -Members $members
  $ownerMember = $members | Where-Object { $_.spec_id -eq $owner } | Select-Object -First 1
  if ($null -eq $ownerMember) {
    $ownerMember = $members[0]
    $owner = $ownerMember.spec_id
  }

  $localMembers = @($members | Where-Object { [string]::IsNullOrWhiteSpace($_.imported_from) })
  $hashes = @($localMembers | Select-Object -ExpandProperty definition_excerpt_hash -Unique)
  if ($localMembers.Count -gt 1 -and $hashes.Count -gt 1) {
    $conflicts.Add([pscustomobject]@{
        type = 'term-definition-conflict'
        concept = $key
        members = $members
      })
  }

  $canonicalTerms.Add([pscustomobject]@{
      canonical_term = $key
      canonical_owner_spec_id = $owner
      canonical_anchor = $ownerMember.anchor
      aliases = @($members | Select-Object -ExpandProperty term_text -Unique)
      members = $members
    })
}

$operationRows = New-Object System.Collections.Generic.List[object]
foreach ($spec in $allSpecs) {
  if ($null -eq $spec.openapi) { continue }
  foreach ($op in $spec.openapi.operations) {
    $operationRows.Add([pscustomobject]@{
        spec_id = $spec.spec_id
        operationId = $op.operationId
        method = $op.method
        path = $op.path
        requirement_id = $op.x_requirement
        requirement_key = $op.requirement_key
        operation_contract_hash = $op.operation_contract_hash
      })
  }
}

$operationGroups = @{}
foreach ($row in $operationRows) {
  if ([string]::IsNullOrWhiteSpace($row.operationId)) { continue }
  if (-not $operationGroups.ContainsKey($row.operationId)) {
    $operationGroups[$row.operationId] = New-Object System.Collections.Generic.List[object]
  }
  $operationGroups[$row.operationId].Add($row)
}

$canonicalClauses = New-Object System.Collections.Generic.List[object]
foreach ($opId in ($operationGroups.Keys | Sort-Object)) {
  $members = $operationGroups[$opId]
  $owner = Resolve-ClauseOwner -OperationId $opId
  $ownerMember = $members | Where-Object { $_.spec_id -eq $owner } | Select-Object -First 1
  if ($null -eq $ownerMember) {
    $ownerMember = $members[0]
    $owner = $ownerMember.spec_id
  }
  $canonicalClauses.Add([pscustomobject]@{
      clause_concept = $opId
      canonical_owner_spec_id = $owner
      canonical_clause_id = $ownerMember.requirement_id
      member_clause_ids = @($members | ForEach-Object { "$($_.spec_id):$($_.requirement_id)" })
      member_operation_contract_hashes = @($members | ForEach-Object { "$($_.spec_id):$($_.operation_contract_hash)" })
    })

  $reqIds = @($members | Select-Object -ExpandProperty requirement_id -Unique)
  if ($reqIds.Count -gt 1) {
    $conflicts.Add([pscustomobject]@{
        type = 'requirement-id-namespace-conflict'
        concept = $opId
        members = $members
      })
  }

  $contractHashes = @($members | Select-Object -ExpandProperty operation_contract_hash -Unique)
  if ($contractHashes.Count -gt 1) {
    $conflicts.Add([pscustomobject]@{
        type = 'operation-contract-conflict'
        concept = $opId
        members = $members
      })
  }
}

$allDefinedTerms = @{}
foreach ($spec in $allSpecs) {
  foreach ($term in $spec.terms) {
    $allDefinedTerms[$term.normalized_term] = $true
  }
}

$gaps = New-Object System.Collections.Generic.List[object]
foreach ($spec in $allSpecs) {
  $content = Get-Content -Raw $spec.files.index_html
  $termRefs = [regex]::Matches($content, '\[=([^=\]]+)=\]')
  foreach ($ref in $termRefs) {
    $t = Normalize-Term $ref.Groups[1].Value
    if (-not $allDefinedTerms.ContainsKey($t)) {
      $gaps.Add([pscustomobject]@{
          type = 'undefined-term'
          spec_id = $spec.spec_id
          reference = $ref.Groups[1].Value
        })
    }
  }

  $reqRefs = [regex]::Matches($content, 'REQ-[A-Z0-9-]+')
  $clauseSet = @{}
  foreach ($c in $spec.clauses) {
    $clauseSet[$c.clause_id] = $true
  }
  foreach ($rr in $reqRefs) {
    $req = $rr.Value
    if (-not $clauseSet.ContainsKey($req)) {
      $gaps.Add([pscustomobject]@{
          type = 'missing-requirement-anchor'
          spec_id = $spec.spec_id
          reference = $req
        })
    }
  }
}

$crossMap = [pscustomobject]@{
  alignment_focus = [pscustomobject]@{
    wallet_private_artifacts = @('proof artifact', 'binding credential', 'gdis binding credential')
    trust_public_verification_material = @('verification material', 'did document', 'key history')
    gqts_log_model = 'append-only signed linear chain; root key at first event; each event links to previous head by signature'
    conflict_resolution = 'flag conflicting nodes as bad nodes and do not silently merge'
  }
  canonical_terms = $canonicalTerms
  canonical_clauses = $canonicalClauses
  conflicts = $conflicts
  gaps = $gaps
}
$crossMap | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $crossMapPath

$selfSpecId = [string]$selfIndex.spec_id
$selfNonCanonicalTerms = New-Object System.Collections.Generic.List[object]
foreach ($ct in $canonicalTerms) {
  if ($ct.canonical_owner_spec_id -eq $selfSpecId) { continue }
  $selfLocalMembers = @($ct.members | Where-Object {
      $_.spec_id -eq $selfSpecId -and [string]::IsNullOrWhiteSpace($_.imported_from)
    })
  if ($selfLocalMembers.Count -gt 0) {
    $selfNonCanonicalTerms.Add([pscustomobject]@{
        term = $ct.canonical_term
        owner = $ct.canonical_owner_spec_id
        owner_anchor = $ct.canonical_anchor
      })
  }
}

$criticalTerms = @('proof artifact', 'binding credential', 'gdis binding credential', 'verification material', 'public verification material')
$planLines = New-Object System.Collections.Generic.List[string]
$planLines.Add('# Alignment Plan')
$planLines.Add('')
$planLines.Add('## Canonical Term Owners')
foreach ($term in $criticalTerms) {
  $match = $canonicalTerms | Where-Object { $_.canonical_term -eq $term } | Select-Object -First 1
  if ($null -eq $match) {
    $planLines.Add("- $term -> UNSPECIFIED (term missing from current snapshots)")
  } else {
    $planLines.Add("- $term -> $($match.canonical_owner_spec_id)$($match.canonical_anchor)")
  }
}
$planLines.Add('- Device/key terms -> GQSCD-CORE (unless explicitly scoped as public verification material).')
$planLines.Add('- Identity/PID terms -> GDIS-CORE.')
$planLines.Add('- Log/publication terms -> GQTS-CORE.')
$planLines.Add('')
$planLines.Add('## Canonical Clause Mapping')
foreach ($clause in $canonicalClauses) {
  $planLines.Add("- $($clause.clause_concept) -> $($clause.canonical_owner_spec_id):$($clause.canonical_clause_id)")
}
$planLines.Add('')
$planLines.Add("## Required Changes In SELF ($selfSpecId)")
if ($selfNonCanonicalTerms.Count -eq 0) {
  $planLines.Add('- No non-canonical local term definitions detected in SELF snapshot.')
} else {
  foreach ($item in $selfNonCanonicalTerms) {
    $anchorId = $item.owner_anchor.TrimStart('#')
    $planLines.Add("- Replace local definition of `$($item.term)` with `<dfn data-cite=`"$($item.owner)#$anchorId`">...`</dfn>` and keep only minimal local note.")
  }
}
$planLines.Add('- Explicitly state that wallet proof artifacts/claims remain private and are not stored by trust services.')
$planLines.Add('- Keep GDIS credential issuance semantics, but leave publication mechanics for private artifacts as UNSPECIFIED.')
$planLines.Add('- Ensure any GQTS-hosted OpenAPI operations use canonical requirement IDs and schema-equivalent Proof/DID document structures.')
$planLines.Add('- Ensure each requirement ID has a stable anchor or explicit alias anchor.')
$planLines.Add('')
$planLines.Add('## UNSPECIFIED')
$planLines.Add('- OPRF/BBS profile details and blinded/unblinded flow details remain UNSPECIFIED unless separately profiled.')
$planLines.Add('- Bad-node handling policy details beyond detect/flag/reject are UNSPECIFIED.')
$planLines.Add('- Cross-repo peer edits are out of scope for this repo and remain UNSPECIFIED in this run.')
$planLines | Set-Content -Encoding UTF8 $planPath

$dupCount = 0
foreach ($ct in $canonicalTerms) {
  $memberCount = ($ct.members | Measure-Object).Count
  if ($memberCount -gt 1) {
    $dupCount++
  }
}
$termConflictCount = ($conflicts | Where-Object { $_.type -eq 'term-definition-conflict' } | Measure-Object).Count
$reqConflictCount = ($conflicts | Where-Object { $_.type -eq 'requirement-id-namespace-conflict' } | Measure-Object).Count
$operationConflictCount = ($conflicts | Where-Object { $_.type -eq 'operation-contract-conflict' } | Measure-Object).Count
$gapCount = ($gaps | Measure-Object).Count

$topReqConflicts = $conflicts |
  Where-Object { $_.type -eq 'requirement-id-namespace-conflict' } |
  Select-Object -First 12
$topOperationConflicts = $conflicts |
  Where-Object { $_.type -eq 'operation-contract-conflict' } |
  Select-Object -First 12

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add('# Alignment Report')
$reportLines.Add('')
$reportLines.Add('## Status')
$reportLines.Add('- COMPLETED: preconditions, deterministic indexes, cross-spec map, and alignment plan generated from local working trees.')
$reportLines.Add('')
$reportLines.Add('## Alignment Focus Applied')
$reportLines.Add('- Wallet-private artifacts (`proof artifact`, binding credentials, VC claims) are treated as private and GDIS-owned concepts.')
$reportLines.Add('- Trust-public verification material (`verification material`, DID docs, key history) is treated as GQTS-owned publication state.')
$reportLines.Add('- GQTS log semantics are modeled as an append-only signed chain with bad-node conflict signaling.')
$reportLines.Add('')
$reportLines.Add('## What Changed')
$reportLines.Add("- Read `AGENTS.md` and `gidas-alignment.config.json` preconditions.")
$reportLines.Add("- Generated `spec-index.self.json` for $selfSpecId.")
$reportLines.Add('- Generated `spec-index.peers.json` for configured peer snapshots.')
$reportLines.Add('- Generated `cross-spec-map.json` with canonical ownership, new conflict classes, and gaps.')
$reportLines.Add('- Generated `alignment-plan.md` with SELF-specific edits and UNSPECIFIED items.')
$reportLines.Add('- Generated `codex-alignment-prompt.template.txt` ready to copy into peer repos.')
$reportLines.Add('')
$reportLines.Add('## Duplicates Removed')
if ($selfNonCanonicalTerms.Count -eq 0) {
  $reportLines.Add('- none detected in this generation step.')
} else {
  foreach ($item in $selfNonCanonicalTerms) {
    $reportLines.Add("- planned removal of local duplicate term: `$($item.term)` (canonical owner: $($item.owner)).")
  }
}
$reportLines.Add('')
$reportLines.Add('## Cross-References Added')
$reportLines.Add('- no spec text edits were applied by this generator; cross-reference actions are listed in `alignment-plan.md`.')
$reportLines.Add('')
$reportLines.Add('## Metrics')
$reportLines.Add("- term_clusters_with_multiple_members: $dupCount")
$reportLines.Add("- term_definition_conflicts: $termConflictCount")
$reportLines.Add("- requirement_id_namespace_conflicts: $reqConflictCount")
$reportLines.Add("- operation_contract_conflicts: $operationConflictCount")
$reportLines.Add("- gaps_detected: $gapCount")
$reportLines.Add('')
$reportLines.Add('## Key Requirement ID Namespace Conflicts')
if ((($topReqConflicts | Measure-Object).Count) -eq 0) {
  $reportLines.Add('- none')
} else {
  foreach ($c in $topReqConflicts) {
    $members = ($c.members | ForEach-Object { "$($_.spec_id) $($_.method.ToUpper()) $($_.path) -> $($_.requirement_id)" }) -join '; '
    $reportLines.Add("- $($c.concept): $members")
  }
}
$reportLines.Add('')
$reportLines.Add('## Key Operation Contract Conflicts')
if ((($topOperationConflicts | Measure-Object).Count) -eq 0) {
  $reportLines.Add('- none')
} else {
  foreach ($c in $topOperationConflicts) {
    $members = ($c.members | ForEach-Object { "$($_.spec_id) $($_.method.ToUpper()) $($_.path) -> $($_.operation_contract_hash)" }) -join '; '
    $reportLines.Add("- $($c.concept): $members")
  }
}
$reportLines.Add('')
$reportLines.Add('## Remaining Conflicts/Gaps')
$reportLines.Add('- See `cross-spec-map.json` (`conflicts[]`, `gaps[]`) and `alignment-plan.md` for UNSPECIFIED/TODO items requiring editorial decisions.')

$reportLines | Set-Content -Encoding UTF8 $reportPath

