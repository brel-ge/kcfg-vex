# CycloneDX VEX Integration To-Do

## Goal

Add CycloneDX VEX output generation to the `yocto-scan` command, accepting an SBOM path to produce correct component references.

## Assumptions

- SBOM provided is CycloneDX JSON.
- A linux kernel `.config` file is provided (same one optionally used for symbol filtering in tracing).
- Only linux kernel CVEs processed for VEX now.
- Default VEX output: CycloneDX 1.6 JSON.

## Acceptance Criteria

- `yocto-scan --sbom SBOM.json --vex-out VEX.json` produces valid CycloneDX VEX referencing kernel component(s).
- Each unpatched linux kernel CVE appears exactly once with derived analysis state.
- Idempotent with cache (re-run produces same VEX when inputs unchanged).
- Clear errors for missing SBOM or missing kernel component.

## Phases & Tasks

### Phase 1: Requirements & Design

- [ ] Confirm CycloneDX spec version (1.5 vs 1.6) and fields used.
- [ ] Decide CLI flags: `--sbom`, `--vex-out`, (future: `--vex-format`, `--kernel-ref`).
- [ ] Define mapping of CVE -> VEX analysis.state & justification heuristics.
- [ ] Decide default states (affected / not_affected / under_investigation).
- [ ] Strategy for multiple kernel components (choose all vs first).

### Phase 2: Dependencies / Data Structures

- [ ] Decide: use `cyclonedx-python-lib` or handcrafted JSON.
- [ ] If using lib: add to pyproject dependencies.
- [ ] Create internal model (dataclass) for VEX entry.
- [ ] SBOM component index by bom-ref, name, purl.

### Phase 3: CLI Changes

- [ ] Extend `yocto_scan` signature with `sbom: Path | None`, `vex_out: Path | None`.
- [ ] Validate required combinations (cannot set `--vex-out` without `--sbom`).
- [ ] Update help text and README.

### Phase 4: SBOM Parsing

- [ ] Load JSON, verify `bomFormat == "CycloneDX"`.
- [ ] Extract `components` and build maps (bom-ref -> component).
- [ ] Kernel component detection heuristics (name contains `linux` or `kernel`, purl type patterns).
- [ ] (Optional) Implement `--kernel-ref` override.
- [ ] Handle zero / multiple matches gracefully.

### Phase 5: CVE Analysis Heuristics

- [ ] For each CVE gather: file list, symbol union size, required config symbols (set of enabling Kconfig symbols traced for those files).
- [ ] State rules (revised with kernel config):
  - affected: at least one required symbol is enabled in the provided `.config` AND CVE lists programFiles.
  - not_affected: CVE lists programFiles AND none of its required symbols are enabled (all required symbols missing / set !=y/=m).
  - not_applicable: CVE lists programFiles but every required symbol is entirely absent from the kernel config (distinguish from disabled? Decide if we separate; see Open Questions) OR (option chosen) treat absence & disabled the same (choose one approach and document).
  - under_investigation: CVE has no programFiles.
- [ ] Decide whether to collapse `not_applicable` into `not_affected` if CycloneDX consumer tooling lacks distinction (spec uses state values: affected, not_affected, fixed, under_investigation – NEED: Evaluate if "not applicable" must be represented via state `not_affected` + justification `component_not_present`).
- [ ] Map to CycloneDX fields:
  - not_affected & missing symbols => justification `component_not_present`.
  - not_affected but symbols present yet disabled => justification `vulnerable_code_not_in_execute_path` (or `code_not_present` alternative) – refine.
  - under_investigation => no justification.
- [ ] Compose `analysis.detail` string (files count, sample symbols, reasoning of enabled vs missing vs disabled).

### Phase 6: VEX Document Construction

- [ ] Root: `bomFormat`, `specVersion`, `version`, `metadata.timestamp`.
- [ ] Build `vulnerabilities` array entries with: id, source (name/url), analysis, affects (refs), (optional) ratings.
- [ ] Validate structure (library serializer or JSON schema if available).

### Phase 7: Output Integration

- [ ] Write JSON to `--vex-out` (pretty-printed).
- [ ] Emit console summary of counts per state.
- [ ] (Optional) Add `--vex-minify` flag.

### Phase 8: Testing

- [ ] Add fixture SBOM with kernel component bom-ref.
- [ ] Add fixture Yocto summary with mixed CVEs (patched, unpatched variants).
- [ ] Mock CVE fetch (inject static data) to avoid network.
- [ ] Assert state mapping and justification logic.
- [ ] Test cache reuse + force refresh path with VEX generation.

### Phase 9: Documentation

- [ ] README updates (usage snippet, heuristic explanation, sample VEX snippet).
- [ ] Add rationale for analysis states & justifications.

### Phase 10: Quality

- [ ] Update pyproject (dependency) & lockfile.
- [ ] Run lint & (future) tests in CI.
- [ ] Consider jsonschema validation step (optional).

## Backlog / Future Enhancements

- Per-CVE override mapping file for state/justification.
- Include CVSS scores (requires extra source e.g., NVD enrichment).
- Merge/update existing VEX (append mode).
- Parallel CVE fetch (rate-limit aware).

## Open Questions

- Which CycloneDX spec version guaranteed by downstream tooling?
- How to represent "not applicable" best: separate heuristic state or reuse `not_affected` with `component_not_present` justification (spec doesn't define `not_applicable` explicitly)?
- Preferred justification for disabled vs entirely missing symbols? (Possible split: disabled => `vulnerable_code_not_in_execute_path`; missing => `component_not_present`).
- Include trace edges or object list in `analysis.detail` or separate custom field?

---

Generated initial plan; update items as design decisions are finalized.
