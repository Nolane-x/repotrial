# RepoTrial 0.8 Autonomous Threat Discovery Design

## Goal

Evolve RepoTrial from a deterministic causal engine that reasons over a fixed threat registry into a deterministic system that can discover previously unregistered threat compositions, while preventing test/fixture/benchmark evidence from being silently interpreted as production risk.

## Motivation from self-dogfood

RepoTrial 0.7 scanning its own repository produces two `arbitrary-code-execution` chains in `PROVEN` state. The supporting evidence is located under `tests/adversarial-corpus/**` and `tests/fixtures/**`, not production source. The finding is transparent but context-blind. This reveals two architectural gaps:

1. evidence is not partitioned into execution/intent realms before causal composition;
2. the causal engine can only instantiate threat definitions already present in the built-in registry.

0.8 addresses both gaps together.

## Non-goals

- Do not add an LLM runtime dependency or make model output authoritative.
- Do not auto-edit the built-in registry from discovered hypotheses.
- Do not convert `NOT_OBSERVED` into proof of absence.
- Do not weaken the Linux sandbox, copied-rootfs, namespaces, chroot, network, or resource boundaries.
- Do not silently alter legacy verdict semantics when autonomous discovery is disabled.

## Architecture

```text
canonical charges + reasoning graph
        |
        +--> Evidence Realm Index
        |      production / test / benchmark / fixture / docs / generated / vendor / unknown
        |
        +--> Causal Capability Graph
                   |
                   +--> Registry-backed chain synthesis (0.7)
                   |
                   +--> Autonomous Hypothesis Discovery
                          capability semantics
                          + generic composition grammar
                          + realm coherence
                          + evidence co-location
                          + novelty comparison vs registry
                                   |
                                   +--> discovered hypotheses
                                   |       STRUCTURAL
                                   |       CORROBORATED
                                   |       PROMOTABLE
                                   |       DISMISSED
                                   |
                                   +--> Promotion Gate
                                           transient threat definition only
                                           never mutates built-in registry
```

## Evidence realms

Every positive evidence anchor is deterministically assigned one realm from:

- `production`
- `test`
- `benchmark`
- `fixture`
- `docs`
- `generated`
- `vendor`
- `unknown`

Path classification is pure and local. More specific realms win over broader ones: adversarial corpus before generic test, fixtures before generic test, generated/vendor before production.

A charge can contain anchors in multiple realms. Realm indexing maps each stable evidence node identity to the set of realms represented by its anchors.

A causal chain receives a realm assessment:

- `PRODUCTION_RELEVANT`: at least one supported stage has production evidence and no unproven cross-realm dependency is required;
- `NON_PRODUCTION_ONLY`: all supporting evidence belongs to test/benchmark/fixture/docs/generated/vendor realms;
- `CROSS_REALM_UNPROVEN`: the chain needs evidence from multiple isolated realms without an explicit trust/reachability crossing;
- `UNKNOWN_REALM`: evidence cannot be scoped confidently.

Realm metadata is explanatory and gateable. Existing all-repository causal results remain visible.

## Capability semantics

0.8 adds a declarative capability semantic table. Each known capability can have one or more roles:

- `SOURCE`
- `CONTROL`
- `EXECUTION`
- `PERSISTENCE`
- `AUTHORITY`
- `TOOL`
- `SINK`

It can also declare semantic properties such as `sensitive`, `external`, `destructive`, `privileged`, or `stateful`.

This table is not a threat registry. It describes what a capability *is*, not a complete attack scenario.

## Generic composition grammar

Autonomous discovery uses bounded generic grammar families rather than named threats:

1. `SOURCE -> CONTROL|EXECUTION -> SINK`
2. `CONTROL -> TOOL|EXECUTION -> SINK`
3. `AUTHORITY -> CONTROL|EXECUTION -> SINK`
4. `PERSISTENCE -> CONTROL -> TOOL|EXECUTION|SINK`
5. `SOURCE(sensitive) -> CONTROL|EXECUTION -> SINK(external|persistent)`
6. `CONTROL -> AUTHORITY -> SINK(privileged|destructive)`

The grammar enumerates only observed capabilities. It never invents a capability because a grammar rule needs one.

Hard limits:

- maximum candidate depth: 4;
- maximum discovered candidates: 32 by default, 128 hard maximum;
- deterministic ordering;
- duplicate and dominance pruning;
- no candidate consisting of a single capability;
- a candidate must terminate in an impact-bearing capability or cross an authority/persistence boundary.

## Evidence coherence

Candidate composition strength is measured from concrete evidence relationships:

- same evidence node supports multiple candidate capabilities: strongest static corroboration;
- distinct evidence nodes from the same file: strong co-location;
- distinct files inside the same realm: structural support;
- mixed realms without explicit crossing: cannot become promotable.

Discovered candidate states:

- `STRUCTURAL`: role-compatible observed capabilities exist in one realm, but no strong co-location/causal trace connects them;
- `CORROBORATED`: shared evidence, same-file evidence, explicit trust crossing, or runtime causal trace connects at least two stages;
- `PROMOTABLE`: corroborated, sufficiently novel, bounded, and production-relevant; may be converted into a transient validated threat definition for further analysis;
- `DISMISSED`: dominated, too similar to a registered threat, non-impactful, or realm-incoherent.

`PROMOTABLE` means suitable for verification, not proven vulnerable.

## Novelty scoring

Each candidate is compared against every registered threat using stage capability overlap and ordered-role similarity.

Outputs:

- `nearestThreatId`
- `knownThreatSimilarity` in `[0,1]`
- `noveltyScore = 1 - knownThreatSimilarity`

Candidates at or above `0.35` novelty may be returned as discoveries. Candidates below the threshold are recorded in summary counters as registry-covered and omitted from the primary candidate list.

## Severity bounds

Severity is deterministic and conservative:

- destructive or privileged sink: up to `critical`;
- sensitive source to external sink: `critical`;
- arbitrary execution composition: `high` unless paired with privileged/destructive authority;
- persistent control chain: `high`;
- filesystem/state-only sink without sensitive/privileged semantics: at most `medium`.

Discovered severity is a risk bound, not a legacy verdict input.

## Promotion gate

`promoteDiscoveredHypothesis(candidate)` returns a transient `repotrial.threat-registry.v1` compatible threat definition only when:

- state is `PROMOTABLE`;
- candidate is production relevant;
- all stages reference known capability ids;
- novelty threshold is met;
- the candidate has at least one corroboration anchor;
- generated ids/titles are canonical and bounded.

Promotion never writes the registry file or modifies source code.

## Causal product contract

0.8 extends causal modes to:

- `off`
- `analyze`
- `discover`
- `active`

`discover` performs registry-backed causal analysis plus autonomous discovery without executing repository code.

`active` includes discovery but preserves the 0.7 rule that only supported bounded experiment templates may execute.

New realm scope control:

- `all` (compatibility default)
- `production`

Causal gates can evaluate either all chains or only production-relevant chains. Discovered candidates are exposed in `causal.json`, HTML, CLI JSON, GitHub Action outputs, and a proof-bound `hypotheses.json` artifact when discovery is enabled.

## Self-dogfood acceptance criteria

On RepoTrial 0.7 source scanned with 0.8:

- the existing two fixture/corpus arbitrary-code-execution chains remain visible in `all` scope;
- production-relevant active chain count for those chains becomes zero;
- their realm assessment is non-production, not silently deleted;
- discovery does not promote benchmark/test-only compositions into production hypotheses;
- `hypotheses.json` is proof/provenance bound;
- no raw synthetic canary is persisted.

## Testing and gates

0.8 requires:

- evidence realm classifier unit tests;
- mixed-realm and explicit-crossing tests;
- hypothesis discovery determinism under input reordering;
- novelty/dominance/promotion tests;
- production-scope causal gate tests;
- self-dogfood regression test or release checkpoint proving fixture isolation;
- adversarial corpus benchmark preserved at or above 0.7 thresholds;
- new discovery benchmark with benign production false-positive rate <= 0.05;
- Node 22 and Node 24 CI;
- coverage gate;
- npm audit and npm pack;
- Docker build/version E2E;
- sandbox-capable runtime tests where supported;
- artifact proof/provenance verification.

## Compatibility

- zero npm runtime dependencies remain mandatory;
- existing `off|analyze|active` behavior remains valid;
- `all` remains the realm-scope default;
- legacy verdict and exit codes are unchanged unless a new 0.8-specific gate is explicitly requested;
- causal/hypothesis discovery artifacts are additive and versioned.
