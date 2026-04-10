# Architecture Reservations

## Purpose

This note records the current architectural reservations for `TEECheck`.

The goal is to keep several implementation decisions intentionally conservative
until the core harness protocol is stable.

This document is not a rejection of retrieval, agent frameworks, or richer
orchestration. It is a statement of **sequencing**:

- first stabilize the case protocol
- then stabilize artifact flow
- then decide whether external frameworks are actually necessary

## Current Position

The current preferred direction is:

- use a file-driven CLI pipeline as the runtime backbone
- use a Claude Code-like interactive shell as the human-facing control layer
- defer adoption of a general multi-agent framework

In short:

`CLI/artifacts first, agent shell second, framework later if needed`

## Reservation 1: Do Not Start With A General Agent Framework

We are intentionally not starting with LangGraph, CrewAI, AutoGen, or similar
frameworks.

Reasoning:

- the hardest problem right now is not orchestration syntax
- the hardest problem is defining the right `case`, `slice`, `evidence`, and
  `review` contracts
- introducing a framework too early adds abstraction before the underlying
  protocol is stable
- security research requires replayability, auditability, and artifact-level
  debugging
- file-based pipelines are easier to inspect than opaque framework state

Current stance:

- build the first real harness runtime ourselves
- keep each stage explicit
- keep the state transition visible on disk

## Reservation 2: Do Not Start With Plain Chunk-RAG

We expect the harness to need knowledge lookup, but we do not want to center
the system around classic "retrieve raw chunks at query time" RAG.

Reasoning:

- most document RAG systems force the model to rediscover synthesized knowledge
  on every query
- TEE review needs accumulated, domain-shaped knowledge, not generic security
  text fragments
- the important problem is **what stable knowledge surface agents should read**
  rather than which vector backend is fashionable
- a poor obligation library with a fancy retrieval stack is still poor
  knowledge engineering

Current stance:

- build a knowledge layer around a curated wiki
- preserve raw sources, but do not make them the primary agent-facing surface
- allow simple retrieval over wiki pages, tags, and review memory
- treat vector retrieval as optional optimization, not the architectural center

Initial knowledge sources should include:

- TEE obligation library
- misuse patterns
- attestation verification patterns
- authorization and binding patterns
- state-machine anti-patterns
- historical review outcomes
- false-positive notes

Preferred knowledge flow:

`raw sources -> curator process -> knowledge wiki -> agent lookup`

## Reservation 3: Agents Should Collaborate Around Cases, Not Just Stages

We are keeping the stage-oriented runtime, but we are explicitly reserving the
right to evolve toward case-centered collaboration.

Reasoning:

- pure stage pipelines can become too mechanical
- TEE findings often require disagreement, challenge, and re-interpretation
- one agent should not silently own the whole truth

Current stance:

- keep stage separation for runtime simplicity
- but treat each `case pack` as the unit of collaboration
- let multiple roles contribute to one case:
  - mapper
  - expert
  - challenger
  - verifier
  - arbiter

This means the runtime is still sequential on disk, but the design intent is
collaborative, not merely assembly-line.

## Reservation 4: Heavy Static Analysis Should Remain Selective

We do not want Joern, CodeQL, or other heavyweight tools to become mandatory
for every case from the start.

Reasoning:

- heavy tools are powerful, but expensive in setup and iteration time
- we still need a fast path for exploration and case generation
- not every candidate deserves a heavyweight pass

Current stance:

- static tools are primarily part of the mapper and verifier roles
- they should help produce better case packs
- they should also be available for selective re-checking
- they are not the only source of truth

## Reservation 5: Human Review Must Stay In The Loop

We are not trying to design a fully autonomous vulnerability discovery system
yet.

Reasoning:

- TEE usage issues are highly contextual
- exploitability and trust-boundary reasoning often need human judgment
- feedback from human review is part of the harness itself

Current stance:

- humans remain the final arbiter
- every candidate should be reviewable through artifacts
- every reviewed case should produce reusable feedback

## Practical Decision Table

### What We Will Build Now

- a file-driven run layout
- explicit case artifacts
- a lightweight knowledge layer
- a curated knowledge wiki
- a collaborative role model
- a Claude Code-like interactive shell
- selective verifier hooks

### What We Will Delay

- full adoption of LangGraph/CrewAI/AutoGen
- plain chunk-RAG as the main knowledge strategy
- framework-heavy retrieval stacks
- opaque agent memory systems
- highly dynamic autonomous branching logic

## Trigger Conditions For Reconsidering Framework Adoption

We should revisit a general framework only if at least one of these becomes
true:

- the number of active agent roles grows enough that manual orchestration is
  painful
- case routing becomes highly branching and dynamic
- retries, resumes, and cross-machine scheduling become a major burden
- the harness needs long-lived distributed execution
- artifact discipline is already stable and no longer the main source of
  iteration cost

Until then, framework adoption should be treated as optional infrastructure,
not as a prerequisite for progress.

## Current Working Architecture

The preferred layered direction is:

1. `knowledge/`
2. `cases/`
3. `orchestrator/`
4. `console/`
5. `verification adapters/`

With responsibilities:

- `knowledge/`: raw sources, curated wiki, retrieval metadata, review memory
- `cases/`: case packs, hypotheses, challenges, evidence, review packets
- `orchestrator/`: run lifecycle and artifact flow
- `console/`: interactive human control layer
- `verification adapters/`: CodeQL, Joern, grep, and future tool bridges

## Summary

The current architectural reservation is simple:

`TEECheck` should first become a clear, replayable, case-driven harness.

Only after the case protocol, artifact contracts, collaboration model, and
knowledge wiki are stable should we consider introducing a general agent
framework or a more complex retrieval stack.
