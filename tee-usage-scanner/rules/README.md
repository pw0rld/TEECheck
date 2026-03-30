# Rules

This directory contains machine-readable TEE usage rules.

Each rule file describes:

- the trigger operation kinds
- the required checks
- the severity
- whether a failed static proof should emit an LLM review bundle

The first demo rule is `param_types_required.json`.

Design templates for future rule families live under `rules/templates/`.
