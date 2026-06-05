# Stage 1: Architecture Dossier Prompt

You are auditing a TEE-enabled Web3 repository. Based on the fingerprint data below, generate a structured architecture dossier.

## Repository Fingerprint

{{fingerprint}}

## Repository Structure

{{repo_structure}}

## Instructions

Produce a structured dossier with these sections:

1. **Executive Summary** (2-3 sentences): What does this project do? What TEE platform does it use? What is its Web3 role?

2. **Parties and Roles**: Identify the distinct parties/actors in this system (e.g., hardware vendor, provisioning service, verifier, attester, relying party). For each party, describe their role, what they provide, and what they expect from others. This is critical for understanding who trusts whom and why.

3. **Architecture Overview** (1-2 paragraphs): Describe the high-level architecture. Identify enclave/host boundaries, trusted/untrusted zones, and key components. Explain how the parties interact through these components.

4. **Trust Boundary Description**: Where are the trust boundaries? What crosses them? What verification happens at each boundary? Map each boundary to the parties on each side.

5. **Key Components** (list): List the 5-10 most security-relevant components. For each, note which party owns/operates it and whether it runs in a trusted or untrusted context.

## Rules

- Stay grounded in the fingerprint evidence. Do not speculate beyond what the data shows.
- Separate explicit evidence from inference.
- Prefer repo docs and code signals over generic TEE commentary.
- If the fingerprint is sparse, say so explicitly rather than filling gaps with assumptions.

Respond with a JSON object matching the schema provided.
