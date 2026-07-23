# TEE×Web3 design dossier template

## 0. Executive introduction
- Why this project matters:
- Product or protocol context:
- Plain-language description:
- Why the TEE is used in this setting:

## 1. Project identity
- Project name:
- Repo URL:
- Commit / tag audited:
- Primary languages:
- Related docs / paper:
- TEE type:
- Deployment status:

## 2. System purpose
- What does the project do?
- Why does it use a TEE or confidential VM?
- What is the TEE role?
  - confidential execution
  - validator / consensus integrity
  - oracle / bridge
  - key management / signing
  - off-chain worker / coprocessor

## 3. Trusted vs untrusted components
### Trusted
- enclave / guest
- verifier
- key manager
- contract logic
- release signing keys
- other:

### Untrusted
- host OS / hypervisor
- relayer / gateway
- storage volume
- RPC client
- network
- operator
- cloud control plane
- other:

## 4. Claimed security properties
- confidentiality:
- integrity:
- continuity / rollback resistance:
- anti-cloning / anti-forking:
- metadata privacy:
- upgrade / recovery safety:

## 5. Trust boundaries
List each major boundary and why it matters.

## 6. Lifecycle mapping
### Identity lifecycle
### Key lifecycle
### State lifecycle

## 7. Trust-path summary
- Attestation acceptance path:
- Key or output binding path:
- Freshness / replay path:
- State continuity or recovery path:
- Host-mediated input path:
- Debug / simulation / bypass path:

## 8. Code map
List security-critical directories and files.

## 9. Likely TEE×Web3 risks
List the most plausible risk families for this repo.

## 10. Plain-language summary
Write a concise direct explanation suitable for a first-time reader.
