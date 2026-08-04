# OWS Specification

> Scope, document classes, conformance, and extension rules for Open Wallet Standard (OWS).

## Status

OWS is a local-first wallet specification for encrypted wallet storage, signing operations, policy enforcement, and multi-chain account derivation.

This document defines how to read the rest of the `docs/` set:

- `01-storage-format.md`, `02-signing-interface.md`, `03-policy-engine.md`, `06-wallet-lifecycle.md`, `07-supported-chains.md`, and `08-conformance-and-security.md` are the **normative core**.
- `04-agent-access-layer.md` and `05-key-isolation.md` define **optional access and deployment profiles**. They describe acceptable implementation patterns, but they do not require a specific package manager, programming language, or transport.
- `quickstart.md`, `sdk-cli.md`, `sdk-node.md`, `sdk-python.md`, `policy-engine-implementation.md`, and `cardano.md` are **non-normative reference implementation documentation**.

If there is a conflict between a normative core document and a reference implementation document, the normative core document wins.

## Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in the normative core documents are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Examples, CLI commands, package names, public RPC URLs, and installation instructions are informative unless a document explicitly marks them as normative.

## Specification Versioning

OWS evolves in two layers:

- **Specification documents** define interoperable behavior and file formats.
- **Schema versions** embedded inside stored artifacts define compatibility for those artifacts.

Current version markers:

- Wallet file schema: `ows_version = 2`
- Policy schema: `version = 1`

Implementations MUST reject unknown required schema fields and MUST reject schema versions they do not understand. Implementations MAY accept older schema versions if they document the compatibility behavior.

## Conformance Targets

An implementation is conforming only for the parts it fully implements.

The primary conformance targets are:

1. **Storage Conformance**: correctly reads and writes wallet, API key, policy, config, and audit-log artifacts as defined by `01-storage-format.md`.
2. **Signing Conformance**: implements the required request validation, authentication, signing, and error semantics from `02-signing-interface.md`.
3. **Policy Conformance**: evaluates built-in policy rules and policy outcomes as defined by `03-policy-engine.md`.
4. **Lifecycle Conformance**: preserves creation, import, export, backup, recovery, deletion, and rotation semantics from `06-wallet-lifecycle.md`.
5. **Chain Conformance**: uses the identifiers, derivation rules, and address encodings defined by `07-supported-chains.md`.

An implementation MUST NOT claim general "OWS compliant" status if it only implements a subset of those targets. It SHOULD instead declare the profiles it supports, for example: `OWS Storage + Signing + EVM Chain Profile`.

## Optional Features

The following features are optional unless a calling profile requires them:

- `signAndSend`
- `signHash`
- `signAuthorization`
- `signTypedData`
- executable policies
- subprocess or enclave-style isolation
- shorthand aliases in interactive CLI contexts

If an implementation omits an optional feature, it MUST fail clearly and MUST NOT silently degrade into a weaker behavior.

## Extension Rules

OWS permits extension in controlled places:

- New chain families MAY be added when they define a stable CAIP-2 namespace or equivalent canonical identifier, a deterministic derivation path, and an address encoding rule.
- Policy engines MAY add implementation-specific declarative rule types, but they MUST namespace them to avoid collisions and MUST reject unknown unnamespaced rule types.
- Wallet, API key, and policy files MAY include additional metadata fields, but implementations MUST preserve unknown fields they do not own when performing non-destructive updates.

Extensions MUST NOT redefine the meaning of existing required fields.

## Out of Scope

The following are intentionally outside the core specification:

- package names and distribution channels
- public RPC endpoint selection
- hosted wallet services and remote custody
- on-chain service payment flows
- UI, CLI ergonomics, and installer behavior

Those topics may be documented by a reference implementation, but they are not required for interoperability.
