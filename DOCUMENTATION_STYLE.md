# Documentation Style Guide

SkeletonKey source files should read like audited technical notes, not just executable code. Follow the established YARD-style annotation pattern already used in older files such as `lib/skeleton_key/keyring.rb`, `lib/skeleton_key/bitcoin/account.rb`, and `lib/skeleton_key/utils/hashing.rb`.

## Goals

- Explain the role and safety boundary of each file before the implementation begins.
- Make every public entry point understandable without reading its callers.
- Document non-obvious algorithm steps where correctness depends on protocol details.
- Prefer short, precise explanations over repetitive commentary.

## Required Structure

Every production Ruby file under `lib/` should include:

1. A file-level module or class docblock that states:
   - the component’s responsibility
   - the architectural boundary it belongs to
   - any protocol or standard it implements
2. Public class and module methods documented with:
   - purpose in plain language
   - `@param`
   - `@return`
   - `@raise` when invalid input or unsupported behavior matters
3. `@example` blocks on public entry points when the return shape is not obvious.
4. Inline comments only where the algorithm would otherwise require reconstructing a spec from the code.

## Style Rules

- Use YARD-style comments (`#`, `@param`, `@return`, `@raise`, `@example`).
- Explain why a step exists, not what a single line of Ruby already says.
- Document protocol-sensitive constants when their meaning is not self-evident.
- Keep comments deterministic and specific to this repository.
- Do not add filler comments, narrative prose, or duplicate the method name.

## Boundary Guidance

- Shared-layer files must state that they stop at key material, parsing, recovery, or generic serialization.
- Chain-layer files must document the exact chain-facing conventions they own.
- Recovery-layer files must distinguish mnemonic/share recovery from downstream derivation.
- Codec files must describe exact encoding rules, accepted inputs, and failure conditions.

## Review Standard

Documentation is incomplete if a reviewer still needs to reverse-engineer:

- path semantics
- hardened versus non-hardened behavior
- checksum or digest validation
- which layer owns an encoding or address rule
- why an error is raised
