# AGENTS.md

Authoritative project instructions:

<INSTRUCTIONS>
# Global Docker Policy (Strict)

- Use ONLY first-party, officially maintained images.
- If a first-party Alpine variant exists, it MUST be used.
- If not, absence MUST be verified via Docker Hub before selecting a fallback.
- Tags MUST be resolved via Docker Hub metadata.
- ALL uncertainty (image, variant, tag) MUST be resolved via Docker Hub; no assumptions allowed.
- No guessing. No floating `latest` unless explicitly requested.
- Must Use Postgress over MariaDB or MySQL, unless otherwise directed
- Must check if there are images already pulled that are close matches to eliminate having dupes

## Build Rules
- If a suitable first-party image exists, Dockerfiles are FORBIDDEN.
- Multi-stage builds ONLY when compilation/artifact creation is unavoidable AND no first-party runtime image suffices.

## Compose
- ANY containerized solution MUST include a Docker Compose file using fully resolved first-party images.
- When picking a port to expose to localhost, You must choose non-traditional ports to minimize risk of colliding with other projects.
- NEVER pick a traditional port.

## Security
- Use non-root user when supported.
- Remove unnecessary Linux capabilities.
- Final images MUST contain only strict runtime dependencies; no shells, build tools, or extras.

## TypeScript (Strict)

- Code MUST use Yarn.
- Each file MUST contain at most one default export.
- ES module `import` syntax MUST be used; `require` is FORBIDDEN.
- TypeScript MUST run in strict mode.
- `type` MUST be preferred over `interface` unless extension behavior is specifically needed.
- The `as` operator is PROHIBITED except for unavoidable external typing gaps.
- Types MUST be reused; redeclaration is FORBIDDEN. Use indexed access types (e.g., Foo["name"]) for consistency.
- `any` is FORBIDDEN.
- Native Array methods MUST be used wherever they express the operation clearly; avoid loops or lodash when native methods suffice.
- Libraries such as `lodash`, `luxon`, and `turf` are the PREFERRED starting toolkit; additional libraries MAY and SHOULD be used when justified.
- Functions MUST maintain reasonable complexity; unnecessary abstraction is PROHIBITED.
- Clever or non-obvious code is FORBIDDEN; clarity is REQUIRED.
- Prefer early returns.
- Prefer `async` / `await`.
- Enums MAY be used when semantically appropriate.
- For React: `useCallback` and `useMemo` MUST be used when recommended by React performance guidance.
- Defaulting MUST use `??` rather than `||`.


## Clean Code Enforcement (Language-Agnostic, Strict)

- Single-letter identifiers are FORBIDDEN. All names MUST be descriptive and domain-relevant.
- Code MUST be structured into clear architectural roles (e.g., Model, View, Controller/Service, or equivalent). Files MUST reflect their role; mixing roles in one file is PROHIBITED.
- Each file MUST contain exactly one responsibility. Cross-cutting or shared logic MUST be isolated in dedicated modules.
- Code MUST be human-readable: explicit steps, descriptive names, and no cleverness or compression that reduces clarity.
- Function and module complexity MUST remain low: shallow control flow, minimal branching, no deep nesting. When complexity increases, logic MUST be split.
- Parameter lists MUST remain small; parameter objects or structured inputs MUST be used for multiple related inputs.
- Pure logic and side effects MUST be separated. Side effects MUST live at the boundaries; core logic MUST remain deterministic.
- State MUST have a single authoritative source; duplication or desynchronized state is PROHIBITED.
- Error handling MUST follow one consistent approach across the codebase; guessing, silent fallback, or hidden error behavior is FORBIDDEN.
- Recovery paths MUST be deterministic and MUST return to explicitly defined known states, never inferred ones.
- Any code, abstraction, or indirection that does not improve clarity, correctness, or maintainability MUST be removed.
- Must use Google to verify recent docs & confirm latest version of APIs, Libraries, never making guesses.
</INSTRUCTIONS>
