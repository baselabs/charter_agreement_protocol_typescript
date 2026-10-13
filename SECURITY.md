# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.7.x | yes, once 0.7.0 is released, in a new 0.7 patch release |
| 0.6.x and earlier | no; upgrade to 0.7.x once released |

The [changelog](CHANGELOG.md) describes verification changes between releases.
Keep the package version with stored verification results so you can check
them again when upgrading.

## Reporting a vulnerability

Report it privately through the repository's Security tab, then
"Report a vulnerability", for
[`baselabs/charter_agreement_protocol_typescript`](https://github.com/baselabs/charter_agreement_protocol_typescript/security/advisories/new).

Never put an exploit, credential, private key, production data or an
unfixed vulnerability's details in a public issue, pull request or discussion.

A useful report names:

- the package version or commit and the Node version;
- the property that fails, such as a modified artifact verifying or a limit
  not being enforced;
- the smallest reproduction, using test keys and synthetic data;
- the result you expected, usually a typed `{ ok: false, code: "..." }`.

## What happens after you report

| Step | Target |
| --- | --- |
| We confirm we received the report | within 3 business days |
| We tell you whether we can reproduce it and how serious it is | within 10 business days |
| We ship a fix in a patch release | as soon as it is ready, within 90 days of the report |
| We publish an advisory crediting you, unless you ask us not to | when the fix is on npm |

If a fix needs longer than 90 days, we agree on a new date with you before
the 90 days run out. Please keep the details private until the advisory is
published.

## Scope

In scope: everything shipped in the npm package
`@charter-agreement-protocol/verifier`.

- Decoding, canonicalization, digests, signature checks, descriptor, chain,
  acceptance, termination and receipt verification, and the facts they return.
- Signing input helpers, compact assembly, `prepareSigning` and `finishSigning`.
  The caller supplies the context, time, limits, public key and signature.
- The corpus loader and CLI, including filesystem checks. They cap a corpus
  at 64 files and 32 MiB and reject symlinks and other entries that are neither
  regular files nor directories.
- The shipped conformance corpus and package documentation.

Out of scope here:

- What your application does with the facts. CAP verifies and never
  authorizes; the [README](README.md) describes the `not_verified` fields.
- Key custody and signing callbacks. Report companion signer issues to
  [charter_agreement_signer_typescript](https://github.com/baselabs/charter_agreement_signer_typescript).
- The Elixir reference. Report its issues to
  [charter_agreement_protocol](https://github.com/baselabs/charter_agreement_protocol).

The workshop is maintained in this repository but is outside the npm package.
Report a flaw in its signing or verification flow through the same private
reporting form.

## Reproducing a report

Use Node 24.8.0 or later. From a source checkout:

```sh
npm ci
npm test
npm run typecheck
npm run typecheck:web
npm run self-checks
npm run build
npm run build:site
node cli.ts --corpus conformance
node dist/cli.js --corpus conformance
```

For an installed package, run `cap-verifier --corpus DIRECTORY` to check a
corpus directory. Include the command, its output and the synthetic input
that reproduces the problem in your private report.
