# Contributing

Same rules as [cronstable](https://github.com/ptweezy/cronstable)
itself:

- Contributions are MIT-licensed and must be certified under the
  [Developer Certificate of Origin](https://developercertificate.org/):
  sign off every commit (`git commit -s`).
- Keep the wire behavior conformant to
  [`docs/relay-protocol.md`](https://github.com/ptweezy/cronstable/blob/main/docs/relay-protocol.md)
  in the cronstable repo — protocol changes start there, not here.
- `npm run typecheck && npm test` must pass; new policy behavior needs
  tests (the policy engine is pure functions in `src/policy.ts`
  precisely so its edges are cheap to pin).
- Never commit key material. Real `.p8` files are gitignored; the only
  key in the repo is the throwaway one the test suite signs with.
