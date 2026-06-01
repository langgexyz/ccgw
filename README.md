# ccgw

Shared gateway protocol library for the distributed AI-gateway edge system:
the wire contract, crypto primitives, and registry used by both the **cchub**
control-plane (embedded in [sub2api](https://github.com/langgexyz/sub2api)) and
the **ccdirect** edge client.

Pure-stdlib, no business logic, no secrets — safe to be public and imported by
both the (public) platform and the (private) edge client.

## Packages
- `contract` — wire types (lease/settle/enroll/register/heartbeat) + Ed25519
  sealed-token / liveness / release-manifest crypto.
- `edgereg` — in-memory edge registry.
- `edgetls` — edge mTLS helpers.
- `enroll` — single-token enrollment wire types + session.
- `quota` — quota ledger interface.
