# asyncua interop check

Every other test in this repository drives the server with this module's own
client, so the two share one reading of the specification. This check uses
[asyncua](https://github.com/FreeOpcUa/opcua-asyncio), an independent Python
implementation, as the client.

## Running it

```bash
tests/interop/asyncua/run.sh
```

Needs Go and Python 3 with `venv`. The script installs `asyncua` into a
temporary virtualenv, builds `server/`, starts four server variants on
`BASE_PORT` (default 48400) and the three ports above it, runs the cases and
exits non-zero if any fail. It takes about two minutes.

## What it covers

The server offers Basic256Sha256 with UserName authentication. The client asks
for a 4-second channel lifetime, so asyncua renews its secure channel every
3 seconds.

| Case | What it checks |
|---|---|
| `basic` | Connect, read a value, browse Objects |
| `wrong_password` | A bad password returns `BadUserAccessDenied` |
| `anonymous` | An anonymous token is refused on the secured endpoint |
| `renewal_idle` | Four renewals with one read after each |
| `renewal` | 25 seconds of reads every 20 ms and a 50 ms subscription, across about eight renewals |
| `none` | Anonymous over None, when that endpoint is enabled |

Server variants: SignAndEncrypt, Sign, a server certificate presented as a
leaf plus CA chain, and a None endpoint beside the secured one.

## What it has found

Two faults that every test using this module's own client had missed, both
since fixed:

- **A channel lost at renewal.** The server installed the new keys as soon as
  it had answered a renewal. A request the client had sent before it saw the
  answer was still secured with the old keys, failed verification, and the
  server closed the connection. The server now keeps the previous token's keys
  for a while after a renewal.
- **`ActivateSession` refused with a chained server certificate.** The server
  verified the client's session signature over the whole certificate blob it
  was configured with. asyncua signs the leaf certificate only, as Part 4,
  5.6.3.2 describes. The server now checks the leaf first.

All 12 cases pass.

## In CI

The `interop` job of `.github/workflows/go.yml` runs `make interop` on every
pull request.

## Limits

asyncua is one client. Nothing here says how UaExpert or the .NET stack
behave. The 4-second channel lifetime is there to force renewals quickly; a
client that asks for an hour renews about every 45 minutes.
