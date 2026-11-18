# asyncua interop check

Every other test in this repository drives the server with this module's own
client, so the two share one reading of the specification. This check uses
[asyncua](https://github.com/FreeOpcUa/opcua-asyncio), an independent Python
implementation, as the client.

It was written while reviewing
[flexgen-power/opcua#4](https://github.com/flexgen-power/opcua/pull/4) and sits
on top of that PR's head (9e86c4b).

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

## Results on 9e86c4b

7 of 12 cases pass. The failures:

- **`renewal`, both modes.** The channel dies at the first renewal, every run.
  The server installs the new keys as soon as it has answered the renewal and
  reuses the token ID. A request the client sent before it saw the answer is
  still secured with the old keys, fails verification, and the server closes
  the connection with `BadSecurityChecksFailed`.
- **`renewal_idle`.** Same cause, intermittent: it failed in 4 of 7 runs.
- **Chain certificate, both cases.** The server verifies the client's session
  signature over the whole certificate blob it was configured with. asyncua
  signs the leaf certificate only, as Part 4, 5.6.3.2 describes, so
  `ActivateSession` is refused.

## Patches

`patches/` holds one fix for each failure. They apply to 9e86c4b:

```bash
git apply tests/interop/asyncua/patches/*.patch
```

- `0001-renewal-keep-previous-token.patch` issues a new token ID on renewal
  and keeps the previous token's keys for verifying chunks that still carry
  its ID, until a quarter of the old lifetime has passed.
- `0002-session-signature-over-leaf-certificate.patch` verifies the session
  signature over the leaf certificate and falls back to the whole blob, which
  is what this module's own client signs.

With both applied, all 12 cases pass, and `go test -race ./server/ ./uasc/`
passes.

## Limits

asyncua is one client. Nothing here says how UaExpert or the .NET stack
behave. The 4-second lifetime is there to force renewals quickly; with a
one-hour lifetime the same collision happens at the 45-minute renewal, and how
often depends on how busy the client is at that moment.
