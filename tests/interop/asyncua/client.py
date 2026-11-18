"""asyncua client side of the interop check. See README.md.

Usage: client.py <endpoint-url> <namespace-index> <SignAndEncrypt|Sign> <case>...

Each case prints one line: RESULT <name>: PASS|FAIL <detail>.
The process exits non-zero if any case failed.
"""
import asyncio
import logging
import socket
import sys
import tempfile
import time
from pathlib import Path
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua import Client, ua
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

# The client key pair is generated per run and never written next to the script.
WORK = Path(tempfile.mkdtemp(prefix="asyncua-interop-"))
FAILED = []
APP_URI = "urn:interop:asyncua-client"
USER, PW = "scada", "correct horse battery staple"


async def certs():
    key, cert = WORK / "client_key.pem", WORK / "client_cert.der"
    await setup_self_signed_certificate(key, cert, APP_URI, socket.gethostname(),
                                        [ExtendedKeyUsageOID.CLIENT_AUTH], {"commonName": "interop-client"})
    return key, cert


async def secure_client(url, user=USER, pw=PW, mode=ua.MessageSecurityMode.SignAndEncrypt, lifetime_ms=None):
    key, cert = await certs()
    c = Client(url, timeout=5)
    c.application_uri = APP_URI
    if user is not None:
        c.set_user(user)
        c.set_password(pw)
    if lifetime_ms:
        c.secure_channel_timeout = lifetime_ms
    await c.set_security(SecurityPolicyBasic256Sha256, certificate=str(cert), private_key=str(key), mode=mode)
    return c


def result(name, ok, detail=""):
    if not ok:
        FAILED.append(name)
    print(f"RESULT {name}: {'PASS' if ok else 'FAIL'} {detail}", flush=True)


async def t_basic(url, ns, mode):
    c = await secure_client(url, mode=mode)
    async with c:
        v = await c.get_node(f"ns={ns};s=soc").read_value()
        kids = await c.nodes.objects.get_children()
        result("basic_read_browse", isinstance(v, float) and len(kids) > 0, f"value={v} children={len(kids)}")


async def t_wrong_password(url, ns, mode):
    c = await secure_client(url, pw="nope", mode=mode)
    try:
        async with c:
            result("wrong_password", False, "connected")
    except ua.UaStatusCodeError as e:
        result("wrong_password", e.code == ua.StatusCodes.BadUserAccessDenied, f"{type(e).__name__} {e}")
    except Exception as e:
        result("wrong_password", False, f"{type(e).__name__} {e}")


async def t_anonymous_on_secure(url, ns, mode):
    c = await secure_client(url, user=None, mode=mode)
    try:
        async with c:
            result("anonymous_refused", False, "connected")
    except ua.UaStatusCodeError as e:
        result("anonymous_refused", True, f"{type(e).__name__} {e}")
    except Exception as e:
        result("anonymous_refused", False, f"{type(e).__name__} {e}")


class Handler:
    def __init__(self):
        self.count, self.last, self.status = 0, 0.0, []

    def datachange_notification(self, node, val, data):
        self.count += 1
        self.last = time.monotonic()

    def status_change_notification(self, status):
        self.status.append(status)


async def t_renewal(url, ns, mode, lifetime_ms=4000, seconds=25):
    c = await secure_client(url, mode=mode, lifetime_ms=lifetime_ms)
    h = Handler()
    start = time.monotonic()
    reads = errors = 0
    err = ""
    try:
        async with c:
            node = c.get_node(f"ns={ns};s=soc")
            sub = await c.create_subscription(50, h)
            await sub.subscribe_data_change(node)
            while time.monotonic() - start < seconds:
                try:
                    await node.read_value()
                    reads += 1
                except Exception as e:  # noqa
                    errors += 1
                    err = err or f"{type(e).__name__} {e} at t={time.monotonic()-start:.1f}s"
                    if errors > 3:
                        break
                await asyncio.sleep(0.02)
            stale = time.monotonic() - h.last if h.last else -1
            ok = errors == 0 and h.count > 50 and 0 <= stale < 2
            result("renewal_under_load", ok,
                   f"lifetime={lifetime_ms}ms ran={time.monotonic()-start:.1f}s reads={reads} read_errors={errors} "
                   f"notifications={h.count} last_notification_age={stale:.1f}s first_error='{err}'")
    except Exception as e:
        stale = time.monotonic() - h.last if h.last else -1
        result("renewal_under_load", False,
               f"lifetime={lifetime_ms}ms died at t={time.monotonic()-start:.1f}s reads={reads} notifications={h.count} "
               f"last_notification_age={stale:.1f}s first_error='{err}' exc={type(e).__name__} {e}")


async def t_renewal_idle(url, ns, mode, lifetime_ms=4000):
    """No requests in flight while the channel renews; read after each renewal."""
    c = await secure_client(url, mode=mode, lifetime_ms=lifetime_ms)
    done = 0
    try:
        async with c:
            node = c.get_node(f"ns={ns};s=soc")
            for i in range(4):
                await asyncio.sleep(lifetime_ms * 0.75 / 1000 + 0.4)  # just after a renewal
                await node.read_value()
                done += 1
            result("renewal_idle", True, f"lifetime={lifetime_ms}ms reads_after_renewals={done}")
    except Exception as e:
        result("renewal_idle", False, f"lifetime={lifetime_ms}ms reads_after_renewals={done} exc={type(e).__name__} {e}")


async def t_none_anonymous(url, ns, mode):
    c = Client(url, timeout=5)
    try:
        async with c:
            v = await c.get_node(f"ns={ns};s=soc").read_value()
            result("none_anonymous", isinstance(v, float), f"value={v}")
    except Exception as e:
        result("none_anonymous", False, f"{type(e).__name__} {e}")


TESTS = {"basic": t_basic, "wrong_password": t_wrong_password, "anonymous": t_anonymous_on_secure,
         "renewal": t_renewal, "renewal_idle": t_renewal_idle, "none": t_none_anonymous}

if __name__ == "__main__":
    url, ns, mode, names = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    logging.basicConfig(level=logging.WARNING)
    m = ua.MessageSecurityMode.Sign if mode == "Sign" else ua.MessageSecurityMode.SignAndEncrypt
    for n in names:
        try:
            asyncio.run(TESTS[n](url, ns, m))
        except Exception as e:
            result(n, False, f"unhandled {type(e).__name__} {e}")
    sys.exit(1 if FAILED else 0)
