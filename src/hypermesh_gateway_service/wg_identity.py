"""Durable local WireGuard identity; only its public half is registered."""
import base64
import fcntl
import os
from pathlib import Path
import stat
import tempfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def public_key(private):
    try:
        raw = base64.b64decode(private, validate=True)
        key = X25519PrivateKey.from_private_bytes(raw)
        return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    except (TypeError, ValueError):
        raise ValueError("Invalid local WireGuard identity") from None


def identity_path():
    path = Path(os.environ.get("HYPERMESH_WG_PRIVATE_KEY_FILE", "/var/lib/hypermesh-gateway/wireguard.key"))
    if not path.is_absolute():
        raise ValueError("WireGuard identity path must be absolute")
    return path


def read_private_key(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("WireGuard identity file permissions are unsafe")
        try:
            return source.read(257).strip().decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("Invalid local WireGuard identity") from None


def retained_identity():
    """Load an operator-provisioned identity without generating or adopting one."""
    expected = os.environ.get("HYPERMESH_WG_EXPECTED_PUBLIC_KEY")
    if expected is None:
        return None
    try:
        raw = base64.b64decode(expected, validate=True)
    except ValueError:
        raise ValueError("Invalid expected WireGuard public key") from None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != expected:
        raise ValueError("Invalid expected WireGuard public key")
    private = read_private_key(identity_path())
    if private is None:
        raise ValueError("Provision the retained WireGuard identity before starting Gateway")
    public = public_key(private)
    if public != expected:
        raise ValueError("WireGuard identity differs from its configured public key")
    return private, public


def local_identity(rows, *, registration_supported):
    active = [row for row in rows if row.get("status") == "allocated"]
    if registration_supported and any(row.get("server_private_key") for row in rows):
        raise ValueError("Public-only Plane supplied private key material")
    expected = {row.get("server_public_key") for row in active}
    if len(expected) > 1 or None in expected:
        raise ValueError("Conflicting assigned WireGuard identities")
    retained = retained_identity()
    if retained is not None:
        if not registration_supported:
            raise ValueError("Retained WireGuard identity requires public-only Plane registration")
        if expected and expected != {retained[1]}:
            raise ValueError("WireGuard identity differs from assigned peers")
        return retained
    path = identity_path()
    if not registration_supported and not active and not path.exists():
        return None
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(str(path)+".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        private = read_private_key(path)
        if private is None:
            # Upgrade an old Plane without changing its existing peer identity.
            legacy = {row.get("server_private_key") for row in active}
            legacy.discard(None)
            if registration_supported and legacy:
                raise ValueError("Public-only Plane supplied private key material")
            if len(legacy) > 1:
                raise ValueError("Conflicting legacy WireGuard identities")
            if legacy:
                private = next(iter(legacy))
            elif expected:
                raise ValueError("Existing WireGuard identity must be retained before Plane upgrade")
            else:
                key = X25519PrivateKey.generate()
                private = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
            public = public_key(private)
            if expected and expected != {public}:
                raise ValueError("WireGuard identity differs from assigned peers")
            descriptor, temporary = tempfile.mkstemp(prefix=".wireguard-", dir=path.parent)
            try:
                with os.fdopen(descriptor,"w") as output:
                    output.write(private+"\n"); output.flush(); os.fsync(output.fileno())
                os.replace(temporary,path)
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(directory)
                finally: os.close(directory)
            finally:
                if os.path.exists(temporary): os.unlink(temporary)
        public = public_key(private)
        if expected and expected != {public}:
            raise ValueError("WireGuard identity differs from assigned peers")
        return private, public
    finally:
        os.close(lock)
