# rules/engine/opensslconf.py
"""The OpenSSL config that switches the legacy provider on, kept where only this account can write.

NTLM needs MD4, which OpenSSL 3 only offers through its legacy provider, and pywinrm and impacket
reach it through OPENSSL_CONF. That file used to be a fixed name in the shared temp directory,
created with the process umask and trusted when it already existed, so any local user who planted
it chose which providers the harness loaded, including inside the namespace snippets that run as
root (external review of the public export, 2026-10-24).

Now it is a directory named for the uid (mode 0700) under $XDG_RUNTIME_DIR, else the temp directory,
holding one file (mode 0600). Both are inspected with lstat on every call, and a symlink, an owner
other than the caller, or a group or other write bit raises OpenSSLConfError naming the path: a
file that is wrong is refused, never repaired and never trusted.
"""
import os
import stat
import tempfile

DIR_NAME = f"zybur-proofloop-{os.getuid()}"
FILE_NAME = "openssl_legacy.cnf"

CONF = ("openssl_conf = openssl_init\n"
        "[openssl_init]\nproviders = provider_sect\n"
        "[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n"
        "[default_sect]\nactivate = 1\n"
        "[legacy_sect]\nactivate = 1\n")


class OpenSSLConfError(RuntimeError):
    """The config file or its directory is not what this account created."""


def _inspect(path, kind):
    """lstat `path` (never following a link) and refuse anything this account did not make private."""
    try:
        st = os.lstat(path)
    except OSError as e:
        raise OpenSSLConfError(f"{path}: cannot inspect the OpenSSL config {kind}: {e.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise OpenSSLConfError(f"{path}: the OpenSSL config {kind} is a symlink")
    if kind == "directory" and not stat.S_ISDIR(st.st_mode):
        raise OpenSSLConfError(f"{path}: the OpenSSL config directory is not a directory")
    if kind == "file" and not stat.S_ISREG(st.st_mode):
        raise OpenSSLConfError(f"{path}: the OpenSSL config file is not a regular file")
    if st.st_uid != os.getuid():
        raise OpenSSLConfError(f"{path}: the OpenSSL config {kind} is owned by uid {st.st_uid}, "
                               f"not by uid {os.getuid()}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OpenSSLConfError(f"{path}: the OpenSSL config {kind} is writable by group or other "
                               f"(mode {stat.S_IMODE(st.st_mode):04o})")
    return st


def ensure_openssl_conf(base_dir=None):
    """Return the path of the legacy-provider config, creating it private if it is absent.

    Idempotent: a second call returns the same path and writes nothing. The file appears whole
    or not at all (written beside it, then renamed into place), so a concurrent caller never reads
    half of it.
    """
    base = base_dir or os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    directory = os.path.join(base, DIR_NAME)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    except OSError as e:
        raise OpenSSLConfError(f"{directory}: cannot create the OpenSSL config directory: {e.strerror}") from None
    st = _inspect(directory, "directory")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(directory, 0o700)      # ours and not a link (inspected above): tighten, never loosen
    path = os.path.join(directory, FILE_NAME)
    if not os.path.lexists(path):
        fd, staged = tempfile.mkstemp(prefix=FILE_NAME + ".", dir=directory)   # created 0600
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(CONF)
            # The directory is private to this account, so a concurrent caller can only be this
            # same code writing these same bytes: whichever replace lands last is identical.
            os.replace(staged, path)
        except BaseException:
            try:
                os.unlink(staged)
            except FileNotFoundError:
                pass
            raise
    _inspect(path, "file")
    return path
