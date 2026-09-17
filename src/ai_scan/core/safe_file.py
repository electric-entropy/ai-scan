"""Descriptor-safe bounded regular-file reads for untrusted local inputs."""

from __future__ import annotations

import os
import stat


class SafeFileError(ValueError):
    """Fixed-code failure from the descriptor-safe regular-file loader."""


def read_stable_regular_file(path: str, *, max_bytes: int) -> bytes:
    """Read stable bytes twice while binding the pathname to one descriptor."""
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
        raise SafeFileError("safe_open_unavailable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except (TypeError, ValueError):
        raise SafeFileError("invalid_path") from None
    except OSError:
        raise SafeFileError("not_regular") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SafeFileError("not_regular")
        if before.st_size > max_bytes:
            raise SafeFileError("too_large")
        before = _observe_path_and_descriptor(fd, path)
        identity = _identity(before)
        first = _read_bounded(fd, max_bytes)
        after = _observe_path_and_descriptor(fd, path)
        if _identity(after) != identity or len(first) != before.st_size:
            raise SafeFileError("changed")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            raise SafeFileError("changed") from None
        before_second = _observe_path_and_descriptor(fd, path)
        if _identity(before_second) != identity:
            raise SafeFileError("changed")
        second = _read_bounded(fd, max_bytes)
        repeated_after = _observe_path_and_descriptor(fd, path)
        if (
            _identity(repeated_after) != identity
            or second != first
            or len(second) != before.st_size
        ):
            raise SafeFileError("changed")
        return first
    except OSError:
        raise SafeFileError("changed") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            raise SafeFileError("changed") from None


def _read_bounded(fd: int, max_bytes: int) -> bytes:
    chunks = bytearray()
    try:
        while True:
            chunk = os.read(fd, min(8192, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > max_bytes:
                raise SafeFileError("too_large")
    except OSError:
        raise SafeFileError("changed") from None
    return bytes(chunks)


def _observe_path_and_descriptor(fd: int, path: str) -> os.stat_result:
    """Return matching no-follow pathname and descriptor metadata or fail closed."""
    descriptor_info = os.fstat(fd)
    try:
        path_info = os.stat(path, follow_symlinks=False)
    except (TypeError, ValueError):
        raise SafeFileError("invalid_path") from None
    except OSError:
        raise SafeFileError("changed") from None
    if not stat.S_ISREG(path_info.st_mode) or _identity(path_info) != _identity(descriptor_info):
        raise SafeFileError("changed")
    return descriptor_info


def _identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int | None, int | None]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", None),
        getattr(info, "st_ctime_ns", None),
    )


__all__ = ["SafeFileError", "read_stable_regular_file"]
