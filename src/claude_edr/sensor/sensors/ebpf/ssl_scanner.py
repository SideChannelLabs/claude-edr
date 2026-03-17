"""SSL_write / SSL_read discovery for eBPF uprobe attachment.

Two-tier approach:
  Tier 1: Find libssl.so in /proc/PID/maps → attach by symbol name (reliable)
  Tier 2: Scan stripped binary for BoringSSL function signatures (fallback)

Tier 1 covers Node.js, Python, curl, and anything using system OpenSSL.
Tier 2 covers Claude's native binary and Bun which embed BoringSSL.
"""

from __future__ import annotations

import logging
import os
import re
import struct
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Tier 1: Dynamic libssl.so discovery ─────────────────────────────────────

# Regex to parse /proc/PID/maps lines
# Format: addr-addr perms offset dev inode pathname
_MAPS_RE = re.compile(
    r"^[0-9a-f]+-[0-9a-f]+\s+r.x.\s+\S+\s+\S+\s+\d+\s+(.+)$",
    re.MULTILINE,
)


def find_libssl_for_pid(pid: int) -> str | None:
    """Find the path to libssl.so loaded by a process.

    Reads /proc/PID/maps looking for libssl.so.* or libcrypto.so.* in
    executable memory regions. Returns the path or None.
    """
    try:
        maps = Path(f"/proc/{pid}/maps").read_text()
    except (OSError, FileNotFoundError):
        return None

    for match in _MAPS_RE.finditer(maps):
        path = match.group(1).strip()
        basename = os.path.basename(path)
        # Match libssl.so.3, libssl.so.1.1, etc.
        if basename.startswith("libssl.so"):
            if os.path.exists(path):
                logger.info("PID %d uses %s", pid, path)
                return path

    return None


def find_system_libssl() -> str | None:
    """Find libssl.so on the system without a specific PID.

    Checks common paths for the system OpenSSL library.
    """
    common_paths = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
    ]
    for path in common_paths:
        if os.path.exists(path):
            logger.info("Found system libssl: %s", path)
            return path

    # Try ldconfig
    try:
        import subprocess
        result = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "libssl.so" in line and "x86-64" in line:
                path = line.split("=>")[-1].strip()
                if os.path.exists(path):
                    logger.info("Found libssl via ldconfig: %s", path)
                    return path
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def has_symbol(library_path: str, symbol: str) -> bool:
    """Check if a shared library exports a given symbol.

    Reads the ELF dynamic symbol table (.dynsym) to verify
    the symbol exists before attempting uprobe attachment.
    """
    try:
        data = Path(library_path).read_bytes()
        # Quick check: symbol name must appear as a string in the binary
        if symbol.encode() not in data:
            return False
        return True
    except OSError:
        return False


# ── Tier 2: Signature scanning for embedded BoringSSL ───────────────────────

# Known SSL_write function prologues (first N bytes of the function).
# Each entry: (label, ssl_write_sig, ssl_read_sig_or_None)
SSL_SIGNATURES: list[tuple[str, bytes, bytes | None]] = [
    (
        # BoringSSL via Bun/Chromium (clang, x86_64, -O2)
        "boringssl_clang_x64_v1",
        bytes.fromhex(
            "554889e5"          # push rbp; mov rbp, rsp
            "4157"              # push r15
            "4156"              # push r14
            "4155"              # push r13
            "4154"              # push r12
            "53"                # push rbx
            "4883ec18"          # sub rsp, 0x18
            "4189d7"            # mov r15d, edx  (num/length param)
            "4989f6"            # mov r14, rsi   (buf pointer)
            "4889fb"            # mov rbx, rdi   (SSL* context)
            "488b4730"          # mov rax, [rdi+0x30]
            "c780"              # mov dword [rax+...], ...
        ),
        None,
    ),
]

# Shorter signatures for broader matching (with validation)
SSL_SIGNATURES_BROAD: list[tuple[str, bytes]] = [
    (
        # Generic BoringSSL SSL_write: push rbp + callee-saved regs + sub rsp
        "boringssl_generic_x64",
        bytes.fromhex(
            "554889e5"          # push rbp; mov rbp, rsp
            "4157"              # push r15
            "4156"              # push r14
            "4155"              # push r13
            "4154"              # push r12
            "53"                # push rbx
            "4883ec"            # sub rsp, imm8
        ),
    ),
]


def _get_elf_load_offset(data: bytes) -> int:
    """Get the virtual address offset for the first executable PT_LOAD segment."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    if data[4] != 2:
        raise ValueError("Only 64-bit ELF supported")

    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]

    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, offset)[0]
        p_flags = struct.unpack_from('<I', data, offset + 4)[0]

        if p_type == 1 and (p_flags & 0x1):  # PT_LOAD + PF_X
            p_offset = struct.unpack_from('<Q', data, offset + 8)[0]
            p_vaddr = struct.unpack_from('<Q', data, offset + 16)[0]
            return p_vaddr - p_offset

    return 0


def file_offset_to_vaddr(data: bytes, file_offset: int) -> int:
    """Convert a file offset to a virtual address using ELF headers."""
    return file_offset + _get_elf_load_offset(data)


def scan_for_ssl_write(binary_path: str | Path) -> int | None:
    """Scan a stripped binary for SSL_write by byte signature.

    Returns the virtual address suitable for uprobe attachment, or None.
    """
    binary_path = Path(binary_path)
    if not binary_path.exists():
        return None

    logger.info("Scanning %s for SSL_write signature...", binary_path)
    data = binary_path.read_bytes()

    if data[:4] != b'\x7fELF':
        return None

    # Try precise signatures first
    for label, sig, _ in SSL_SIGNATURES:
        idx = data.find(sig)
        if idx >= 0:
            vaddr = file_offset_to_vaddr(data, idx)
            logger.info(
                "Found SSL_write via '%s' at file offset 0x%x (vaddr 0x%x)",
                label, idx, vaddr,
            )
            return vaddr

    # Try broad signatures with validation
    for label, sig in SSL_SIGNATURES_BROAD:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            snippet = data[idx:idx + 64]
            # Validate: SSL_write accesses SSL->s3 via [rdi+0x30]
            if b'\x48\x8b\x47\x30' in snippet:
                vaddr = file_offset_to_vaddr(data, idx)
                logger.info(
                    "Found SSL_write via broad '%s' at offset 0x%x (vaddr 0x%x)",
                    label, idx, vaddr,
                )
                return vaddr
            start = idx + 1

    logger.warning("SSL_write not found in %s", binary_path)
    return None


def scan_for_ssl_read(binary_path: str | Path, ssl_write_vaddr: int | None = None) -> int | None:
    """Scan a stripped binary for SSL_read near SSL_write."""
    binary_path = Path(binary_path)
    data = binary_path.read_bytes()
    if data[:4] != b'\x7fELF':
        return None

    if ssl_write_vaddr is not None:
        load_offset = _get_elf_load_offset(data)
        write_file_off = ssl_write_vaddr - load_offset

        # SSL_read is typically within 64KB after SSL_write in BoringSSL
        search_start = write_file_off + 0x100
        search_end = min(write_file_off + 0x10000, len(data))

        for label, sig, _ in SSL_SIGNATURES:
            idx = data.find(sig[:16], search_start, search_end)
            if idx >= 0 and idx != write_file_off:
                vaddr = file_offset_to_vaddr(data, idx)
                logger.info("Found SSL_read near SSL_write at vaddr 0x%x", vaddr)
                return vaddr

        # Broad search near SSL_write
        for label, sig in SSL_SIGNATURES_BROAD:
            idx = data.find(sig, search_start, search_end)
            if idx >= 0 and idx != write_file_off:
                vaddr = file_offset_to_vaddr(data, idx)
                logger.info("Found SSL_read via broad '%s' at vaddr 0x%x", label, vaddr)
                return vaddr

    logger.warning("SSL_read not found in %s", binary_path)
    return None


# ── Public API ──────────────────────────────────────────────────────────────

def scan_binary(binary_path: str | Path) -> dict[str, int | None]:
    """Scan a stripped binary for SSL_write and SSL_read offsets.

    Returns dict with 'ssl_write' and 'ssl_read' virtual addresses (or None).
    Used for binaries with statically-linked/embedded BoringSSL.
    """
    ssl_write = scan_for_ssl_write(binary_path)
    ssl_read = scan_for_ssl_read(binary_path, ssl_write) if ssl_write else None

    return {
        "ssl_write": ssl_write,
        "ssl_read": ssl_read,
        "binary": str(binary_path),
    }


def discover_ssl_for_pid(pid: int) -> dict:
    """Full SSL discovery for a process: try libssl.so first, then signature scan.

    Returns dict with:
      - method: "libssl" | "signature" | "none"
      - library: path to libssl.so (if method=libssl)
      - binary: path to main binary (if method=signature)
      - ssl_write: symbol name or vaddr
      - ssl_read: symbol name or vaddr
    """
    result = {
        "method": "none",
        "library": None,
        "binary": None,
        "ssl_write": None,
        "ssl_read": None,
        "pid": pid,
    }

    # Tier 1: Check for dynamically-linked libssl.so
    libssl = find_libssl_for_pid(pid)
    if libssl and has_symbol(libssl, "SSL_write"):
        result["method"] = "libssl"
        result["library"] = libssl
        result["ssl_write"] = "SSL_write"   # symbol name, not address
        result["ssl_read"] = "SSL_read"
        logger.info(
            "PID %d: SSL via libssl (%s) - will attach by symbol name",
            pid, libssl,
        )
        return result

    # Tier 2: Scan main binary for embedded BoringSSL signatures
    try:
        binary_path = os.readlink(f"/proc/{pid}/exe")
    except (OSError, FileNotFoundError):
        return result

    scan = scan_binary(binary_path)
    if scan["ssl_write"]:
        result["method"] = "signature"
        result["binary"] = binary_path
        result["ssl_write"] = scan["ssl_write"]  # virtual address
        result["ssl_read"] = scan["ssl_read"]
        logger.info(
            "PID %d: SSL via signature scan (%s) - write=0x%x read=%s",
            pid, binary_path, scan["ssl_write"],
            f"0x{scan['ssl_read']:x}" if scan["ssl_read"] else "None",
        )
        return result

    logger.info("PID %d: no SSL symbols found (Go/Rust/no-TLS process)", pid)
    return result
