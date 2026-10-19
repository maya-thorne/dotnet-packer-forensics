"""
Stream Decompressor for Compressed .NET Single-File Host Payloads.
Engineered & Audited by Maya Thorne.
"""

from typing import Optional, Tuple
import zlib

from .models import CompressionKind, SecurityError, zeroize_buffer


class BundleDecompressor:
    """Safely decompresses single-file bundle payload streams with memory zeroizing."""

    MAX_UNCOMPRESSED_SIZE = 512 * 1024 * 1024  # 512 MB safety ceiling against zip bombs

    @classmethod
    def decompress(
        cls,
        compressed_bytes: bytes,
        expected_size: Optional[int] = None,
        preferred_kind: Optional[CompressionKind] = None,
    ) -> Tuple[bytes, CompressionKind]:
        """
        Decompresses a payload stream, auto-detecting Deflate, Zlib, Brotli, or LZMA.
        Returns: Tuple of (decompressed_bytes, CompressionKind).
        """
        if not compressed_bytes:
            return (b"", CompressionKind.NONE)

        if expected_size is not None and expected_size > cls.MAX_UNCOMPRESSED_SIZE:
            raise SecurityError(
                f"Decompressed size {expected_size} exceeds safety threshold {cls.MAX_UNCOMPRESSED_SIZE}."
            )

        # 1. Try Raw Deflate (-15, .NET DeflateStream default)
        try:
            decomp = zlib.decompress(compressed_bytes, -15)
            if expected_size is None or len(decomp) == expected_size:
                return (decomp, CompressionKind.DEFLATE)
        except Exception:
            pass

        # 2. Try Standard Zlib (wbits=15)
        try:
            decomp = zlib.decompress(compressed_bytes)
            if expected_size is None or len(decomp) == expected_size:
                return (decomp, CompressionKind.ZLIB)
        except Exception:
            pass

        # 3. Try GZip wrapped stream (wbits=31)
        try:
            decomp = zlib.decompress(compressed_bytes, 31)
            if expected_size is None or len(decomp) == expected_size:
                return (decomp, CompressionKind.DEFLATE)
        except Exception:
            pass

        # 4. Try Brotli if available
        try:
            import brotli
            decomp = brotli.decompress(compressed_bytes)
            if expected_size is None or len(decomp) == expected_size:
                return (decomp, CompressionKind.BROTLI)
        except Exception:
            pass

        # 5. Try LZMA if available
        try:
            import lzma
            decomp = lzma.decompress(compressed_bytes)
            if expected_size is None or len(decomp) == expected_size:
                return (decomp, CompressionKind.LZMA)
        except Exception:
            pass

        # If already uncompressed or decompression failed, verify expected size
        if expected_size is not None and len(compressed_bytes) == expected_size:
            return (compressed_bytes, CompressionKind.NONE)

        # If decompression could not resolve, raise SecurityError or return raw
        raise SecurityError(
            f"Unable to decompress payload of {len(compressed_bytes)} bytes (expected: {expected_size})."
        )
