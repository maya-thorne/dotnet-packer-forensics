"""
Multi-Threaded PE Directory Scanner with Fast PE Pre-Filter & Thread-Safe Progress.
Engineered & Audited by Maya Thorne.
"""

import concurrent.futures
import fnmatch
import hashlib
import os
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..core import DotNetPackerCore
from .models import (
    BatchScanOptions,
    BatchScanReport,
    BatchScanSummary,
    FileScanStatus,
    SingleScanResult,
    ThreatLevel,
    safe_path,
    zeroize_buffer,
)


class BatchDirectoryScanner:
    """Multi-threaded high-throughput directory scanner for .NET and PE binaries."""

    @staticmethod
    def _safe_getsize(file_path: str) -> int:
        """Safely gets file size in bytes without raising exceptions on permission locks."""
        try:
            return os.path.getsize(file_path) if os.path.exists(file_path) else 0
        except OSError:
            return 0

    @staticmethod
    def is_pe_buffer(data: bytes) -> bool:
        """Fast pre-filter checking MZ and PE\\0\\0 headers within raw binary buffer."""
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew < 0x40 or e_lfanew + 4 > len(data):
                return False
            return data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
        except Exception:
            return False

    @classmethod
    def is_pe_file(cls, file_path: str) -> bool:
        """Reads initial chunk of file to perform fast PE header pre-filtering."""
        if not os.path.isfile(file_path):
            return False
        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)
                if len(header) < 0x40 or header[:2] != b"MZ":
                    return False
                e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
                if e_lfanew < 0x40:
                    return False
                if e_lfanew + 4 <= len(header):
                    return header[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
                f.seek(e_lfanew)
                return f.read(4) == b"PE\x00\x00"
        except Exception:
            return False

    @staticmethod
    def matches_pattern(file_name: str, pattern: str) -> bool:
        """Checks if filename matches single or comma/semicolon-separated glob patterns."""
        if not pattern or pattern == "*":
            return True
        patterns = [p.strip() for p in pattern.replace(";", ",").split(",") if p.strip()]
        if not patterns or "*" in patterns:
            return True
        lower_name = file_name.lower()
        return any(fnmatch.fnmatch(lower_name, p.lower()) for p in patterns)

    @classmethod
    def discover_files(cls, options: BatchScanOptions) -> List[str]:
        """Discovers files within target directory honoring recursion, patterns, and size limits."""
        if not os.path.exists(options.target_dir):
            raise FileNotFoundError(f"Target directory not found: {options.target_dir}")
        if not os.path.isdir(options.target_dir):
            raise NotADirectoryError(f"Target path is not a directory: {options.target_dir}")

        discovered: List[str] = []
        if options.recursive:
            for root, _, files in os.walk(options.target_dir):
                for f in files:
                    if cls.matches_pattern(f, options.pattern):
                        full_path = os.path.join(root, f)
                        try:
                            sz = os.path.getsize(full_path)
                            if options.min_size_bytes <= sz <= options.max_size_bytes:
                                discovered.append(full_path)
                        except OSError:
                            continue
        else:
            with os.scandir(options.target_dir) as entries:
                for entry in entries:
                    try:
                        if not entry.is_file():
                            continue
                        if not cls.matches_pattern(entry.name, options.pattern):
                            continue
                        sz = entry.stat().st_size
                        if options.min_size_bytes <= sz <= options.max_size_bytes:
                            discovered.append(entry.path)
                    except OSError:
                        continue

        discovered.sort()
        return discovered

    @staticmethod
    def classify_threat_level(
        protectors: List[str],
        anomalies: List[str],
        overlay_size: int,
        is_dotnet: bool,
    ) -> ThreatLevel:
        """Evaluates detected protectors, structural anomalies, and overlay to assess threat severity."""
        critical_protectors = {"antitamper", "antidump", "native stub"}
        high_protector_keys = {
            "armdot", "eazfuscator", "intellilock", "deepsea",
            ".net reactor", "necrobit", "babel", "confuserex",
        }

        if any(any(cp in p.lower() for cp in critical_protectors) for p in protectors) or len(protectors) >= 3:
            return ThreatLevel.CRITICAL
        if any(any(hp in p.lower() for hp in high_protector_keys) for p in protectors) or len(protectors) >= 2:
            return ThreatLevel.HIGH
        if len(protectors) >= 1:
            return ThreatLevel.MEDIUM
        if overlay_size > 1024 * 1024 or len(anomalies) >= 2:
            return ThreatLevel.MEDIUM
        if overlay_size > 0 or len(anomalies) >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    @classmethod
    def scan_single_file(cls, file_path: str, options: BatchScanOptions) -> SingleScanResult:
        """Executes deep forensic inspection on a single candidate binary."""
        start_time = time.perf_counter()
        file_name = os.path.basename(file_path)
        data: Optional[bytearray] = None

        try:
            with open(file_path, "rb") as f:
                data = bytearray(f.read())
        except Exception as e:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return SingleScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=0,
                sha256="",
                status=FileScanStatus.ERROR,
                threat_level=ThreatLevel.LOW,
                is_pe=False,
                is_dotnet=False,
                scan_duration_ms=duration_ms,
                error_message=f"File read error: {e}",
            )

        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        is_pe = cls.is_pe_buffer(data)

        # Fast PE pre-filtering skip
        if options.pe_only and not is_pe:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return SingleScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                status=FileScanStatus.SKIPPED,
                threat_level=ThreatLevel.CLEAN,
                is_pe=False,
                is_dotnet=False,
                scan_duration_ms=duration_ms,
            )

        if not is_pe:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return SingleScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                status=FileScanStatus.CLEAN,
                threat_level=ThreatLevel.CLEAN,
                is_pe=False,
                is_dotnet=False,
                scan_duration_ms=duration_ms,
            )

        try:
            analysis = DotNetPackerCore.analyze_bytes(
                data, master_key=options.master_key, file_name=file_name
            )
            is_dotnet = analysis.get("assembly_info", {}).get("is_dotnet_assembly", False)
            protectors = analysis.get("detected_protectors", [])
            anomalies = analysis.get("pe_structural_health", {}).get("anomalies", [])
            overlay_size = analysis.get("pe_overlay", {}).get("overlay_size", 0)

            status = (
                FileScanStatus.PACKED
                if (protectors or overlay_size > 0 or anomalies)
                else FileScanStatus.CLEAN
            )
            threat_level = cls.classify_threat_level(
                protectors=protectors,
                anomalies=anomalies,
                overlay_size=overlay_size,
                is_dotnet=is_dotnet,
            )

            unpacked_files: List[str] = []
            if options.unpack_payloads and options.unpack_out_dir:
                try:
                    from ..unpacker_dispatcher import unpack_all_to_dir
                    base_stem = os.path.splitext(file_name)[0].strip(". ") or "unpacked_payload"
                    invalid_chars = set('<>:/\\|?*' + chr(34))
                    sanitized_stem = "".join(c if c not in invalid_chars else "_" for c in base_stem)
                    dest_dir = safe_path(options.unpack_out_dir, sanitized_stem)
                    os.makedirs(dest_dir, exist_ok=True)
                    extracted = unpack_all_to_dir(bytes(data), dest_dir)
                    for item in extracted:
                        if isinstance(item, str) and item:
                            unpacked_files.append(item)
                        elif isinstance(item, dict):
                            p = item.get("path") or item.get("file_path") or item.get("output_path")
                            if p and isinstance(p, str):
                                unpacked_files.append(p)
                except Exception as ex:
                    anomalies.append(f"Unpacking error: {ex}")

            duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return SingleScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                status=status,
                threat_level=threat_level,
                is_pe=is_pe,
                is_dotnet=is_dotnet,
                protectors=protectors,
                anomalies=anomalies,
                overlay_size=overlay_size,
                scan_duration_ms=duration_ms,
                unpacked_count=len(unpacked_files),
                unpacked_files=unpacked_files,
                extra_telemetry={
                    "is_xor_packed": analysis.get("pe_overlay", {}).get("is_xor_packed", False),
                    "entropy": analysis.get("pe_overlay", {}).get("entropy", 0.0),
                },
            )
        except Exception as e:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return SingleScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                status=FileScanStatus.ERROR,
                threat_level=ThreatLevel.LOW,
                is_pe=is_pe,
                is_dotnet=False,
                scan_duration_ms=duration_ms,
                error_message=f"Analysis pipeline error: {e}",
            )
        finally:
            if data is not None and isinstance(data, (bytearray, memoryview)):
                zeroize_buffer(data)

    @classmethod
    def scan_directory(
        cls,
        options: BatchScanOptions,
        progress_callback: Optional[Callable[[int, int, SingleScanResult], None]] = None,
    ) -> BatchScanReport:
        """Coordinates multi-threaded batch scanning across target directory with timeout handling."""
        start_overall = time.perf_counter()
        files = cls.discover_files(options)
        total_discovered = len(files)

        if options.unpack_payloads and options.unpack_out_dir:
            try:
                os.makedirs(options.unpack_out_dir, exist_ok=True)
            except OSError:
                pass

        if total_discovered == 0:
            summary = BatchScanSummary(
                total_files_discovered=0,
                total_files_scanned=0,
                total_files_skipped=0,
                elapsed_seconds=round(time.perf_counter() - start_overall, 3),
            )
            return BatchScanReport(options=options, summary=summary, results=[])

        workers = max(1, min(options.workers, total_discovered))
        results: List[SingleScanResult] = []
        progress_lock = threading.Lock()
        completed_count = 0

        file_queue = list(files)
        pending: Dict[concurrent.futures.Future, Tuple[str, float]] = {}
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

        try:
            while file_queue or pending:
                while file_queue and len(pending) < workers:
                    f_path = file_queue.pop(0)
                    fut = executor.submit(cls.scan_single_file, f_path, options)
                    pending[fut] = (f_path, time.perf_counter())

                if not pending:
                    break

                done, _ = concurrent.futures.wait(
                    set(pending.keys()), timeout=0.05, return_when=concurrent.futures.FIRST_COMPLETED
                )

                for fut in done:
                    if fut not in pending:
                        continue
                    f_path, _ = pending.pop(fut)
                    try:
                        res = fut.result(timeout=0)
                    except Exception as exc:
                        res = SingleScanResult(
                            file_path=f_path,
                            file_name=os.path.basename(f_path),
                            file_size=cls._safe_getsize(f_path),
                            sha256="",
                            status=FileScanStatus.ERROR,
                            threat_level=ThreatLevel.LOW,
                            is_pe=False,
                            is_dotnet=False,
                            error_message=str(exc),
                        )
                    results.append(res)
                    with progress_lock:
                        completed_count += 1
                        if progress_callback:
                            try:
                                progress_callback(completed_count, total_discovered, res)
                            except Exception:
                                pass

                # Enforce per-file timeout limits on actively running tasks
                now = time.perf_counter()
                for fut, (f_path, start_t) in list(pending.items()):
                    if (now - start_t) >= options.timeout_sec:
                        pending.pop(fut, None)
                        fut.cancel()
                        timeout_res = SingleScanResult(
                            file_path=f_path,
                            file_name=os.path.basename(f_path),
                            file_size=cls._safe_getsize(f_path),
                            sha256="",
                            status=FileScanStatus.TIMEOUT,
                            threat_level=ThreatLevel.LOW,
                            is_pe=False,
                            is_dotnet=False,
                            error_message=f"Scan exceeded timeout limit of {options.timeout_sec}s",
                        )
                        results.append(timeout_res)
                        with progress_lock:
                            completed_count += 1
                            if progress_callback:
                                try:
                                    progress_callback(completed_count, total_discovered, timeout_res)
                                except Exception:
                                    pass
                        try:
                            executor._max_workers += 1
                        except Exception:
                            pass
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        results.sort(key=lambda r: r.file_path)
        elapsed_seconds = round(time.perf_counter() - start_overall, 3)
        total_scanned = len([r for r in results if r.status != FileScanStatus.SKIPPED])
        total_skipped = len([r for r in results if r.status == FileScanStatus.SKIPPED])
        total_pe = len([r for r in results if r.is_pe])
        total_dotnet = len([r for r in results if r.is_dotnet])
        total_packed = len([r for r in results if r.status == FileScanStatus.PACKED])
        total_clean = len([r for r in results if r.status == FileScanStatus.CLEAN])
        total_errors = len([r for r in results if r.status == FileScanStatus.ERROR])
        total_timeouts = len([r for r in results if r.status == FileScanStatus.TIMEOUT])

        threat_counts = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        protector_counts: Dict[str, int] = {}
        total_bytes = 0

        for r in results:
            total_bytes += r.file_size
            tl_key = getattr(r.threat_level, "value", str(r.threat_level)).lower()
            threat_counts[tl_key] = threat_counts.get(tl_key, 0) + 1
            for p in r.protectors:
                protector_counts[p] = protector_counts.get(p, 0) + 1

        rate_files = round(total_scanned / max(0.001, elapsed_seconds), 2)
        rate_mb = round((total_bytes / (1024 * 1024)) / max(0.001, elapsed_seconds), 2)

        summary = BatchScanSummary(
            total_files_discovered=total_discovered,
            total_files_scanned=total_scanned,
            total_files_skipped=total_skipped,
            total_pe_files=total_pe,
            total_dotnet_files=total_dotnet,
            total_packed_files=total_packed,
            total_clean_files=total_clean,
            total_errors=total_errors,
            total_timeouts=total_timeouts,
            threat_counts=threat_counts,
            protector_counts=protector_counts,
            total_bytes_scanned=total_bytes,
            elapsed_seconds=elapsed_seconds,
            scan_rate_files_per_sec=rate_files,
            scan_rate_mb_per_sec=rate_mb,
        )

        return BatchScanReport(options=options, summary=summary, results=results)
