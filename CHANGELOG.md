# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-10-13

### Added
- **PE Header & Section Rebuilder Engine (`dotnet_deobfuscator.pe_rebuilder`)**:
  - Full structural health diagnostics identifying corrupted DOS headers, invalid `e_lfanew` pointers, damaged NT signatures, non-power-of-two alignments, and process memory dump layouts.
  - DOS and NT header reconstruction: auto-locates orphaned PE signatures, restores valid `MZ` and `e_lfanew` pointers, synthesizes standard MS-DOS stubs, and normalizes Machine architecture and subsystem fields.
  - Section table realignment: realigns section headers, enforces power-of-two FileAlignment and SectionAlignment padding, and recalculates `SizeOfHeaders` and `SizeOfImage`.
  - Process memory dump unmapping: unmaps mapped section RVAs back to compact sequential disk raw offsets, transforming in-memory process dumps into runnable disk binaries.
  - CLR COM Descriptor recovery: scans `.text` and code sections for anti-dump zeroed Cor20Header descriptors, verifies `BSJB` CLI metadata streams, and restores directory entry 14 RVA and 72-byte size.
  - Authenticode stripping: automatically clears obsolete, broken Certificate / Security directory tables post-unpacking.
  - Safe bounds checks and buffer zeroizing on sensitive intermediate rebuild buffers.
- **CLI & Core Orchestrator Integration**:
  - Added `--rebuild`, `--rebuild-out`, and `--unmap-dump` flags to `dotnet-packer-re` CLI.
  - Extended text and JSON telemetry with `PE Structural Health & Rebuilder Diagnostics`.
  - Added `DotNetPackerCore.rebuild_pe` and `DotNetPackerCore.rebuild_pe_buffer`.
- **Comprehensive PE Rebuilder Test Suite (`tests/test_pe_rebuilder.py`)**:
  - 14 test cases covering anomaly detection, DOS/NT header repairs, section realignment, memory dump unmapping, Cor20Header recovery, security directory stripping, bounds checks, and CLI commands.
- **GitHub Actions Automated CI Pipeline (`.github/workflows/ci.yml`)**:
  - Continuous integration testing across Python 3.10, 3.11, and 3.12 with asset integrity verification.

## [1.2.0] - 2026-10-13

### Added
- **ConfuserEx Forensic Unpacker & Decryption Engine (`dotnet_deobfuscator.unpackers.confuserex`)**:
  - Full static analysis and marker detection for ConfuserEx attributes (`ConfusedByAttribute`), runtime indicators, and Unicode mangled identifiers.
  - Multi-mode constants and string decryption supporting LCG/XorShift 32-bit PRNG stream ciphers, key mutation schedules, and entropy-minimizing auto key recovery.
  - Encrypted resource container parsing, CLI Cor20Header resource stream decoding, and multi-format decompression (Deflate, Zlib, Gzip, raw).
  - Internal resource catalog parser extracting embedded assemblies, bitmaps, XML configurations, and managed resources.
  - Safe extraction to directory (`-d, --unpack-dir`) with strict directory traversal neutralization and memory buffer Zeroize wiping.
  - Dedicated CLI command flag `--dump-strings` for direct extraction and cataloging of decrypted strings.
- **Comprehensive ConfuserEx Test Suite (`tests/test_confuserex_unpacker.py`)**:
  - Added 19 test cases validating detection heuristics, PRNG keystream generation, string table decoding, resource catalog parsing, path traversal defense, and CLI command integration.

### Changed
- Integrated ConfuserEx forensics into `DotNetPackerCore.analyze_file`, returning structured telemetry for active protections, decrypted strings, and extracted resources.
- Extended `dotnet-packer-re` CLI to format ConfuserEx detection and telemetry in text and JSON modes.

## [1.1.0] - 2026-10-13

### Added
- **Costura.Fody Unpacker Engine (`dotnet_deobfuscator.unpackers.costura`)**:
  - Full static analysis and extraction of embedded managed assemblies, native unmanaged DLLs (`costura32`/`costura64`), and PDB symbols.
  - Multi-tier RFC 1951 DeflateStream inversion supporting raw deflate, 4-byte/8-byte length prefixes, zlib, and gzip fallbacks.
  - CLI Cor20Header and metadata `#Strings` parser to recover authentic assembly resource names.
  - Heuristic stream carving fallback for packed, stripped, or anti-tampered binaries.
  - Directory extraction support (`-d, --unpack-dir`) with strict path traversal defenses and safe filename normalization.
  - SHA-256 integrity hashing, PE structure validation (`MZ` / `PE\0\0`), and Shannon entropy profiling on all extracted payloads.
- **Protector Signatures Expansion**:
  - Added Costura heuristic rules to `ProtectorSignatures.RULES`.
- **Comprehensive Test Suite (`tests/test_costura_unpacker.py`)**:
  - Added 9 new unit test cases covering raw deflate, length prefixes, filename sanitization, synthetic PE assembly resource extraction, CLI integration, and carving fallbacks.
- **Milestone Evolution Roadmap**:
  - Proactively expanded `TASK_BACKLOG.md` with milestones M06 through M20 and added forward-looking milestones M21 through M25.

### Changed
- Updated `dotnet-packer-re` CLI to format Costura embedded assembly forensics in text and JSON telemetry outputs.
- Enhanced `DotNetPackerCore.unpack_to_file` and added `DotNetPackerCore.unpack_to_dir`.

## [1.0.0] - 2026-10-11

### Added
- Initial baseline release of `dotnet-packer-forensics`.
- xorPacker dual-stage XOR decryption engine and PE overlay carver.
- .NET CLI metadata stream parser (`#Strings`, `#US`, `#Blob`, `#GUID`, `#~`).
- Heuristic signature matcher for 8 major .NET packers (ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, DeepSea, IntelliLock, xorPacker).
- CLI toolchain (`dotnet-packer-re`) and verification pipeline.
