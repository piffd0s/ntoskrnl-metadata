# ntoskrnl-metadata

An IDA Python script for extracting critical kernel metadata from Windows ntoskrnl.exe binaries. This tool automatically extracts function RVAs and `_EPROCESS` structure offsets required for developing exploits targeting **CVE-2026-40369** and other kernel vulnerabilities.

## Purpose

This tool aids in compiling successful exploits for **CVE-2026-40369** by automatically extracting version-specific kernel metadata that must be hardcoded into exploit payloads. The extracted values ensure proper function hooking and structure member access across different Windows builds and patch levels.

## Features

- **Automatic Function RVA Extraction**: Retrieves RVAs for key kernel functions:
  - `ExpGetProcessInformation`
  - `ExpQuerySystemInformation`
  - `CmpLayerVersionCount`
  - `CmpLayerVersions`
  - `PsInitialSystemProcess`

- **_EPROCESS Structure Offsets**: Extracts member offsets for:
  - `UniqueProcessId`
  - `ActiveProcessLinks`
  - `Token`
  - `ImageFileName`

- **Ready-to-Use Output**: Generates formatted output ready to paste directly into CVE-2026-40369 exploit code

## Requirements

- **IDA Pro** (with Python support)
- **Windows PDB symbols** loaded for ntoskrnl.exe
- **ida_typeinf module** (included with IDA Pro)

## Usage

1. Open ntoskrnl.exe in IDA Pro
2. Load the matching Windows PDB symbols:
   - File → Load File → PDB File
   - Select the ntoskrnl.pdb for your Windows version
3. Run the script:
   - File → Script File → Select `extract_metadata.py`
   - Or: File → Python → Run script

4. The script will output:
   - All function RVAs with their memory addresses
   - _EPROCESS structure member offsets
   - A formatted row ready for paste into exploit code

## Output Example

```
=== RVAs (image base = 0x140000000) ===
  ExpGetProcessInformation: ea=0x1400a1234  rva=0xa1234
  ExpQuerySystemInformation: ea=0x1400a5678  rva=0xa5678
  ...

=== _EPROCESS member offsets ===
  _EPROCESS.UniqueProcessId: 0x440
  _EPROCESS.ActiveProcessLinks: 0x448
  _EPROCESS.Token: 0x4d8
  _EPROCESS.ImageFileName: 0x5e8

=== g_builds[] row (paste at poc.c:146) ===
    { 26200, 8037, 0xA1234, 0xA5678, 0x440, 0x448, 0x4D8, 0x5E8 },
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "NOT FOUND (PDB not loaded?)" | Load the correct Windows PDB file for your ntoskrnl.exe version |
| "_EPROCESS not in Local Types" | Ensure PDB is properly loaded; try File → Load File → PDB File |
| Script runs but no output | Check that IDA Python console is open (Windows → Output windows → Python) |

## Supported Versions

This script works with any Windows ntoskrnl.exe version where PDB symbols are available. Tested with Windows 10 and Windows 11.

## Notes

- RVAs are calculated relative to the image base displayed in the output
- All offsets are in bytes (converted from IDA's bit offsets)
- The generated output format is compatible with CVE-2026-40369 exploit frameworks
- Ensure you have the correct PDB version matching your ntoskrnl.exe

## License

This tool is provided as-is for security research and authorized analysis purposes only.
