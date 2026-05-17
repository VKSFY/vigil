"""
Generate a minimal valid Windows x64 PE named winword.exe in this directory.

Hand-builds an IMAGE_DOS_HEADER + DOS stub + IMAGE_NT_HEADERS64 + a single
.text section containing `xor eax, eax; ret`. The result is a structurally
valid PE that exits cleanly with status 0 when run on Windows.

The stub exists so the office-spawn-shell behavior test has a process
named winword.exe to use as a parent, without redistributing Microsoft's
cmd.exe. It doesn't interpret arguments -- it just exits -- so the full
end-to-end office->shell test requires a renamed shell on your own box.

Stdlib only.

    python data/test_samples/make_fake_winword.py
"""
import os
import struct
import sys


OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "winword.exe")


def build_pe() -> bytes:
    # --- IMAGE_DOS_HEADER (64 bytes) -------------------------------------
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 0x80)  # e_lfanew -> PE header at 0x80

    # --- DOS stub (64 bytes) — printable "cannot be run in DOS mode" msg
    stub_asm = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    stub_msg = b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub = (stub_asm + stub_msg)[:64].ljust(64, b"\x00")

    # --- IMAGE_NT_HEADERS64 ---------------------------------------------
    pe_sig = b"PE\x00\x00"

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,        # IMAGE_FILE_MACHINE_AMD64
        1,             # NumberOfSections
        0,             # TimeDateStamp
        0,             # PointerToSymbolTable
        0,             # NumberOfSymbols
        240,           # SizeOfOptionalHeader
        0x0022,        # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    opt_hdr = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,           # Magic = PE32+
        14, 0,           # MajorLinkerVersion, MinorLinkerVersion
        0x200,           # SizeOfCode
        0,               # SizeOfInitializedData
        0,               # SizeOfUninitializedData
        0x1000,          # AddressOfEntryPoint (RVA, start of .text)
        0x1000,          # BaseOfCode
        0x140000000,     # ImageBase (standard x64 base)
        0x1000,          # SectionAlignment
        0x200,           # FileAlignment
        6, 0,            # Major/MinorOperatingSystemVersion
        0, 0,            # Major/MinorImageVersion
        6, 0,            # Major/MinorSubsystemVersion
        0,               # Win32VersionValue
        0x2000,          # SizeOfImage (1 page headers + 1 page .text)
        0x200,           # SizeOfHeaders (file-aligned)
        0,               # CheckSum (the loader doesn't verify for EXEs)
        3,               # Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
        0x8160,          # DllCharacteristics = NX | DYNAMIC_BASE | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
        0x100000,        # SizeOfStackReserve
        0x1000,          # SizeOfStackCommit
        0x100000,        # SizeOfHeapReserve
        0x1000,          # SizeOfHeapCommit
        0,               # LoaderFlags
        16,              # NumberOfRvaAndSizes
    )
    # 16 zeroed data directories (8 bytes each)
    opt_hdr += b"\x00" * (16 * 8)
    assert len(opt_hdr) == 240, f"optional header wrong size: {len(opt_hdr)}"

    # --- IMAGE_SECTION_HEADER for .text (40 bytes) ----------------------
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x6,                  # VirtualSize (3-byte code is fine; rounded up)
        0x1000,               # VirtualAddress
        0x200,                # SizeOfRawData (file-aligned)
        0x200,                # PointerToRawData
        0, 0, 0, 0,           # relocs, linenumbers (all unused)
        0x60000020,           # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    )

    # Pad headers to FileAlignment (0x200).
    headers = bytes(dos) + dos_stub + pe_sig + coff + opt_hdr + section
    headers = headers.ljust(0x200, b"\x00")

    # --- .text code: `xor eax, eax; ret`  (returns 0 to RtlUserThreadStart) ---
    text = b"\x31\xc0\xc3"
    text_section = text.ljust(0x200, b"\x00")

    return headers + text_section


def main():
    pe = build_pe()
    with open(OUT, "wb") as f:
        f.write(pe)
    print(f"wrote {OUT} ({len(pe)} bytes)")
    print("Run this once before running the behavior tests.")


if __name__ == "__main__":
    main()
