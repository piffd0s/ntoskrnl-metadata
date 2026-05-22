import ida_typeinf
import idc
import idaapi

base = idaapi.get_imagebase()

# Function/global RVAs
syms = [
    "ExpGetProcessInformation",
    "ExpQuerySystemInformation",
    "CmpLayerVersionCount",
    "CmpLayerVersions",
    "PsInitialSystemProcess",
]

print("=== RVAs (image base = 0x%x) ===" % base)

rvas = {}

for n in syms:
    ea = idc.get_name_ea_simple(n)

    if ea == idc.BADADDR:
        print(f"  {n}: NOT FOUND (PDB not loaded?)")
    else:
        rvas[n] = ea - base
        print(f"  {n}: ea=0x{ea:x}  rva=0x{rvas[n]:x}")

# _EPROCESS offsets
print("\n=== _EPROCESS member offsets ===")

wanted = {
    "UniqueProcessId",
    "ActiveProcessLinks",
    "Token",
    "ImageFileName",
}

eprocs = {}

tif = ida_typeinf.tinfo_t()

if tif.get_named_type(None, "_EPROCESS"):
    udt = ida_typeinf.udt_type_data_t()

    if tif.get_udt_details(udt):
        for m in udt:
            if m.name in wanted:
                off = m.offset // 8  # bits -> bytes
                eprocs[m.name] = off
                print(f"  _EPROCESS.{m.name}: 0x{off:x}")
else:
    print("  _EPROCESS not in Local Types (load PDB / load types?)")

# Ready-to-paste row for poc.c:146
print("\n=== g_builds[] row (paste at poc.c:146) ===")

try:
    values = {**rvas, **eprocs}

    print(
        "    {{ 26200, 8037, "
        "0x{ExpGetProcessInformation:X}, "
        "0x{ExpQuerySystemInformation:X}, "
        "0x{UniqueProcessId:X}, "
        "0x{ActiveProcessLinks:X}, "
        "0x{Token:X}, "
        "0x{ImageFileName:X} }},"
        .format(**values)
    )

except KeyError as e:
    print(f"  missing symbol/struct member: {e}")

print("\n=== aux symbols ===")

for n in ("CmpLayerVersionCount", "CmpLayerVersions", "PsInitialSystemProcess"):
    if n in rvas:
        print(f"  {n} RVA: 0x{rvas[n]:X}")
