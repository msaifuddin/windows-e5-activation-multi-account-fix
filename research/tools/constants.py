from pathlib import Path
import sys,json,struct,uuid
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import load,root
pe=load('LicenseManager.dll');base=pe.OPTIONAL_HEADER.ImageBase
syms=json.loads((root/'symbols/LicenseManager.dll.json').read_text());names={s['rva']:s['name'] for s in syms}
for rva in (0x199058,0x199068,0x199078,0x199098):
 print(hex(rva),str(uuid.UUID(bytes_le=pe.get_data(rva,16))))
for rva in range(0x18ab90,0x18acd0,8):
 p=struct.unpack('<Q',pe.get_data(rva,8))[0]-base
 print(hex(rva),hex(p),names.get(p,'?')[:175])
