from pathlib import Path
import sys,re,struct,json
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import load,root
name=sys.argv[1];pe=load(name);base=pe.OPTIONAL_HEADER.ImageBase
for a in sys.argv[2:]:
 rva=int(a,16);d=pe.get_data(rva,450)
 print(hex(rva),'utf16:',d.decode('utf-16-le',errors='replace').split('\0')[0], 'hex:',d[:16].hex())
 if len(d)>7:
  p=struct.unpack('<Q',d[:8])[0]-base
  if p>0 and p<pe.OPTIONAL_HEADER.SizeOfImage:
   print('pointer',hex(p),pe.get_data(p,450).decode('utf-16-le',errors='replace').split('\0')[0])
if len(sys.argv)==2:
 for match in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}',pe.__data__):
  s=match.group().decode('utf-16-le')
  if re.search(r'client|resource|subscription|store|licensemanager|https|268761a2|45a330b1',s,re.I):
   print(hex(pe.get_rva_from_offset(match.start())),s[:400])
