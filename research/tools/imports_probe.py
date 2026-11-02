from pathlib import Path
import sys,re
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import load
pe=load(sys.argv[1]);pat=re.compile(sys.argv[2],re.I);base=pe.OPTIONAL_HEADER.ImageBase
for kind in ('DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT'):
 for entry in getattr(pe,kind,[]):
  for item in entry.imports:
   name=(item.name or b'').decode()
   if pat.search(name):print(kind,entry.dll.decode(),hex(item.address-base),name)
for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]):
 name=(e.name or b'').decode()
 if pat.search(name):print('EXPORT',hex(e.address),name,(e.forwarder or b'').decode())
