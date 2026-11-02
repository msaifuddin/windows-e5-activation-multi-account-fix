from pathlib import Path
import sys,struct
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import load
pe=load('apisetschema.dll')
d=next(s.get_data() for s in pe.sections if s.Name.startswith(b'.apiset'))
version,size,flags,count,at,hashat,hashfactor=struct.unpack_from('<7I',d)
for i in range(count):
 f,n,nlen,hlen,v,vcount=struct.unpack_from('<6I',d,at+i*24)
 name=d[n:n+nlen].decode('utf-16-le')
 if any(x.lower() in name.lower() for x in sys.argv[1:]):
  print(name)
  for j in range(vcount):
   vf,a,alen,b,blen=struct.unpack_from('<5I',d,v+j*20)
   print(' ',d[a:a+alen].decode('utf-16-le'),'=>',d[b:b+blen].decode('utf-16-le'))
