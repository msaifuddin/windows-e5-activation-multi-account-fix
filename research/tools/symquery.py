from pathlib import Path
import sys,json,re,struct
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import *
name=sys.argv[1]; pattern=sys.argv[2]
pe=load(name); base=pe.OPTIONAL_HEADER.ImageBase
syms=json.loads((root/'symbols'/f'{name}.json').read_text())
names={s['rva']:s['name'] for s in syms}
for s in syms:
    n=s['name']
    if re.search(pattern,n) and not ('?$RuntimeClass' in n or '?$ImplementsHelper' in n or '$$h' in n):
        print(f"{s['rva']:08X} {n}")
        if n.startswith('??_7'):
            for i,pointer in enumerate(struct.unpack('<'+'Q'*16,pe.get_data(s['rva'],128))):
                print('  slot',i,hex(pointer-base),names.get(pointer-base,'?')[:240])
