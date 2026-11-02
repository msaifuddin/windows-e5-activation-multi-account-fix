from pathlib import Path
import sys, struct, uuid, urllib.request, re, json
root = Path(__file__).parent
sys.path[:0] = [str(root/'deps'), str(root/'deps-x64')]
import pefile

def load(name):
    return pefile.PE(str(Path('C:/Windows/System32')/name))

def symbols(pe, name):
    for debug in pe.DIRECTORY_ENTRY_DEBUG:
        if debug.struct.Type != 2: continue
        data = pe.get_data(debug.struct.AddressOfRawData,debug.struct.SizeOfData)
        if data[:4] != b'RSDS': continue
        guid = uuid.UUID(bytes_le=data[4:20]).hex.upper()
        age = struct.unpack_from('<I',data,20)[0]
        pdb_name = data[24:].split(b'\0')[0].decode().split('\\')[-1]
        dest = root/'symbols'/f'{guid}-{pdb_name}'
        dest.parent.mkdir(exist_ok=True)
        if not dest.exists():
            url=f'https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age:X}/{pdb_name}'
            print('Fetching matching public symbols:',url,flush=True)
            urllib.request.urlretrieve(url,dest)
        raw=dest.read_bytes()
        block_size, _, block_count, dir_size, _, map_block = struct.unpack_from('<6I',raw,32)
        dir_blocks = struct.unpack_from('<'+'I'*((dir_size+block_size-1)//block_size),raw,map_block*block_size)
        directory=b''.join(raw[b*block_size:(b+1)*block_size] for b in dir_blocks)[:dir_size]
        count=struct.unpack_from('<I',directory)[0]
        sizes=struct.unpack_from('<'+'I'*count,directory,4)
        at=4+4*count
        streams=[]
        for size in sizes:
            if size==0xffffffff: streams.append(b''); continue
            n=(size+block_size-1)//block_size
            blocks=struct.unpack_from('<'+'I'*n,directory,at) if n else []
            at+=4*n
            streams.append(b''.join(raw[b*block_size:(b+1)*block_size] for b in blocks)[:size])
        sym_index=struct.unpack_from('<H',streams[3],20)[0]
        dbi=streams[3]
        mod_size, contrib_size, secmap_size, source_size, typeserver_size=struct.unpack_from('<5I',dbi,24)
        optional_size, ec_size=struct.unpack_from('<2I',dbi,48)
        opt_at=64+mod_size+contrib_size+secmap_size+source_size+typeserver_size+ec_size
        debug_streams=struct.unpack_from('<'+'H'*(optional_size//2),dbi,opt_at) if optional_size else []
        section_headers=None
        omap=[]
        if len(debug_streams)>10 and debug_streams[10]!=0xffff:
            section_headers=streams[debug_streams[10]]
        elif len(debug_streams)>5 and debug_streams[5]!=0xffff:
            section_headers=streams[debug_streams[5]]
        if len(debug_streams)>4 and debug_streams[4]!=0xffff:
            omap=list(struct.iter_unpack('<II',streams[debug_streams[4]]))
        print('Debug streams',list(debug_streams),'OMAP entries',len(omap),flush=True)
        def original_rva(segment, offset):
            if section_headers and segment<=len(section_headers)//40:
                return struct.unpack_from('<I',section_headers,(segment-1)*40+12)[0]+offset
            return pe.sections[segment-1].VirtualAddress+offset
        def map_rva(rva):
            if not omap: return rva
            import bisect
            i=bisect.bisect_right(omap,(rva,0xffffffff))-1
            if i<0 or not omap[i][1]: return 0
            return omap[i][1]+rva-omap[i][0]
        sym_stream=streams[sym_index]
        records=[]; at=0
        while at+4<=len(sym_stream):
            length,kind=struct.unpack_from('<HH',sym_stream,at)
            if length<2: break
            if kind==0x110e:
                flags,offset,segment=struct.unpack_from('<IIH',sym_stream,at+4)
                text=sym_stream[at+14:at+length+2].split(b'\0')[0].decode('utf-8','replace')
                if 0<segment<=len(pe.sections):
                    rva=map_rva(original_rva(segment,offset))
                    if not rva:
                        at+=length+2
                        continue
                    records.append(dict(rva=rva,name=text,flags=flags))
            at+=length+2
        (root/'symbols'/f'{name}.json').write_text(json.dumps(records,indent=2))
        print(name,'machine',hex(pe.FILE_HEADER.Machine),'symbols',len(records),flush=True)
        return records
    return []

if __name__=='__main__':
    for name in sys.argv[1:]:
        try:
            syms=symbols(load(name),name)
            for s in syms:
                if re.search(r'CaptureIdentity|Capture.*Ticket|Get.*Ticket|Get.*Account|Subscription|Acquire.*License|Tenant|PrimaryWebAccount|StoreAADAccount|IdentityProvider',s['name'],re.I):
                    print(f"{s['rva']:08X} {s['name']}")
        except Exception as e: print(name,type(e).__name__,str(e))
