from pathlib import Path
import hashlib, urllib.request, zipfile

root = Path(__file__).parent
archive = root / 'downloads' / 'python-3.12.10-embed-amd64.zip'
if not archive.exists():
    urllib.request.urlretrieve('https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip', archive)
assert hashlib.md5(archive.read_bytes()).hexdigest() == 'fe8ef205f2e9c3ba44d0cf9954e1abd3'
with zipfile.ZipFile(archive) as z:
    z.extractall(root / 'python-x64')
for wheel in (root / 'downloads').glob('capstone-*-win_amd64.whl'):
    with zipfile.ZipFile(wheel) as z:
        z.extractall(root / 'deps-x64')
print('Local x64 analysis interpreter and Capstone extracted in workspace.')
