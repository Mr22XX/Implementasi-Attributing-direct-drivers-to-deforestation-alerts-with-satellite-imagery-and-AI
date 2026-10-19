"""
Membuat src/wilayah.json (daftar provinsi -> kabupaten/kota) dari file .dbf BIG di komputer Anda.
Cukup dijalankan SEKALI, dan diulang hanya bila Anda mengganti edisi data.

Pasang:  pip install dbfread
Jalankan: python tools/buat_wilayah.py "D:\\KKN\\BATAS WILAYAH KELURAHAN-DESA 10K\\Batas_Wilayah_KelurahanDesa_10K_AR.dbf"
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

from dbfread import DBF

if len(sys.argv) < 2:
    sys.exit('Pemakaian: python tools/buat_wilayah.py <path-ke-file.dbf> [encoding]')

path = sys.argv[1]
# Cek isi file .cpg di samping .dbf; umumnya UTF-8. Ganti bila nama wilayah tampak rusak.
encoding = sys.argv[2] if len(sys.argv) > 2 else 'utf-8'

wil = defaultdict(set)
tabel = DBF(path, encoding=encoding, char_decode_errors='replace', load=False)
for rec in tabel:
    prov = (rec.get('WADMPR') or '').strip()
    kab = (rec.get('WADMKK') or '').strip()
    if prov and kab:
        wil[prov].add(kab)

hasil = {p: sorted(k) for p, k in sorted(wil.items())}
tujuan = Path(__file__).resolve().parent.parent / 'src' / 'wilayah.json'
tujuan.write_text(json.dumps(hasil, ensure_ascii=False, indent=1), encoding='utf-8')

print(f'{len(hasil)} provinsi, {sum(len(v) for v in hasil.values())} kabupaten/kota -> {tujuan}')