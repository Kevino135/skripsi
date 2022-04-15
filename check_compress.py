import magic
import tarfile
import zipfile
import gzip
import py7zr
import rarfile
import patoolib
import os

file_name = "compressed"

class Zip():
    def write(self):
        with zipfile.ZipFile(file_name+".zip", 'w') as z:
            z.write(file_name+"/pass.txt")

class Targz():
    def write(self):
        with tarfile.open(file_name+".tar.gz", 'w:gz') as tgz:
            tgz.add(file_name, recursive=True)

class Tarbz2():
    def write(self):
        with tarfile.open(file_name+".tar.bz2", 'w:bz2') as tbz:
            tbz.add(file_name, recursive=True)

class Tarxz():
    def write(self):
        with tarfile.open(file_name+".tar.xz", 'w:xz') as txz:
            txz.add(file_name, recursive=True)

# gzip can only compress file, not folder
class Gzip():
    def write(self):
        with gzip.GzipFile(file_name+".gz", 'w') as gz:
            with open(file_name+"/pass.txt") as f:
                gz.write(f.read().encode())

class Sevenzip():
    def write(self):
        with py7zr.SevenZipFile(file_name+".7z", 'w') as sz:
            sz.writeall(file_name)

# error
class Rar():
    def write(self):
        patoolib.create_archive(file_name+'.rar', '\''+file_name+'/pass.txt')


zip = Zip()
zip.write()

tgz = Targz()
tgz.write()

tbz = Tarbz2()
tbz.write()

txz = Tarxz()
txz.write()

gz = Gzip()
gz.write()

sz = Sevenzip()
sz.write()

rar = Rar()
rar.write()

print(magic.from_file(file_name+".zip", mime=True))
print(magic.from_file(file_name+".tar.gz", mime=True))
print(magic.from_file(file_name+".tar.bz2", mime=True))
print(magic.from_file(file_name+".tar.xz", mime=True))
print(magic.from_file(file_name+".gz", mime=True))
print(magic.from_file(file_name+".7z", mime=True))
print(magic.from_file(file_name+".rar", mime=True))