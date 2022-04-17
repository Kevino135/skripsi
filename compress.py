import magic
import tarfile
import zipfile
import gzip
import py7zr
import os


class Zip:
    def compress(self, target_path):
        files_list = []
        for root, directories, files in os.walk("test1"):
            for name in files:
                files_list.append(os.path.join(root, name))

        with zipfile.ZipFile(target_path, 'w') as z:
            for files in files_list:
                z.write(files)
    
    def decompress(self, target_path, extract_path):
        with zipfile.ZipFile(target_path, 'r') as z:
            z.extractall(extract_path)

    def list(self, target_path):
        with zipfile.ZipFile(target_path, 'r') as z:
            return z.namelist()


class Sevenzip:
    def compress(self, target_path):
        with py7zr.SevenZipFile(target_path, 'w') as sz:
            sz.writeall("test2")

    def decompress(self, target_path, extract_path):
        with py7zr.SevenZipFile(target_path, 'r') as sz:
            sz.extractall(extract_path)

    def list(self, target_path):
        with py7zr.SevenZipFile(target_path, 'r') as sz:
            list_file = sz.getnames()
            list_file.pop(0)
            return list_file


class Tar:
    def compress(self, target_path):
        with tarfile.open(target_path, 'w') as t:
            t.add("test3", recursive=True)
    
    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r') as t:
            t.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r') as t:
            list_file = t.getnames()
            list_file.pop(0)
            return list_file


# gzip can only compress one file, not folder
class Gzip:
    def compress(self, target_path):
        with open("test4/pass.txt", "r") as f:
            data = f.read().encode()
        data = gzip.compress(data)

        with gzip.GzipFile(target_path, 'w') as gz:
            with open("test4/pass.txt") as f:
                gz.write(data)
    
    def decompress(self, target_path, extract_path):
        with gzip.GzipFile(target_path, 'r') as gz:
            data = gz.read()
            data = gzip.decompress(data).decode()

        file_name = target_path.split(".gz")[0]
        with open(extract_path + "/" + file_name, 'w') as f:
            f.write(data)

    def list(self, target_path):
        file_name = target_path.split(".gz")[0]
        list_file = list()
        list_file.append(file_name)
        return list_file


class Targz():
    def compress(self, target_path):
        with tarfile.open(target_path, 'w:gz') as tgz:
            tgz.add("test9", recursive=True)
    
    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:gz') as tgz:
            tgz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:gz') as tgz:
            list_file = tgz.getnames()
            list_file.pop(0)
            return list_file


class Tarbz2:
    def compress(self, target_path):
        with tarfile.open(target_path, 'w:bz2') as tbz:
            tbz.add("test6", recursive=True)
    
    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:bz2') as tbz:
            tbz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:bz2') as tbz:
            list_file = tbz.getnames()
            list_file.pop(0)
            return list_file


class Tarxz:
    def compress(self, target_path):
        with tarfile.open(target_path, 'w:xz') as txz:
            txz.add("test7", recursive=True)

    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:xz') as txz:
            txz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:xz') as txz:
            list_file = txz.getnames()
            list_file.pop(0)
            return list_file


zip = Zip()
# zip.compress("test1.zip")
# zip.decompress("test1.zip", "extraction")
# print(zip.list("test1.zip"))

sz = Sevenzip()
# sz.compress("test2.7z")
# sz.decompress("test2.7z", "extraction")
# print(sz.list("test2.7z"))

tar = Tar()
# tar.compress("test3.tar")
# tar.decompress("test3.tar", "extraction")
# print(tar.list("test3.tar"))

gz = Gzip()
# gz.compress("test4.gz")
# gz.decompress("test4.gz", "extraction")
# print(gz.list("test4.gz"))

tgz = Targz()
# tgz.compress("test9.txt.gz")
# tgz.decompress("test5.tar.gz", "extraction")
# print(tgz.list("test5.tar.gz"))

tbz = Tarbz2()
# tbz.compress("test6.tar.bz2")
# tbz.decompress("test6.tar.bz2", "extraction")
# print(tbz.list("test6.tar.bz2"))

txz = Tarxz()
# txz.compress("test7.tar.xz")
# txz.decompress("test7.tar.xz", "extraction")
# print(txz.list("test7.tar.xz"))


# print(magic.from_file("test1.zip", mime=True))
# print(magic.from_file("test2.7z", mime=True))
# print(magic.from_file("test3.tar", mime=True))
# print(magic.from_file("test4.gz", mime=True))
# print(magic.from_file("test5.tar.gz", mime=True))
# print(magic.from_file("test6.tar.bz2", mime=True))
# print(magic.from_file("test7.tar.xz", mime=True))


# compressed_type = {
#     "application/zip": Zip(),
#     "application/x-7z-compressed": Sevenzip(),
#     "application/x-tar": Tar(),
#     "application/x-gzip": {
#         "gz": Gzip(),
#         "tgz": Targz()
#         # ".tar.gz": Targz(),
#         # ".txt.gz": Targz()
#     },
#     "application/bzip2": Tarbz2(),
#     "application/x-xz": Tarxz()
# }