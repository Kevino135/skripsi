import os
import tarfile
import zipfile
import gzip
import py7zr


class Zip:
    def compress(self, target_path, extract_path, extraction_path):
        with zipfile.ZipFile(target_path, 'w') as z:
            for path in extract_path:
                if os.path.isfile(path):
                    z.write(path)
                elif os.path.isdir(path):
                    for root, directories, files in os.walk(path):
                        folder = root.replace(extraction_path+"/", "")
                        for name in files:
                            z.write(
                                filename = os.path.join(root, name), 
                                arcname  = os.path.join(folder, name)
                            )

    def decompress(self, target_path, extract_path):
        with zipfile.ZipFile(target_path, 'r') as z:
            z.extractall(extract_path)

    def list(self, target_path):
        with zipfile.ZipFile(target_path, 'r') as z:
            return z.namelist()


class Sevenzip:
    def compress(self, target_path, extract_path, extraction_path):
        with py7zr.SevenZipFile(target_path, 'w') as sz:
            for path in extract_path:
                arc_name = path.replace(extraction_path+"/", "")
                sz.writeall(
                    path    = path,
                    arcname = arc_name
                )

    def decompress(self, target_path, extract_path):
        with py7zr.SevenZipFile(target_path, 'r') as sz:
            sz.extractall(extract_path)

    def list(self, target_path):
        with py7zr.SevenZipFile(target_path, 'r') as sz:
            list_file = sz.getnames()
            list_file.pop(0)
            return list_file


class Tar:
    def compress(self, target_path, extract_path, extraction_path):
        with tarfile.open(target_path, 'w') as t:
            for path in extract_path:
                arc_name = path.replace(extraction_path+"/", "")
                t.add(
                    name      = path,
                    arcname   = arc_name,
                    recursive = True
                )
    
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
    def compress(self, target_path, extract_path, extraction_path):
        with open(extract_path[0], "r") as f:
            data = f.read().encode()
        data = gzip.compress(data)

        with gzip.GzipFile(target_path, 'w') as gz:
            with open(target_path) as f:
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
    def compress(self, target_path, extract_path, extraction_path):
        with tarfile.open(target_path, 'w:gz') as tgz:
            for path in extract_path:
                arc_name = path.replace(extraction_path+"/", "")
                tgz.add(
                    name      = path,
                    arcname   = arc_name,
                    recursive = True
                )
    
    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:gz') as tgz:
            tgz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:gz') as tgz:
            list_file = tgz.getnames()
            list_file.pop(0)
            return list_file


class Tarbz2:
    def compress(self, target_path, extract_path, extraction_path):
        with tarfile.open(target_path, 'w:bz2') as tbz:
            for path in extract_path:
                arc_name = path.replace(extraction_path+"/", "")
                tbz.add(
                    name      = path,
                    arcname   = arc_name,
                    recursive = True
                )
    
    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:bz2') as tbz:
            tbz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:bz2') as tbz:
            list_file = tbz.getnames()
            list_file.pop(0)
            return list_file


class Tarxz:
    def compress(self, target_path, extract_path, extraction_path):
        with tarfile.open(target_path, 'w:xz') as txz:
            for path in extract_path:
                arc_name = path.replace(extraction_path+"/", "")
                txz.add(
                    name      = path,
                    arcname   = arc_name,
                    recursive = True
                )

    def decompress(self, target_path, extract_path):
        with tarfile.open(target_path, 'r:xz') as txz:
            txz.extractall(extract_path)

    def list(self, target_path):
        with tarfile.open(target_path, 'r:xz') as txz:
            list_file = txz.getnames()
            list_file.pop(0)
            return list_file


compression_type = {
    "application/zip": Zip(),
    "application/x-7z-compressed": Sevenzip(),
    "application/x-tar": Tar(),
    "application/x-gzip": {
        "gz": Gzip(),
        "tgz": Targz()
        # ".tar.gz": Targz(),
        # ".txt.gz": Targz()
    },
    "application/x-bzip2": Tarbz2(),
    "application/x-xz": Tarxz()
}
