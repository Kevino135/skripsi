import setuptools

setuptools.setup(
    name="GitSanity",
    version="0.1.0",
    url="https://github.com/Kevino135/skripsi",
    author="Kevin Nolasco, William Suryajaya, Glenn Yohanes",
    author_email="",
    description="Detects potential credential in code with option to encrypt",
    long_description=open('README.md').read(),
    packages=setuptools.find_packages(),
    install_requires=['colorama==0.4.4','cryptography==36.0.2', 'passwordmeter==0.1.8', 'py7zr==0.18.4', 'python_magic==0.4.25'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
    ],
)