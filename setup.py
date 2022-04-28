import setuptools

setuptools.setup(
    name="GitSanity",
    version="0.1.9",
    url="https://github.com/Kevino135/skripsi",
    author="Kevin Nolasco, William Suryajaya, Glenn Yohanes",
    author_email="",
    description="Detects potential credential in code with option to encrypt",
    long_description=open('README.md').read(),
    packages=setuptools.find_packages(),
    install_requires=['cryptography==36.0.2', 'passwordmeter==0.1.8'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    entry_points={
        'console_scripts': ['gitSanity = GitSanity.gitSanity:main', 'gitSanityPull = GitSanity.gitSanityPull:main', 'gitSanityPush = GitSanity.gitSanityPush:main'],
    },
    include_package_data=True,
    package_data={'': ['regex.json']},
)