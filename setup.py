from glob import glob
from os.path import splitext, basename

from setuptools import setup, find_packages

setup(
    name='vlei-verifier-client',
    version='0.1.3',
    author='Aidar Negimatzhanov',
    author_email='aydar.negimatzhanov@perfectart.com',
    description='Python client for vlei-verifier',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/GLEIF-IT/vlei-verifier-client-py',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',  # Replace with your license
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.12',
    install_requires=[
        'requests',
        'aiohttp'
    ],
)