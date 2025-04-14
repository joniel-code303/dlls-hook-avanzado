from setuptools import setup, find_packages

setup(
    name="dll_hook_scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'psutil>=5.8.0',
        'pefile>=2021.9.3',
    ],
    entry_points={
        'console_scripts': [
            'dllscan=src.escaneo_hook_dlls:main',
        ],
    },
)
