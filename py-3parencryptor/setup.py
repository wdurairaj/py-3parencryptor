import hpe3parencryptor

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

setup(
  name='py-3parencryptor',
  version=hpe3parencryptor.version,
  description="HPE 3PAR Encryption Utility",
  long_description=readme,
  author="Anand Totala",
  author_email="anand-totala.totala@hpe.com",
  maintainer="Anand Totala",
  keywords=["hpe", "3par", "encryptor"],
  install_requires=['python-etcd', 'configparser', 'pycrypto'],
  license="Apache License, Version 2.0",
  packages=find_packages(),
  provides=['hpe3parencryptor'],
  classifiers=[
     'Development Status :: 5 - Production/Stable',
     'Intended Audience :: Developers',
     'License :: OSI Approved :: Apache Software License',
     'Programming Language :: Python',
     'Programming Language :: Python :: 3.6',
     ],
  entry_points={
     "console_scripts":[
         "hpe3parencryptor=hpe3parencryptor:encryption_utility"
     ],
    }
  )
