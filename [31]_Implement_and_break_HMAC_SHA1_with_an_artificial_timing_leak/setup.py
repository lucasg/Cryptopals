from distutils.core import setup, Extension
setup(name='sha1_hmac', version='1.0',  \
      ext_modules=[Extension('sha1_hmac',
      						 library_dirs=['C:\MinGW\lib'],
      						 sources= ['../tools/sha1.c','sha1_hmac.c'])])