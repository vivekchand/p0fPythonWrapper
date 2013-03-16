from distutils.core import setup, Extension

module1 = Extension('p0fmod',
	include_dirs = ['/usr/local/include'],
	libraries = ['pthread','pcap'],
	sources = ['p0fmod.c' , 'api.c' ,'process.c','fp_tcp.c','fp_mtu.c','fp_http.c','readfp.c'])

setup (name = 'p0fmod',
       version = '1.0',
       description = 'This is an example package',
	author = 'vivek',
	url ='http://www.linuxguide.in',
	ext_modules = [module1])
