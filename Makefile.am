# Makefile.am -- Process this file with automake to produce Makefile.in
bin_PROGRAMS = 3dsxtool 3dsxdump smdhtool

_common_SOURCES	=	src/types.h src/FileClass.h
_lodepng_SOURCES	=	src/lodepng/lodepng.cpp src/lodepng/lodepng.h
_polarssl_SOURCES	=	src/polarssl/aes.c src/polarssl/rsa.c src/polarssl/sha1.c src/polarssl/sha2.c src/polarssl/base64.c src/polarssl/bignum.c src/polarssl/aes.h src/polarssl/rsa.h src/polarssl/sha1.h src/polarssl/sha2.h src/polarssl/base64.h src/polarssl/bignum.h src/polarssl/bn_mul.h src/polarssl/config.h
3dsxtool_SOURCES	=	src/3dsxtool.cpp src/romfs.cpp src/elf.h src/romfs.h $(_common_SOURCES)
3dsxtool_CXXFLAGS	=
3dsxdump_SOURCES	=	src/3dsxdump.cpp src/3dsx.h $(_common_SOURCES)
3dsxdump_CXXFLAGS	=
smdhtool_SOURCES	=	src/smdhtool.cpp $(_lodepng_SOURCES) $(_common_SOURCES)
smdhtool_CXXFLAGS	=
EXTRA_DIST = autogen.sh
