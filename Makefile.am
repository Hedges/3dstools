# Makefile.am -- Process this file with automake to produce Makefile.in
bin_PROGRAMS = 3dsxtool 3dsxdump smdhtool cxitool

_common_SOURCES	=	src/types.h src/FileClass.h
_lodepng_SOURCES	=	src/lodepng/lodepng.cpp src/lodepng/lodepng.h
_polarssl_SOURCES	=	src/crypto.cpp src/crypto.h src/polarssl/aes.c src/polarssl/rsa.c src/polarssl/sha1.c src/polarssl/sha2.c src/polarssl/base64.c src/polarssl/bignum.c src/polarssl/aes.h src/polarssl/rsa.h src/polarssl/sha1.h src/polarssl/sha2.h src/polarssl/base64.h src/polarssl/bignum.h src/polarssl/bn_mul.h src/polarssl/config.h
_libyaml_SOURCES	=	src/YamlReader.cpp src/YamlReader.h src/libyaml/api.c src/libyaml/dumper.c src/libyaml/emitter.c src/libyaml/loader.c src/libyaml/parser.c src/libyaml/reader.c src/libyaml/scanner.c src/libyaml/writer.c src/libyaml/yaml_private.h src/libyaml/yaml.h
3dsxtool_SOURCES	=	src/3dsxtool.cpp src/romfs.cpp src/elf.h src/romfs.h $(_common_SOURCES)
3dsxtool_CXXFLAGS	=
3dsxdump_SOURCES	=	src/3dsxdump.cpp src/3dsx.h $(_common_SOURCES)
3dsxdump_CXXFLAGS	=
smdhtool_SOURCES	=	src/smdhtool.cpp $(_lodepng_SOURCES) $(_common_SOURCES)
smdhtool_CXXFLAGS	=
cxitool_SOURCES		=	src/cxitool.cpp src/ncchheader.cpp src/ncchheader.h src/ncchextendedheader.cpp src/ncchextendedheader.h src/exefs.cpp src/exefs.h src/exefscode.cpp src/exefscode.h src/romfs2.cpp src/romfs2.h src/romfsdirscanner.cpp src/romfsdirscanner.h src/oschar.cpp src/oschar.h src/ivfc.cpp src/ivfc.h $(_polarssl_SOURCES) $(_libyaml_SOURCES) $(_common_SOURCES)
cxitool_CXXFLAGS    =   -Wall
EXTRA_DIST = autogen.sh
