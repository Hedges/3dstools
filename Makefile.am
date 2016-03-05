# Makefile.am -- Process this file with automake to produce Makefile.in
bin_PROGRAMS = 3dsxtool 3dsxdump cxitool ciatool

_common_SOURCES     =	src/types.h src/FileClass.h src/ByteBuffer.h
_crypto_SOURCES     =	src/crypto.cpp src/crypto.h src/polarssl/aes.c src/polarssl/rsa.c src/polarssl/sha1.c src/polarssl/sha2.c src/polarssl/base64.c src/polarssl/bignum.c src/polarssl/aes.h src/polarssl/rsa.h src/polarssl/sha1.h src/polarssl/sha2.h src/polarssl/base64.h src/polarssl/bignum.h src/polarssl/bn_mul.h src/polarssl/config.h
_libyaml_SOURCES	=	src/YamlReader.cpp src/YamlReader.h src/libyaml/api.c src/libyaml/dumper.c src/libyaml/emitter.c src/libyaml/loader.c src/libyaml/parser.c src/libyaml/reader.c src/libyaml/scanner.c src/libyaml/writer.c src/libyaml/yaml_private.h src/libyaml/yaml.h
_smdh_SOURCES		=   src/smdh.cpp src/smdh.h src/ctr_app_icon.cpp src/ctr_app_icon.h src/bannerutil/stb_image.c src/bannerutil/stb_image.h
_romfs_SOURCES		=	src/romfs.cpp src/romfs.h src/romfs_dir_scanner.cpp src/romfs_dir_scanner.h
3dsxtool_SOURCES	=	src/3dsxtool.cpp src/elf.h src/oschar.cpp src/oschar.h $(_smdh_SOURCES) $(_romfs_SOURCES) $(_common_SOURCES)
3dsxtool_CXXFLAGS	=
3dsxdump_SOURCES	=	src/3dsxdump.cpp src/3dsx.h $(_common_SOURCES)
3dsxdump_CXXFLAGS	=
cxitool_SOURCES		=	src/cxitool.cpp src/ncch_header.cpp src/ncch_header.h src/cxi_extended_header.cpp src/cxi_extendedheader.h src/exefs.cpp src/exefs.h src/exefs_code.cpp src/exefs_code.h src/ivfc.cpp src/ivfc.h src/oschar.cpp src/oschar.h $(_smdh_SOURCES) $(_romfs_SOURCES) $(_crypto_SOURCES) $(_libyaml_SOURCES) $(_common_SOURCES)
cxitool_CXXFLAGS    =   -Wall
ciatool_SOURCES		=	src/ciatool.cpp src/cia_header.cpp src/cia_header.h src/ncch_header.cpp src/ncch_header.h src/cxi_extended_header.cpp src/cxi_extendedheader.h src/es_ticket.cpp src/es_ticket.h src/es_tmd.cpp src/es_tmd.h src/es_sign.cpp src/es_sign.h $(_crypto_SOURCES) $(_common_SOURCES)
ciatool_CXXFLAGS    =   -Wall
EXTRA_DIST = autogen.sh
