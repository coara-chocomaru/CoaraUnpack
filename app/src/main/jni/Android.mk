LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := coaraunpack
LOCAL_SRC_FILES := \
	avb.cpp \
	boot.cpp \
	boothdr.cpp \
	bzip2.cpp \
	common.cpp \
	compress.cpp \
	cpio.cpp \
	deflate_opt.cpp \
	dtb.cpp \
	hash.cpp \
	info.cpp \
	jni_bridge.cpp \
	lz4.cpp \
	lzma.cpp \
	ramdisk.cpp \
	streaminfo.cpp \
	zimage.cpp
LOCAL_CPPFLAGS := -std=c++17 -O2 -fexceptions -fvisibility=hidden -Wall -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS := -O2 -fvisibility=hidden -D_FILE_OFFSET_BITS=64
LOCAL_LDLIBS := -llog -lz
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,-z,max-page-size=16384
include $(BUILD_SHARED_LIBRARY)
