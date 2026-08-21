ARCHS = arm64
TARGET := iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = sep_panic
sep_panic_FILES = main.c
sep_panic_CFLAGS = -Wno-deprecated-declarations
sep_panic_FRAMEWORKS = IOKit CoreFoundation

include $(THEOS_MAKE_PATH)/tool.mk
