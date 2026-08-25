ARCHS = arm64
TARGET := iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = imgio_probe
imgio_probe_FILES = main.m
imgio_probe_CFLAGS = -Wno-deprecated-declarations
imgio_probe_FRAMEWORKS = Foundation ImageIO CoreGraphics

include $(THEOS_MAKE_PATH)/tool.mk
