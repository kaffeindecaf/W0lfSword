TARGET := iphone:clang:latest:15.0
ARCHS = arm64
# Theos tool builds for CLI test binaries — no substrate needed.
include $(THEOS)/makefiles/common.mk

TOOL_NAME = primtest primtest2
primtest_FILES = primtest.m
primtest_LDFLAGS = -framework IOSurface -framework CoreFoundation -framework IOKit
primtest2_FILES = primtest2.m
primtest2_LDFLAGS = -framework IOSurface -framework CoreFoundation -framework IOKit

include $(THEOS_MAKE_PATH)/tool.mk
