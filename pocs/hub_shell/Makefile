TARGET := iphone:clang:latest:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = W0lfSwordHubShell
W0lfSwordHubShell_FILES = main.m AppDelegate.m engine_stubs.m hub_guard.c
W0lfSwordHubShell_FRAMEWORKS = UIKit Foundation IOKit CoreFoundation
W0lfSwordHubShell_PRIVATE_FRAMEWORKS = IOSurface
W0lfSwordHubShell_LIBRARIES = z sandbox
# L3.3: link the shared engine (kexploit + sandbox_escape + SSV + utils +
# kpf + XPF) so the app can call kexploit_opa334()/sandbox_escape()/kread64
# with the same error codes the tweak uses. Build first: make libengine
# ENGINE_LIB is overridable so a release IPA can link the NDEBUG archive
# (scripts/build_hub_ipa.sh --release) without touching the debug one.
ENGINE_LIB ?= ../../.theos/libengine/libw0lfengine.a
W0lfSwordHubShell_CFLAGS = -I../.. -I../../XPF/src -I../../XPF/external/ChOma/include
W0lfSwordHubShell_LDFLAGS = $(ENGINE_LIB)
W0lfSwordHubShell_INSTALL_PATH = /Applications

# Release parity with the tweak's A6.2/V1.3 pattern (ROADMAP L8.3):
#   FINALPACKAGE=1 -> -DNDEBUG: FAILURE() returns, KPRINTF() address-leak
#   logging compiles out of both the app and the engine archive; -Wl,-S
#   strips debug symbols. Default (no FINALPACKAGE) stays -DDEBUG.
ifeq ($(FINALPACKAGE),1)
W0lfSwordHubShell_CFLAGS += -DNDEBUG
W0lfSwordHubShell_LDFLAGS += -Wl,-S
else
W0lfSwordHubShell_CFLAGS += -DDEBUG
endif

include $(THEOS_MAKE_PATH)/application.mk
