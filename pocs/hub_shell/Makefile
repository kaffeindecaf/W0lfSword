TARGET := iphone:clang:latest:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = W0lfSwordHubShell
W0lfSwordHubShell_FILES = main.m AppDelegate.m engine_stubs.m
W0lfSwordHubShell_FRAMEWORKS = UIKit Foundation IOKit CoreFoundation
W0lfSwordHubShell_PRIVATE_FRAMEWORKS = IOSurface
W0lfSwordHubShell_LIBRARIES = z sandbox
# L3.3: link the shared engine (kexploit + sandbox_escape + SSV + utils +
# kpf + XPF) so the app can call kexploit_opa334()/sandbox_escape()/kread64
# with the same error codes the tweak uses. Build first: make libengine
W0lfSwordHubShell_CFLAGS = -I../.. -I../../XPF/src -I../../XPF/external/ChOma/include -DDEBUG
W0lfSwordHubShell_LDFLAGS = ../../.theos/libengine/libw0lfengine.a
W0lfSwordHubShell_INSTALL_PATH = /Applications

include $(THEOS_MAKE_PATH)/application.mk
