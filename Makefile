TARGET := iphone:clang:latest:15.0
ARCHS = arm64
# Rootless (Dopamine) install target. NOTE: don't use THEOS_PACKAGE_SCHEME=
# rootless here — this Theos build's scheme-staging mv in package/deb.mk is
# broken (parse-time $(shell mv) runs before the stage exists → empty deb
# layout). INSTALL_PATH achieves the same /var/jb layout without the scheme;
# ElleKit's substrate shim resolves the classic substrate load path at runtime.
FilzaApplySandboxExt_INSTALL_PATH = /var/jb/Library/MobileSubstrate/DynamicLibraries

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaApplySandboxExt

# --- Tweak + sandbox escape ---
# FilzaPadlockBypass.xm uses Logos %hook → links CydiaSubstrate from
# /var/jb. On the non-jailbroken MHA path that path doesn't exist, so dyld
# would refuse the injected dylib and Filza wouldn't launch. MHA builds
# drop the padlock bypass (UI edit affordances only; browsing + the kernel
# escape don't need it).
ifeq ($(MHA_IDENTITY),1)
FilzaApplySandboxExt_FILES = Tweak.m sandbox_escape.m TweakExploit.m
else
FilzaApplySandboxExt_FILES = Tweak.m sandbox_escape.m TweakExploit.m FilzaPadlockBypass.xm
endif

# --- kexploit ---
FilzaApplySandboxExt_FILES += kexploit/kexploit_opa334.m kexploit/krw.m kexploit/kutils.m kexploit/offsets.m kexploit/vnode.m kexploit/file.m kexploit/vnode_research.m kexploit/sandbox.m kexploit/Exception.m kexploit/Thread.m kexploit/VM.m kexploit/MigFilterBypassThread.m kexploit/RemoteCall.m kexploit/PAC.m kexploit/mcm_bridge.m kexploit/container_access.m kexploit/bad_query_escape.m 

# --- SSV Bypass ---
FilzaApplySandboxExt_FILES += SSV/SSVUtils.m

# --- utils ---
FilzaApplySandboxExt_FILES += utils/hexdump.c utils/process.c utils/permission_utils.m utils/state.m utils/tweak_log.m

# --- kpf ---
FilzaApplySandboxExt_FILES += kpf/patchfinder.m

# --- XPF ---
FilzaApplySandboxExt_FILES += XPF/src/xpf.c XPF/src/common.c XPF/src/decompress.c XPF/src/bad_recovery.c XPF/src/non_ppl.c XPF/src/ppl.c

# --- Filza Padlock Bypass ---
# (excluded on MHA builds — see the FILES conditional above: the Logos
# %hook generates a hard CydiaSubstrate dependency, and /var/jb doesn't
# exist on a non-jailbroken device, so dyld would reject the dylib)
ifneq ($(MHA_IDENTITY),1)
FilzaApplySandboxExt_FILES += FilzaPadlockBypass.xm
endif

# --- ChOma ---
FilzaApplySandboxExt_FILES += XPF/external/ChOma/src/arm64.c XPF/external/ChOma/src/Base64.c XPF/external/ChOma/src/BufferedStream.c XPF/external/ChOma/src/CodeDirectory.c XPF/external/ChOma/src/CSBlob.c XPF/external/ChOma/src/DER.c XPF/external/ChOma/src/DyldSharedCache.c XPF/external/ChOma/src/Entitlements.c XPF/external/ChOma/src/Fat.c XPF/external/ChOma/src/FileStream.c XPF/external/ChOma/src/Host.c XPF/external/ChOma/src/MachO.c XPF/external/ChOma/src/MachOLoadCommand.c XPF/external/ChOma/src/MemoryStream.c XPF/external/ChOma/src/PatchFinder.c XPF/external/ChOma/src/PatchFinder_arm64.c XPF/external/ChOma/src/Util.c

# --- Flags ---
FilzaApplySandboxExt_CFLAGS = -I$(PWD) -I$(PWD)/XPF/src -I$(PWD)/XPF/external/ChOma/include \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable \
    -Wno-incompatible-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers \
    -Wno-deprecated-declarations -Wno-nonportable-include-path -Wno-format

# Release builds (make package FINALPACKAGE=1 DEBUG=0):
#   -DNDEBUG        FAILURE() returns instead of exit() (A6.1)
#   no -DDEBUG      KPRINTF() address-leak logging compiles out entirely (A6.2)
#   -Wl,-S          strip debug symbols from the dylib
ifeq ($(FINALPACKAGE),1)
FilzaApplySandboxExt_CFLAGS += -DNDEBUG
FilzaApplySandboxExt_LDFLAGS += -Wl,-S
else
FilzaApplySandboxExt_CFLAGS += -DDEBUG
endif

# MHA identity build (K4.12): re-signed Filza running as
# com.apple.mobile.MobileHouseArrest gets pre-exploit container access.
# Use:  make mha IPA=/path/Filza.ipa [OUT=Filza-MHA.ipa]
ifeq ($(MHA_IDENTITY),1)
FilzaApplySandboxExt_CFLAGS += -DMHA_IDENTITY
# Classic bind opcodes, NOT chained fixups (LC_DYLD_CHAINED_FIXUPS).
# Sideload re-signers (PlumeImpactor/AltStore) don't understand chained
# fixups and corrupt the LINKEDIT; dyld then dies at launch with
# "bad bind opcode 0xFF". -no_fixup_chains forces LC_DYLD_INFO_ONLY with
# classic bind info that every signer handles.
FilzaApplySandboxExt_LDFLAGS += -Wl,-no_fixup_chains
endif

MHA_DYLIB ?= $(shell ls .theos/obj/debug/arm64/FilzaApplySandboxExt.dylib 2>/dev/null || ls .theos/obj/arm64/FilzaApplySandboxExt.dylib 2>/dev/null || echo "")
mha:
	$(MAKE) package MHA_IDENTITY=1
	@test -n "$(MHA_DYLIB)" || { echo "  ✗ built dylib not found"; exit 1; }
	@test -n "$(IPA)" || { echo "  ✗ usage: make mha IPA=/path/Filza.ipa [OUT=Filza-MHA.ipa]"; exit 1; }
	bash scripts/re-sign_mha.sh "$(IPA)" "$(MHA_DYLIB)" "$(OUT)"

# L2.2 — engine extraction: kexploit/sandbox/SSV/utils/kpf/XPF (no tweak-only
# files) as a standalone static lib for the W0lfSword Hub app. Same CFLAGS as
# the tweak. Output: .theos/libengine/libw0lfengine.a
libengine:
	bash scripts/build_libengine.sh

# L3.1 — build-time offsets.json for the Hub app (cumulative offset table per
# iOS threshold, parsed from kexploit/offsets.m). Bundled at
# pocs/hub_shell/Resources/offsets.json.
offsets-json:
	python3 scripts/gen_offsets_json.py

FilzaApplySandboxExt_CCFLAGS = $(FilzaApplySandboxExt_CFLAGS)
FilzaApplySandboxExt_OBJCFLAGS = $(FilzaApplySandboxExt_CFLAGS)
FilzaApplySandboxExt_OBJCCFLAGS = $(FilzaApplySandboxExt_CFLAGS)

FilzaApplySandboxExt_FRAMEWORKS = UIKit Foundation IOKit CoreFoundation
FilzaApplySandboxExt_PRIVATE_FRAMEWORKS = IOSurface
FilzaApplySandboxExt_LIBRARIES = z sandbox

FilzaApplySandboxExt_INSTALL_TARGET_PROCESSES = Filza

include $(THEOS_MAKE_PATH)/tweak.mk
