/* Host shim: kexploit/kutils.h includes <mach/mach.h>, which does not exist on
 * Linux. The shell's host test only needs the kernel helper PROTOTYPES, so the
 * handful of Mach types those prototypes mention are declared here; the
 * definitions come from tests/trm_shell_host_test.c. Not used by the tweak
 * build (the real iOS SDK headers are on the include path there). */
#pragma once

typedef unsigned int   mach_port_t;
typedef int            kern_return_t;
typedef unsigned long long mach_vm_address_t;
typedef unsigned long long mach_vm_size_t;
typedef unsigned int   mach_vm_prot_t;
