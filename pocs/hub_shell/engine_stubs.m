// engine_stubs.m — TweakExploit.h UI callbacks referenced by the engine
// (kexploit_opa334.m) but excluded from libw0lfengine (tweak-only file,
// ROADMAP L2.2). The hub app provides no-op stubs; a future L6.1 exploit
// runner can replace these with live HUD updates.
#include "TweakExploit.h"

void tweak_exploit_set_cycle(int c) { (void)c; }
void tweak_exploit_set_status(int s) { (void)s; }
int tweak_exploit_status(void) { return 0; }
int tweak_exploit_attempt(void) { return 0; }
int tweak_exploit_cycle(void) { return 0; }
