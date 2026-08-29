# ADR 0001 - ICMPv6 Socket Spray for Kernel Heap Manipulation

**Status:** Accepted  
**Date:** 2025 (inherited from DarkSword)  

---

## Context

The kernel exploit needs to place controlled data at predictable physical addresses
to enable the IOSurface OOB primitive. The XNU zone allocator (zalloc) for `inpcb`
structures exhibits deterministic allocation patterns when the zone is exhausted.

## Decision

Use ICMPv6 sockets for the spray because:
1. ICMPv6 sockets allocate `inpcb` structures in a dedicated zone
2. Creating ~10,000 sockets exhausts the zone, forcing predictable layout
3. `getsockopt(ICMP6_FILTER)` provides a kernel read primitive
4. `setsockopt(ICMP6_FILTER)` provides a kernel write primitive
5. Each socket PCB has a generation counter (`inp_gencnt`) for identification

## Alternatives Considered

- **TCP socket spray** - larger PCB size, different zone, slower allocation
- **UDP socket spray** - smaller PCB, but fewer interesting fields to corrupt
- **Pipe spray** - different allocator, harder to identify in physical scans

## Consequences

- **Pro:** ICMPv6 sockets are lightweight and can be created rapidly
- **Pro:** The `in6p_icmp6filt` pointer is an ideal corruption target
- **Con:** Socket creation is rate-limited by file descriptor limits (ulimit -n)
- **Con:** Zone allocator changes in new iOS versions could break determinism
- **Con:** MTE (A19+) will tag all heap allocations, breaking fake PCB objects
