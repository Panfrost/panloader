Coarse job descriptor memory map
================================

E000 (refreshed -- 0x340)
E040 (descriptor)
E060 (VERTEX)
E120 (referenced in VERTEX)
E140 (referenced in TILER)
E170 (referenced in VERTEX + TILER)
E180 (descriptor)
E1A0 (TILER)
E280 (refreshed -- 0x80)
E300 (descriptor set)
E320 (SET_VALUE)
E340 (refreshed -- 0x80)
E380 (descriptor)
E3A0 (FRAGMENT)
E3C0 (soft job chain, refreshed -- 0x28)

Conclusions:

FRAGMENT    <= 32  bytes
SET_VALUE   <= 32  bytes
VERTEX	    <= 192 bytes
TILER	    <= 224 bytes
