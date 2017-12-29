Framebuffer memory notes
=========================

The framebuffer is BGRA8888 format. It likely uses 16x16 tiles (TODO:
verify). There is a stride of zeroes every 1856 bytes for unknown
reasons.

---

Zeroes at:

1345548
1347404
1349260
1351116

Deltas of 1856 between zero regions; groups of 1804 valid pixels in
between

2048 = 1856 + 4 * 48?
