#include <stdio.h>

/* For dummy framebuffer */
#include "pandev.h"

int main(int argc, char **argv) {
	uint32_t memory_17[64] = {0};

	/* Exercept from the real dump */
	memory_17[0] = 0xff00;
	memory_17[1] = 0xff000000;
	memory_17[2] = 0xffff;
	memory_17[3] = 0xffff0000;
	memory_17[4] = 0xffff;
	memory_17[5] = 0xffff0000;
	memory_17[6] = 0xff00;
	memory_17[7] = 0xff000000;
	memory_17[8] = 0xffff00;
	memory_17[9] = 0xff0000ff;
	memory_17[10] = 0xff;
	memory_17[11] = 0xff0000;
	memory_17[12] = 0xff;
	memory_17[13] = 0xff0000;
	memory_17[14] = 0xffff00;
	memory_17[15] = 0xff0000ff;

	/* Display it with fake frame to see what's up */
	slowfb_init((uint8_t*) memory_17, 8, 2);
	slowfb_update((uint8_t*) memory_17, 8, 2);
	for(;;);
}
