#include <X11/Xlib.h>
#include <stdint.h>

Display *d;
Window w;
XImage *image;
GC gc;

void slowfb_init(uint8_t *framebuffer, int width, int height) {
	d = XOpenDisplay(NULL);
	int black = BlackPixel(d, DefaultScreen(d));
	w = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 200, 100, 0, black, black);
	XSelectInput(d, w, StructureNotifyMask);
	XMapWindow(d, w);
	gc = XCreateGC(d, w, 0, NULL);
	for (;;) {
		XEvent e;
		XNextEvent(d, &e);
		if (e.type == MapNotify) break;
	}
	image = XCreateImage(d, DefaultVisual(d, 0), 24, ZPixmap, 0, framebuffer, width, height, 32, 0);
}
void slowfb_update(uint8_t *framebuffer, int width, int height) {
	XPutImage(d, w, gc, image, 0, 0, 0, 0, width, height);
}
