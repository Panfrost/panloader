#ifdef USE_SDL_FRAMEBUFFER

#include <SDL2/SDL.h>

static SDL_Window *sdlWindow;
static SDL_Renderer *sdlRenderer;
static SDL_Texture *sdlTexture;

void slowfb_init(uint32_t *framebuffer, int width, int height) {
	SDL_Init(SDL_INIT_VIDEO);
	SDL_CreateWindowAndRenderer(width, height, 0, &sdlWindow, &sdlRenderer);
	sdlTexture = SDL_CreateTexture(sdlRenderer,
				       SDL_PIXELFORMAT_ARGB8888,
				       SDL_TEXTUREACCESS_STREAMING,
				       width, height);
}

void slowfb_update(uint8_t *framebuffer, int width, int height) {
	SDL_UpdateTexture(sdlTexture, NULL, framebuffer, width * sizeof (uint32_t));
	SDL_RenderCopy(sdlRenderer, sdlTexture, NULL, NULL);
	SDL_RenderPresent(sdlRenderer);
}

#else

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

#endif
