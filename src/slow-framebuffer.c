#include <SDL2/SDL.h>

static SDL_Window *sdlWindow;
static SDL_Renderer *sdlRenderer;
static SDL_Texture *sdlTexture;

void slowfb_init(int width, int height) {
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
