import { onRequest } from './functions/api/[[route]].js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const context = {
        request, env, params: {},
        next: () => new Response('Not Found', { status: 404 }),
        waitUntil: (promise) => ctx.waitUntil(promise),
        passThroughOnException: () => {}
      };
      return onRequest(context);
    }
    return env.ASSETS.fetch(request);
  }
};
