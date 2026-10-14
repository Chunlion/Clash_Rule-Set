export default {
  async fetch(request, env) {
    const headers = {
      "Cache-Control": "private, no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    };
    const url = new URL(request.url);
    if (url.pathname !== "/egern.yaml") {
      return new Response("Not found", { status: 404, headers });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { ...headers, Allow: "GET, HEAD" },
      });
    }
    const keys = url.searchParams.getAll("key");
    if (!env.DOWNLOAD_TOKEN || keys.length !== 1 || keys[0] !== env.DOWNLOAD_TOKEN) {
      return new Response("Forbidden", { status: 403, headers });
    }
    try {
      const object = await env.CONFIG_BUCKET.get("egern.yaml");
      if (!object) {
        return new Response("Not found", { status: 404, headers });
      }
      headers["Content-Type"] = "application/yaml; charset=utf-8";
      return new Response(request.method === "HEAD" ? null : object.body, { headers });
    } catch {
      return new Response("Temporarily unavailable", { status: 503, headers });
    }
  },
};
