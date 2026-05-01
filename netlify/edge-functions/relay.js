const UPSTREAM_HOST = (Netlify.env.get("BACKEND_HOST") || "").replace(/\/$/, "");
const CACHE_TTL = parseInt(Netlify.env.get("CACHE_TTL") || "300", 10);

const STRIP_HEADERS = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding",
  "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto",
  "x-forwarded-port", "cf-ray", "cf-connecting-ip", "cf-visitor",
  "x-request-id", "x-request-start", "x-global-transaction-id"
]);

const CACHE_METHODS = new Set(["GET", "HEAD"]);
const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB limit

// Fast path for root or health checks
async function handleFastPath(request, url) {
  const userAgent = request.headers.get("user-agent") || "";
  const accept = request.headers.get("accept") || "";
  
  // Return minimal response for bots/analyzers
  if (userAgent.includes("bot") || userAgent.includes("scanner") || accept.includes("application/json+health")) {
    return new Response("OK", { 
      status: 200,
      headers: { "content-type": "text/plain", "cache-control": "no-store" }
    });
  }
  return null;
}

export default async function handler(request) {
  if (!UPSTREAM_HOST) {
    return new Response("Service Unavailable", { status: 503 });
  }

  try {
    const url = new URL(request.url);
    const requestPath = url.pathname + url.search;
    
    // Fast health check bypass
    const fastResult = await handleFastPath(request, url);
    if (fastResult) return fastResult;

    const targetUrl = UPSTREAM_HOST + requestPath;
    const method = request.method;
    const isCacheable = CACHE_METHODS.has(method);
    
    // Build clean headers
    const headers = new Headers();
    let clientIp = null;
    let hasForwarded = false;

    for (const [key, value] of request.headers) {
      const k = key.toLowerCase();
      if (STRIP_HEADERS.has(k)) continue;
      if (k.startsWith("x-nf-") || k.startsWith("x-netlify-")) continue;
      if (k === "x-real-ip" || k === "cf-connecting-ip") {
        clientIp = value;
        continue;
      }
      if (k === "x-forwarded-for") {
        clientIp = value;
        hasForwarded = true;
        continue;
      }
      // Essential headers only
      if (k === "accept" || k === "accept-encoding" || k === "accept-language" ||
          k === "content-type" || k === "content-length" || k === "authorization" ||
          k === "user-agent" || k === "referer" || k === "cookie") {
        headers.set(k, value);
      }
    }

    // Smart IP forwarding
    if (clientIp) {
      headers.set("x-forwarded-for", hasForwarded ? clientIp : `${clientIp}, ${request.headers.get("x-forwarded-for") || ""}`);
    }

    // Connection optimizations
    headers.set("connection", "close");
    
    const fetchOptions = {
      method,
      headers,
      redirect: "manual",
      // Performance tweaks
      cache: isCacheable ? "default" : "no-store",
      keepalive: true,
      compress: true
    };

    if (method !== "GET" && method !== "HEAD") {
      const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
      if (contentLength > MAX_BODY_SIZE) {
        return new Response("Payload Too Large", { status: 413 });
      }
      fetchOptions.body = request.body;
    }

    const upstream = await fetch(targetUrl, fetchOptions);

    // Build response with minimal overhead
    const responseHeaders = new Headers();
    
    // Pass through essential headers only
    const keepHeaders = ["content-type", "content-length", "content-encoding", 
                         "cache-control", "etag", "last-modified", "location",
                         "set-cookie", "x-robots-tag", "strict-transport-security"];
    
    for (const [key, value] of upstream.headers) {
      const k = key.toLowerCase();
      if (k === "transfer-encoding") continue;
      if (keepHeaders.includes(k) || k.startsWith("x-")) {
        responseHeaders.set(key, value);
      }
    }
    
    // Add security and performance headers
    responseHeaders.set("x-content-type-options", "nosniff");
    responseHeaders.set("cache-control", `max-age=${CACHE_TTL}, public, must-revalidate`);
    
    // Remove Server header if present
    if (responseHeaders.has("server")) responseHeaders.delete("server");

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  } catch (error) {
    // Silent fail - don't expose internal errors
    return new Response("Gateway Error", { status: 502 });
  }
}