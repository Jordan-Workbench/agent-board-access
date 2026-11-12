"use strict";
(async () => {
  const status = document.getElementById("status");
  try {
    const response = await fetch("./endpoint.json?fresh=" + crypto.randomUUID(), {cache: "no-store", credentials: "omit", redirect: "error"});
    if (!response.ok) throw new Error("Discovery unavailable");
    const envelope = await response.json(), payload = envelope.payload;
    const decode = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const publicKey = document.querySelector('meta[name="discovery-key"]').content;
    const key = await crypto.subtle.importKey("raw", decode(publicKey), {name:"Ed25519"}, false, ["verify"]);
    const bytes = new TextEncoder().encode(JSON.stringify(payload, Object.keys(payload).sort()));
    if (!await crypto.subtle.verify("Ed25519", key, decode(envelope.signature), bytes)) throw new Error("Signature mismatch");
    if (payload.schema !== 1 || Date.parse(payload.expires_at) <= Date.now()) throw new Error("Discovery expired");
    const target = new URL(payload.board_url);
    if (target.protocol !== "https:" || !/^[a-z0-9-]{1,63}\.trycloudflare\.com$/.test(target.hostname) ||
        target.username || target.password || target.search || target.hash || target.port || target.pathname !== "/apps/deck/board/2") throw new Error("Invalid destination");
    if (payload.mcp_url !== target.origin + "/mcp") throw new Error("Origin mismatch");
    document.getElementById("board").href = target.href;
    window.location.replace(target.href);
  } catch (_) {
    status.textContent = "Automatic access is updating or unavailable in this browser. You can use the last verified board link below.";
  }
})();
