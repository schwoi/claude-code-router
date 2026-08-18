/**
 * Extracted from gateway/service.ts. Keep this module focused on its named gateway boundary.
 */
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from "node:http";
import type { ApiKeyConfig } from "@ccr/core/contracts/app";
import { ccrRemoteControlPathPrefix } from "@ccr/core/gateway/remote-control-service";
import { coreGatewayAuthHeader, localObservabilityHeaderNames, proxyHeaderDenyList, responseHeaderDenyList } from "@ccr/core/gateway/internal/shared";


export function inferGatewayClient(apiKey: ApiKeyConfig | undefined, headers: IncomingHttpHeaders): string | undefined {
  const explicit =
    readHeader(headers["x-ccr-client"]) ??
    readHeader(headers["x-client-name"]) ??
    readHeader(headers["x-forwarded-client-cert"]);
  if (explicit) {
    return explicit;
  }

  const apiKeyClient = apiKey?.name?.trim() || apiKey?.id?.trim();
  const userAgentClient = inferClientFromUserAgent(headers);
  if (readHeader(headers["x-ccr-proxy-mode"]) === "gateway") {
    return userAgentClient ?? apiKeyClient;
  }
  return apiKeyClient ?? userAgentClient;
}


function inferClientFromUserAgent(headers: IncomingHttpHeaders): string | undefined {
  const userAgent = readHeader(headers["user-agent"]);
  if (!userAgent) {
    return undefined;
  }

  const normalized = userAgent.toLowerCase();
  if (normalized.includes("codex")) {
    return "Codex";
  }
  if (normalized.includes("@anthropic-ai/claude-code") || normalized.includes("claude-code") || normalized.includes("claude code")) {
    return "Claude Code";
  }
  if (normalized.includes("claude")) {
    return "Claude";
  }
  if (normalized.includes("curl")) {
    return "curl";
  }
  if (normalized.includes("python")) {
    return "Python";
  }
  if (normalized.includes("node")) {
    return "Node.js";
  }
  if (normalized.includes("chrome")) {
    return "Google Chrome";
  }
  if (normalized.includes("safari") && !normalized.includes("chrome")) {
    return "Safari";
  }
  return userAgent.split(/[ /]/)[0]?.trim() || undefined;
}


export function readAuthToken(headers: IncomingHttpHeaders): string | undefined {
  const raw = readHeader(headers.authorization) || readHeader(headers["x-api-key"]);
  if (!raw) {
    return undefined;
  }
  return raw.toLowerCase().startsWith("bearer ") ? raw.slice(7).trim() : raw;
}


export function readRemoteControlQueryAuthToken(request: IncomingMessage): string | undefined {
  const url = new URL(request.url || "/", "http://127.0.0.1");
  if (url.pathname !== ccrRemoteControlPathPrefix && !url.pathname.startsWith(`${ccrRemoteControlPathPrefix}/`)) {
    return undefined;
  }
  return url.searchParams.get("api_key")?.trim() || url.searchParams.get("key")?.trim() || undefined;
}


export function forwardHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const forwarded: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const normalized = key.toLowerCase();
    if (proxyHeaderDenyList.has(normalized) || value === undefined) {
      continue;
    }
    forwarded[normalized] = Array.isArray(value) ? value.join(",") : String(value);
  }
  return forwarded;
}


export function stripLocalGatewayAuthHeaders(headers: Record<string, string>): void {
  delete headers.authorization;
  delete headers["x-api-key"];
  delete headers["api-key"];
}


export function omitLocalObservabilityHeaders(headers: Record<string, string>): Record<string, string> {
  const forwarded = { ...headers };
  for (const name of localObservabilityHeaderNames) {
    delete forwarded[name];
  }
  return forwarded;
}


export function withCoreGatewayAuthHeader(headers: Record<string, string>, token: string): Record<string, string> {
  if (!token) {
    throw new Error("Core gateway auth token is not initialized.");
  }
  return {
    ...headers,
    [coreGatewayAuthHeader]: token
  };
}


export function filteredResponseHeaders(headers: Headers): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  headers.forEach((value, key) => {
    if (!responseHeaderDenyList.has(key.toLowerCase())) {
      entries.push([key, value]);
    }
  });
  return entries;
}


export function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}


/**
 * Send a JSON error response safely from a top-level request handler catch.
 *
 * If the response has already begun (headers sent), writing a fresh status line
 * throws ERR_HTTP_HEADERS_SENT — and because these handlers run inside a
 * `void promise.catch(...)`, that throw becomes an unhandled rejection that can
 * take down the whole process. In that case we can only destroy the socket.
 */
export function sendErrorResponse(response: ServerResponse, status: number, error: unknown): void {
  if (response.headersSent || response.writableEnded) {
    response.destroy(error instanceof Error ? error : new Error(formatError(error)));
    return;
  }
  // Honor a status code carried on the error (e.g. 400 for malformed JSON, 413
  // for an over-size body) instead of always reporting the caller's default.
  const resolvedStatus = error instanceof HttpRequestError ? error.statusCode : status;
  try {
    const body = JSON.stringify({ error: { message: formatError(error) } });
    response.writeHead(resolvedStatus, { "content-type": "application/json" });
    response.end(body);
  } catch {
    response.destroy(error instanceof Error ? error : undefined);
  }
}


/** Error carrying the HTTP status the top-level handler should report. */
export class HttpRequestError extends Error {
  readonly statusCode: number;
  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpRequestError";
    this.statusCode = statusCode;
  }
}

/** Largest request body the gateway will buffer before replying 413. */
export const maxRequestBodyBytes = (() => {
  const raw = Number(process.env.CCR_MAX_REQUEST_BODY_BYTES);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 100 * 1024 * 1024;
})();


export type UpstreamErrorLogContext = {
  attempts: number;
  elapsedMs: number;
  fallbackFailures: number;
  operation: "fetch" | "stream";
  responseStarted: boolean;
  retryDelayMs?: number;
};


export function formatUpstreamErrorForLog(error: unknown, context: UpstreamErrorLogContext): string {
  const chain = collectErrorChain(error);
  const outer = chain[0];
  const cause = chain[chain.length - 1] ?? outer;
  const code = firstErrorProperty(chain, "code");
  const errno = firstErrorProperty(chain, "errno");
  const syscall = firstErrorProperty(chain, "syscall");
  const message = redactUpstreamCredentialValues(outer?.message || formatError(error)) || "Unknown upstream error";
  const causeMessage = redactUpstreamCredentialValues(cause?.message || "");
  const phase = inferUpstreamErrorPhase({
    code,
    message: `${message} ${causeMessage}`,
    name: cause?.name,
    responseStarted: context.responseStarted,
    syscall
  });
  const fields = [
    `cause=${normalizeDiagnosticValue(cause?.name || "UnknownError")}`,
    code ? `code=${normalizeDiagnosticValue(code)}` : undefined,
    errno ? `errno=${normalizeDiagnosticValue(errno)}` : undefined,
    syscall ? `syscall=${normalizeDiagnosticValue(syscall)}` : undefined,
    `phase=${phase}`,
    `response_started=${context.responseStarted}`,
    `attempts=${Math.max(1, Math.trunc(context.attempts))}`,
    `fallback_failures=${Math.max(0, Math.trunc(context.fallbackFailures))}`,
    `retry_delay_ms=${Math.max(0, Math.trunc(context.retryDelayMs ?? 0))}`,
    `elapsed_ms=${Math.max(0, Math.trunc(context.elapsedMs))}`,
    !code && causeMessage && causeMessage !== message ? `detail=${JSON.stringify(causeMessage)}` : undefined
  ].filter((field): field is string => Boolean(field));
  return `Upstream ${context.operation} failed: ${message} [${fields.join("; ")}]`;
}


type ErrorChainItem = {
  error: object;
  message?: string;
  name?: string;
};


function collectErrorChain(error: unknown): ErrorChainItem[] {
  const chain: ErrorChainItem[] = [];
  const seen = new Set<object>();
  let current = error;
  for (let depth = 0; depth < 6 && isObject(current) && !seen.has(current); depth += 1) {
    seen.add(current);
    chain.push({
      error: current,
      message: typeof readErrorProperty(current, "message") === "string"
        ? String(readErrorProperty(current, "message"))
        : undefined,
      name: typeof readErrorProperty(current, "name") === "string"
        ? String(readErrorProperty(current, "name"))
        : undefined
    });
    current = readErrorProperty(current, "cause");
  }
  return chain;
}


function firstErrorProperty(chain: ErrorChainItem[], key: "code" | "errno" | "syscall"): string | undefined {
  for (const item of chain) {
    const value = readErrorProperty(item.error, key);
    if (typeof value === "string" || typeof value === "number") {
      const normalized = String(value).trim();
      if (normalized) {
        return normalized;
      }
    }
  }
  return undefined;
}


function inferUpstreamErrorPhase(input: {
  code?: string;
  message: string;
  name?: string;
  responseStarted: boolean;
  syscall?: string;
}): "aborted" | "connect" | "dns" | "fetch" | "response_body" | "response_headers" | "tls" {
  const signature = `${input.code ?? ""} ${input.name ?? ""} ${input.message} ${input.syscall ?? ""}`.toUpperCase();
  if (/ABORT|CANCEL/.test(signature)) return "aborted";
  if (/ENOTFOUND|EAI_AGAIN|DNS/.test(signature)) return "dns";
  if (/CERT|TLS|SSL|EPROTO/.test(signature)) return "tls";
  if (/HEADERS?_TIMEOUT|RESPONSE_HEADERS|WAITING FOR HEADERS/.test(signature)) return "response_headers";
  if (/BODY_TIMEOUT|RESPONSE_BODY/.test(signature)) return "response_body";
  if (/ECONNRESET|EPIPE|UND_ERR_SOCKET/.test(signature)) {
    return input.responseStarted ? "response_body" : "connect";
  }
  if (/CONNECT|ECONNREFUSED|ETIMEDOUT/.test(signature)) return "connect";
  return input.responseStarted ? "response_body" : "fetch";
}


function redactUpstreamCredentialValues(value: string): string {
  return value
    .replace(/(\b(?:https?|wss?):\/\/[^/\s:@]+:)[^@\s/]+@/gi, "$1[redacted]@")
    .replace(/([?&](?:api[-_]?key|key|token|access[-_]?token|refresh[-_]?token|client[-_]?secret|auth|authorization|password)=)[^&\s#]*/gi, "$1[redacted]")
    .replace(/"((?:proxy[-_])?authorization|(?:x[-_](?:[a-z0-9]+[-_])*)?api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|token|password)"\s*:\s*"(?:\\.|[^"\\])*"/gi, '"$1":"[redacted]"')
    .replace(/\b((?:proxy[-_])?authorization)\s*([:=])\s*(?:(?:Bearer|Basic)\s+)?[^\s,;&#]+/gi, "$1$2[redacted]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [redacted]")
    .replace(/\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}/gi, "[redacted-secret]")
    .replace(/\b((?:x[-_](?:[a-z0-9]+[-_])*)?api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|token|password)\s*([:=])\s*(?:"[^"]*"|'[^']*'|[^\s,;&#"']+)/gi, "$1$2[redacted]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 240);
}


function normalizeDiagnosticValue(value: string): string {
  const normalized = value.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 80);
  return normalized || "unknown";
}


function readErrorProperty(error: object, key: string): unknown {
  try {
    return (error as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}


function isObject(value: unknown): value is object {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}


export function abortSignalMessage(signal: AbortSignal): string {
  const reason = signal.reason as unknown;
  if (reason instanceof Error && reason.message) {
    return reason.message;
  }
  if (typeof reason === "string" && reason.trim()) {
    return reason.trim();
  }
  return "Upstream request was aborted.";
}


export function parseJsonObject(buffer: Buffer): Record<string, unknown> {
  if (buffer.length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(buffer.toString("utf8")) as unknown;
  } catch {
    // Malformed client JSON is a client error, not a gateway (502) failure.
    throw new HttpRequestError(400, "Request body is not valid JSON.");
  }
  if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
    return parsed as Record<string, unknown>;
  }
  throw new HttpRequestError(400, "Request body must be a JSON object.");
}


export function readHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0]?.trim();
  }
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}


export function readRequestBody(request: IncomingMessage, maxBytes = maxRequestBodyBytes): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    request.on("data", (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buffer.length;
      if (total > maxBytes) {
        // Stop buffering an unbounded body before it exhausts memory.
        request.destroy();
        reject(new HttpRequestError(413, `Request body exceeds ${maxBytes} bytes.`));
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}


export function sendJson(response: ServerResponse, statusCode: number, payload: unknown): void {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(`${JSON.stringify(payload)}\n`);
}


export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      if (timeout) {
        clearTimeout(timeout);
      }
      resolve();
    };

    try {
      server.closeIdleConnections?.();
      timeout = setTimeout(() => {
        server.closeAllConnections?.();
        finish();
      }, 800);
      server.close(() => finish());
    } catch {
      finish();
    }
  });
}


export function shouldSendBody(method: string | undefined): boolean {
  const normalized = method?.toUpperCase();
  return normalized !== "GET" && normalized !== "HEAD";
}


export function shouldCaptureGatewayUsage(method: string, _path: string): boolean {
  return shouldSendBody(method);
}
