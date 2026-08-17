/**
 * Process-level backstops for long-running server entrypoints.
 *
 * The gateway/proxy handle concurrent streaming responses inside
 * `void handler(...).catch(...)` wrappers. If an error escapes such a handler
 * after a response has already started, the catch can itself throw
 * (ERR_HTTP_HEADERS_SENT), producing an unhandled rejection. Under Node's
 * defaults an unhandled rejection terminates the process — taking every
 * concurrent stream down with it. Individual handlers are hardened to avoid
 * this (see sendErrorResponse / sendProxyError), but a single missed edge must
 * not kill the whole daemon, so we install a logging backstop here.
 */
let installed = false;

export function installProcessErrorGuards(): void {
  if (installed) {
    return;
  }
  installed = true;

  process.on("unhandledRejection", (reason) => {
    const message = reason instanceof Error ? reason.stack ?? reason.message : String(reason);
    process.stderr.write(`[ccr] Unhandled promise rejection (kept alive): ${message}\n`);
  });

  process.on("uncaughtException", (error) => {
    process.stderr.write(`[ccr] Uncaught exception (kept alive): ${error.stack ?? error.message}\n`);
  });
}
