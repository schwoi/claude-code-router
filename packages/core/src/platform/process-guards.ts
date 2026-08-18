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
 *
 * The two conditions are handled differently on purpose:
 *  - unhandledRejection: the H1 crash class (a throw inside a per-request
 *    `.catch`, e.g. writeHead-after-headers-sent) surfaces here. It is scoped to
 *    one request and recoverable, and under Node >=15 the default is to
 *    terminate, so we log and keep the daemon (and every other stream) alive.
 *  - uncaughtException: Node's guidance is that the process may be left in an
 *    inconsistent state (partially-updated structures, an interrupted
 *    auth/redaction step) and must not resume. We log and exit non-zero so the
 *    supervisor (pm2 in Docker, the desktop app, or a shell restart loop)
 *    restarts a clean process instead of continuing corrupt.
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
    process.stderr.write(`[ccr] Uncaught exception; exiting for a clean supervised restart: ${error.stack ?? error.message}\n`);
    process.exit(1);
  });
}
