import { app, session as electronSession, type Session } from "electron";

/**
 * Deny-by-default permission handling for every Electron session.
 *
 * The built-in browser and web-search/plugin partitions load arbitrary web
 * pages (and can be steered there by prompt-injected automation). With no
 * handler registered, Electron auto-approves permission requests, so a page
 * could silently obtain getUserMedia (camera/mic), geolocation, HID/serial/USB,
 * etc. The management UI and login browser do not need any of these, so we deny
 * all web-content permission requests.
 */
function applyDenyByDefaultPermissions(session: Session): void {
  session.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  session.setPermissionCheckHandler(() => false);
}

export function installDenyByDefaultSessionPermissions(): void {
  // Cover the default session and every partition created later.
  applyDenyByDefaultPermissions(electronSession.defaultSession);
  app.on("session-created", (session) => {
    applyDenyByDefaultPermissions(session);
  });
}
