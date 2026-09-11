// passkey.js: el único script de la app de cuenta. WebAuthn sólo existe en el
// navegador (navigator.credentials), así que este fichero hace lo mínimo: lee
// las opciones que GoTrue puso en data-options, pide al navegador crear o usar
// la passkey, mete la credencial (en JSON, base64url) en el campo oculto
// «credential» y envía el formulario. Nada de red desde aquí: el servidor
// verifica contra GoTrue. Sin passkeys en la página, este script no se carga.
(function () {
  "use strict";

  function b64uToBuf(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    var pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
    var bin = atob(s + pad);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u.buffer;
  }

  function bufToB64u(b) {
    var u = new Uint8Array(b), s = "";
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // GoTrue manda los binarios en base64url (formato JSON de WebAuthn); el
  // navegador quiere ArrayBuffer. Los navegadores nuevos traen
  // parseCreationOptionsFromJSON, pero no todos: se convierte a mano.
  function preparar(pk, crear) {
    pk.challenge = b64uToBuf(pk.challenge);
    if (crear && pk.user && pk.user.id) pk.user.id = b64uToBuf(pk.user.id);
    var lista = crear ? pk.excludeCredentials : pk.allowCredentials;
    (lista || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return pk;
  }

  // Lo contrario: la credencial que devuelve el navegador, a JSON con
  // base64url, que es lo que GoTrue (go-webauthn) sabe leer. toJSON() existe
  // en los navegadores nuevos; si no, a mano.
  function serializar(cred) {
    if (typeof cred.toJSON === "function") return cred.toJSON();
    var r = cred.response;
    var out = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: { clientDataJSON: bufToB64u(r.clientDataJSON) }
    };
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64u(r.attestationObject);
      if (typeof r.getTransports === "function") out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
    }
    return out;
  }

  function mensaje(e) {
    if (e && e.name === "NotAllowedError") return "The request was cancelled or timed out. Try again.";
    if (e && e.name === "InvalidStateError") return "This device already has a passkey for this account.";
    return "That did not work" + (e && e.message ? ": " + e.message : "") + ". Try again.";
  }

  document.querySelectorAll("form[data-passkey]").forEach(function (form) {
    var go = form.querySelector("[data-passkey-go]");
    var status = form.querySelector("[data-passkey-status]");
    var campo = form.querySelector("input[name=credential]");
    if (!go || !campo) return;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      go.disabled = true;
      if (status) { status.hidden = false; status.textContent = "This browser cannot use passkeys."; }
      return;
    }
    go.addEventListener("click", function () {
      var crear = form.dataset.passkey === "create";
      go.disabled = true;
      if (status) { status.hidden = false; status.textContent = "Waiting for your device…"; }
      var opciones;
      try {
        opciones = JSON.parse(form.dataset.options);
      } catch (e) {
        if (status) status.textContent = "The page did not load correctly. Reload it.";
        return;
      }
      var pk = preparar(opciones.publicKey || opciones, crear);
      var promesa = crear ? navigator.credentials.create({ publicKey: pk }) : navigator.credentials.get({ publicKey: pk });
      promesa.then(function (cred) {
        campo.value = JSON.stringify(serializar(cred));
        if (status) status.textContent = "Checking…";
        form.submit();
      }).catch(function (e) {
        go.disabled = false;
        if (status) status.textContent = mensaje(e);
      });
    });
  });
})();
