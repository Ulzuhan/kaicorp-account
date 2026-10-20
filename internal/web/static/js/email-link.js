// email-link.js: una capacidad de correo llega en el fragmento, que nunca se
// envía por HTTP. Este script la mueve al formulario protegido por CSRF y
// sustituye de inmediato la entrada de historial por la URL sin fragmento.
(function () {
  "use strict";

  var form = document.querySelector("form[data-email-capability]");
  if (!form) return;

  var fieldName = form.getAttribute("data-email-capability");
  var field = form.querySelector('input[name="' + fieldName + '"]');
  var submit = form.querySelector("[data-email-capability-submit]");
  var error = form.querySelector("[data-email-capability-error]");
  var token = "";

  try {
    var fragment = window.location.hash.slice(1);
    var parts = fragment.split("&");
    if (parts.length === 1) {
      var separator = parts[0].indexOf("=");
      if (separator > 0 && decodeURIComponent(parts[0].slice(0, separator)) === fieldName) {
        token = decodeURIComponent(parts[0].slice(separator + 1));
      }
    }
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  } catch (_) {
    token = "";
  }

  if (!field || !submit || token === "" || token.length > 8192 || /[\u0000-\u001f\u007f]/.test(token)) {
    if (error) error.hidden = false;
    return;
  }

  field.value = token;
  submit.disabled = false;
}());
