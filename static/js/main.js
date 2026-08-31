// main.js
// Small shared front-end helpers for the Web Application Security Scanner UI.
// Page-specific behavior (progress polling, search/filter) lives inline in
// each template's {% block scripts %} for clarity.

document.addEventListener('DOMContentLoaded', function () {
  // Auto-dismiss flash alerts after a few seconds
  document.querySelectorAll('.alert').forEach(function (alertEl) {
    setTimeout(function () {
      if (window.bootstrap) {
        const alert = window.bootstrap.Alert.getOrCreateInstance(alertEl);
        alert.close();
      }
    }, 6000);
  });
});
