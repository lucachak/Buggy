"use strict";

function startPolling(element) {
  if (!element || !element.dataset.pollUrl || element.dataset.polling === "true") return;
  element.dataset.polling = "true";
  const delay = Number(element.dataset.pollInterval || 2000);

  window.setTimeout(async () => {
    if (!element.isConnected) return;
    try {
      const response = await window.fetch(element.dataset.pollUrl, {
        credentials: "same-origin",
        headers: { "X-Buggy-Fragment": "1" },
        cache: "no-store"
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      if (response.headers.get("HX-Refresh") === "true") {
        window.location.reload();
        return;
      }
      const template = document.createElement("template");
      template.innerHTML = (await response.text()).trim();
      const replacement = template.content.firstElementChild;
      if (!replacement) throw new Error("empty fragment");
      element.replaceWith(replacement);
      startPolling(replacement);
    } catch (error) {
      element.dataset.polling = "false";
      element.dataset.pollError = "true";
      startPolling(element);
    }
  }, Math.max(500, delay));
}

function startAllPolling(root = document) {
  root.querySelectorAll("[data-poll-url]").forEach(startPolling);
}

document.addEventListener("DOMContentLoaded", () => startAllPolling());

function updateScanEstimate(container) {
  const rateInput = container.querySelector('[name="requests_per_minute"]');
  const estimate = container.closest("details").querySelector("[data-scan-estimate]");
  const words = Number(container.dataset.wordCount || 0);
  const rate = Number(rateInput?.value || 0);
  if (!estimate || rate <= 0) return;
  const seconds = Math.ceil(words / rate * 60);
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  estimate.textContent = `Estimativa da lista base: ${minutes} min ${remainder} s.`;
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-scan-tuning]").forEach((container) => {
    updateScanEstimate(container);
    container.querySelector('[name="requests_per_minute"]')
      ?.addEventListener("input", () => updateScanEstimate(container));
  });
});
