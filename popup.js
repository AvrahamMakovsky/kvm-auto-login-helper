// KVM Auto Login Helper popup
// Author: Avraham Makovsky

(() => {
  "use strict";

  const DEFAULT_CONFIG = {
    username: "",
    password: "",
    enabled: false,
    allowedHostPatterns: "192.168.*\n10.*"
  };

  function getElement(id) {
    return document.getElementById(id);
  }

  function showStatus(message, type = "success") {
    const status = getElement("status");
    status.textContent = message;
    status.className = `status ${type}`;

    setTimeout(() => {
      status.textContent = "";
      status.className = "";
    }, 3000);
  }

  function loadSettings() {
    chrome.storage.local.get(DEFAULT_CONFIG, (config) => {
      getElement("username").value = config.username || "";
      getElement("password").value = config.password || "";
      getElement("enabled").checked = Boolean(config.enabled);
      getElement("allowed-host-patterns").value = config.allowedHostPatterns || DEFAULT_CONFIG.allowedHostPatterns;
    });
  }

  function saveSettings() {
    const config = {
      username: getElement("username").value.trim(),
      password: getElement("password").value,
      enabled: getElement("enabled").checked,
      allowedHostPatterns: getElement("allowed-host-patterns").value.trim() || DEFAULT_CONFIG.allowedHostPatterns
    };

    chrome.storage.local.set(config, () => {
      if (chrome.runtime.lastError) {
        showStatus(`Save failed: ${chrome.runtime.lastError.message}`, "error");
        return;
      }

      showStatus("Settings saved.", "success");
    });
  }

  function tryManualLogin() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs && tabs[0];

      if (!activeTab || !activeTab.id) {
        showStatus("No active tab found.", "error");
        return;
      }

      chrome.tabs.sendMessage(activeTab.id, { action: "manualLogin" }, (response) => {
        if (chrome.runtime.lastError) {
          showStatus("This tab is not available to the extension.", "error");
          return;
        }

        if (response && response.success) {
          showStatus("Login submitted.", "success");
        } else {
          showStatus("Login was not submitted on this tab.", "error");
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadSettings();
    getElement("save").addEventListener("click", saveSettings);
    getElement("manual-login").addEventListener("click", tryManualLogin);
  });
})();
