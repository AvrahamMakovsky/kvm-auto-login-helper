// KVM Auto Login Helper
// Author: Avraham Makovsky
// Purpose: Auto-fill normal authenticated KVM login forms on approved local lab hosts.
// Security note: This does not bypass authentication. It submits credentials supplied by the user.

(() => {
  "use strict";

  const DEFAULT_CONFIG = {
    username: "",
    password: "",
    enabled: false,
    allowedHostPatterns: "192.168.*\n10.*"
  };

  let config = { ...DEFAULT_CONFIG };
  let loginSubmitted = false;
  let monitorIntervalId = null;
  let observer = null;

  function log(...args) {
    console.log("[KVM Auto Login]", ...args);
  }

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function getConfiguredHostPatterns() {
    return String(config.allowedHostPatterns || "")
      .split(/[\n,;]+/)
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
  }

  function hostMatchesPattern(hostname, pattern) {
    const host = String(hostname || "").toLowerCase();
    const cleanPattern = String(pattern || "").toLowerCase().trim();

    if (!host || !cleanPattern) return false;
    if (cleanPattern === "*") return true;

    // Supports simple operator-friendly patterns such as:
    // 10.*
    // 192.168.*
    // 192.168.10.25
    const regexText = "^" + cleanPattern.split("*").map(escapeRegExp).join(".*") + "$";
    return new RegExp(regexText).test(host);
  }

  function isApprovedHost() {
    const host = window.location.hostname;
    const patterns = getConfiguredHostPatterns();
    return patterns.some((pattern) => hostMatchesPattern(host, pattern));
  }

  function safeQuerySelector(selector) {
    try {
      return document.querySelector(selector);
    } catch (error) {
      return null;
    }
  }

  function bodyContains(text) {
    const body = document.body;
    if (!body) return false;
    return body.innerHTML.toLowerCase().includes(String(text).toLowerCase());
  }

  function isRaritanKvmPage() {
    if (!document.documentElement) return false;

    const indicators = [
      () => document.title.trim().toLowerCase() === "login",
      () => bodyContains("raritan"),
      () => Boolean(safeQuerySelector("form[action*='auth.asp']")),
      () => Boolean(safeQuerySelector("form[action*='client=javascript']")),
      () => Boolean(safeQuerySelector("input[name='is_javascript_kvm_client']")),
      () => Boolean(safeQuerySelector("input[name='is_javascript_rsc_client']")),
      () => Boolean(safeQuerySelector("img[src*='raritan']")),
      () => Boolean(safeQuerySelector("img[alt*='raritan' i]")),
      () => Boolean(document.getElementById("raritan_logo")),
      () => Boolean(safeQuerySelector(".raritan_logo_img")),
      () => Boolean(safeQuerySelector("div[id*='login_form']")),
      () => window.location.href.toLowerCase().includes("auth.asp"),
      () => window.location.href.toLowerCase().includes("javascriptclient"),
      () => Boolean(safeQuerySelector("script[src*='prototype.js']")),
      () => Boolean(safeQuerySelector("script[src*='erla.js']"))
    ];

    let matches = 0;
    const matchedIndexes = [];

    indicators.forEach((check, index) => {
      try {
        if (check()) {
          matches += 1;
          matchedIndexes.push(index);
        }
      } catch (error) {
        // Ignore failed checks. Some frames/pages do not expose everything cleanly.
      }
    });

    log(`Raritan-style KVM detection: ${matches} indicators matched`, matchedIndexes);
    return matches >= 2;
  }

  function setNativeInputValue(input, value) {
    const prototype = Object.getPrototypeOf(input);
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");

    if (descriptor && typeof descriptor.set === "function") {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function findLoginControls() {
    const loginInput =
      safeQuerySelector("input[name='login']") ||
      safeQuerySelector("input[name='username']") ||
      safeQuerySelector("input[type='text']");

    const passwordInput =
      safeQuerySelector("input[name='password']") ||
      safeQuerySelector("input[type='password']");

    const submitButton =
      safeQuerySelector("input[name='action_login']") ||
      safeQuerySelector("button[name='action_login']") ||
      safeQuerySelector("input[type='submit']") ||
      safeQuerySelector("button[type='submit']");

    const form =
      loginInput?.closest("form") ||
      passwordInput?.closest("form") ||
      safeQuerySelector("form[action*='auth.asp']") ||
      safeQuerySelector("form");

    return { loginInput, passwordInput, submitButton, form };
  }

  function isReadyToLogin() {
    if (!config.enabled) return false;
    if (!config.username || !config.password) return false;
    if (!isApprovedHost()) return false;
    if (!isRaritanKvmPage()) return false;
    return true;
  }

  function attemptLogin(reason = "auto") {
    if (loginSubmitted) return false;

    if (!isReadyToLogin()) {
      log(`Login attempt skipped (${reason})`);
      return false;
    }

    const { loginInput, passwordInput, submitButton, form } = findLoginControls();

    if (!loginInput || !passwordInput) {
      log(`Login controls not found yet (${reason})`);
      return false;
    }

    const loginAlreadyCorrect = loginInput.value === config.username;
    const passwordAlreadyPresent = passwordInput.value.length > 0;

    if (!loginAlreadyCorrect) {
      setNativeInputValue(loginInput, config.username);
    }

    if (!passwordAlreadyPresent) {
      setNativeInputValue(passwordInput, config.password);
    }

    log(`Submitting KVM login (${reason})`);
    loginSubmitted = true;

    if (submitButton) {
      submitButton.click();
      return true;
    }

    if (form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
      return true;
    }

    if (form && typeof form.submit === "function") {
      form.submit();
      return true;
    }

    loginSubmitted = false;
    log("No submit method found");
    return false;
  }

  function startContinuousMonitoring() {
    let count = 0;

    if (monitorIntervalId) {
      clearInterval(monitorIntervalId);
    }

    monitorIntervalId = setInterval(() => {
      count += 1;

      if (attemptLogin("interval") || count > 40) {
        clearInterval(monitorIntervalId);
        monitorIntervalId = null;
      }
    }, 50);
  }

  function startMutationObserver() {
    if (!document.body) return;

    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver(() => {
      if (attemptLogin("mutation")) {
        observer.disconnect();
        observer = null;
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class"]
    });

    setTimeout(() => {
      if (observer) {
        observer.disconnect();
        observer = null;
      }
    }, 5000);
  }

  function initialize() {
    chrome.storage.local.get(DEFAULT_CONFIG, (storedConfig) => {
      config = { ...DEFAULT_CONFIG, ...storedConfig };

      if (!config.enabled) {
        log("Disabled in settings");
        return;
      }

      if (!isApprovedHost()) {
        log("Host is not approved:", window.location.hostname);
        return;
      }

      if (!isRaritanKvmPage()) {
        log("Approved host, but not a detected Raritan-style KVM login page");
        return;
      }

      log("Approved Raritan-style KVM page detected");
      attemptLogin("initial");
      startContinuousMonitoring();
      startMutationObserver();
    });
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || request.action !== "manualLogin") return;

    chrome.storage.local.get(DEFAULT_CONFIG, (storedConfig) => {
      config = { ...DEFAULT_CONFIG, ...storedConfig };
      loginSubmitted = false;
      const success = attemptLogin("manual");
      sendResponse({ success });
    });

    return true;
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      attemptLogin("visibilitychange");
    }
  });

  window.addEventListener("focus", () => {
    setTimeout(() => attemptLogin("focus"), 25);
  });

  initialize();
})();
