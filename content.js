// Raritan KVM/PDU Auto Login Helper
// Author: Avraham Makovsky
// Purpose: Auto-fill normal authenticated KVM/PDU login forms on approved local lab hosts.
// Security note: This does not bypass authentication. It submits credentials supplied by the user.
// Logic notes:
// - Uses positive login-form detection instead of broad "already logged in" guessing.
// - Requires a Raritan/KVM/PDU identity signal plus username + password login controls.
// - Avoids generic text-field fallback unless the field is explicitly login-like.
// - Excludes known config/dongle fields such as FV_0_portedit and portedit.
// - PDU/Angular timing was shortened; retry/observer logic handles slower pages.

(() => {
  "use strict";

  const DEFAULT_CONFIG = {
    username: "",
    password: "",
    enabled: false,
    allowedHostPatterns: "192.168.*\n10.*"
  };

  const TIMING = {
    initialKvm: 150,
    initialPdu: 650,
    delayedInit: 1500,
    afterUserKvm: 80,
    afterUserPdu: 120,
    afterPassKvm: 100,
    afterPassPdu: 180,
    buttonKvm: 1800,
    buttonPdu: 3500,
    intervalKvm: 100,
    intervalPdu: 150,
    attemptsKvm: 45,
    attemptsPdu: 55,
    observerKvm: 8000,
    observerPdu: 12000
  };

  let config = { ...DEFAULT_CONFIG };
  let detectedPageType = "unknown";
  let loginSubmitted = false;
  let loginInProgress = false;
  let monitorIntervalId = null;
  let observer = null;

  const log = (...args) => console.log("[Raritan Login Helper]", ...args);
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const lower = (value) => String(value || "").toLowerCase();
  const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function qs(selector, root = document) {
    try {
      return root.querySelector(selector);
    } catch (_) {
      return null;
    }
  }

  function qsa(selector, root = document) {
    try {
      return Array.from(root.querySelectorAll(selector));
    } catch (_) {
      return [];
    }
  }

  function bodyContains(text) {
    const body = document.body;
    if (!body) return false;
    const needle = lower(text);
    return lower(body.textContent).includes(needle) || lower(body.innerHTML).includes(needle);
  }

  function titleContains(text) {
    return lower(document.title).includes(lower(text));
  }

  function urlContains(text) {
    return lower(window.location.href).includes(lower(text));
  }

  function fieldText(input) {
    if (!input) return "";
    return [
      input.name,
      input.id,
      input.className,
      input.placeholder,
      input.autocomplete,
      input.getAttribute("aria-label"),
      input.getAttribute("title"),
      input.getAttribute("onchange"),
      input.getAttribute("oninput")
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function elementText(element) {
    if (!element) return "";
    return [
      element.id,
      element.className,
      element.getAttribute?.("name"),
      element.getAttribute?.("action"),
      element.getAttribute?.("aria-label"),
      element.getAttribute?.("title"),
      element.textContent
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function buttonText(button) {
    if (!button) return "";
    return [
      button.textContent,
      button.value,
      button.name,
      button.id,
      button.className,
      button.getAttribute("aria-label"),
      button.getAttribute("title")
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function isApprovedHost() {
    const host = lower(window.location.hostname);
    return String(config.allowedHostPatterns || "")
      .split(/[\n,;]+/)
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
      .some((pattern) => {
        if (pattern === "*") return true;
        const regex = "^" + pattern.split("*").map(escapeRegExp).join(".*") + "$";
        return new RegExp(regex).test(host);
      });
  }

  function hasRaritanSignal() {
    return (
      bodyContains("raritan") ||
      bodyContains("dominion") ||
      titleContains("raritan") ||
      titleContains("dominion") ||
      titleContains("pdu") ||
      titleContains("power") ||
      urlContains("auth.asp") ||
      urlContains("javascriptclient") ||
      urlContains("raritan") ||
      urlContains("pdu") ||
      urlContains("power") ||
      Boolean(qs("img[src*='raritan']")) ||
      Boolean(qs("img[alt*='raritan' i]")) ||
      Boolean(qs("#raritan_logo")) ||
      Boolean(qs(".raritan_logo_img"))
    );
  }

  function hasKvmSignal() {
    return (
      Boolean(qs("form[action*='auth.asp']")) ||
      Boolean(qs("form[action*='client=javascript']")) ||
      Boolean(qs("input[name='is_javascript_kvm_client']")) ||
      Boolean(qs("input[name='is_javascript_rsc_client']")) ||
      Boolean(qs("script[src*='prototype.js']")) ||
      Boolean(qs("script[src*='erla.js']")) ||
      urlContains("auth.asp") ||
      urlContains("javascriptclient")
    );
  }

  function hasPduSignal() {
    return (
      bodyContains("dominion px") ||
      titleContains("pdu") ||
      titleContains("power") ||
      urlContains("pdu") ||
      urlContains("power") ||
      Boolean(qs("button[translate]")) ||
      Boolean(qs(".btn-block"))
    );
  }

  function isUsernameInput(input) {
    if (!input) return false;
    const type = lower(input.type || "text");
    if (["hidden", "password", "checkbox", "radio", "submit", "button"].includes(type)) return false;

    const text = fieldText(input);
    return (
      /(^|\b)login(\b|$)/i.test(text) ||
      /(^|\b)username(\b|$)/i.test(text) ||
      /user\s*name/i.test(text) ||
      /(^|\b)user(\b|$)/i.test(text) ||
      input.autocomplete === "username"
    );
  }

  function isPasswordInput(input) {
    if (!input) return false;
    const text = fieldText(input);
    return (
      lower(input.type) === "password" ||
      /password/i.test(text) ||
      /passwd/i.test(text) ||
      /(^|\b)pwd(\b|$)/i.test(text)
    );
  }

  function shouldExcludeInput(input) {
    if (!input) return true;
    const text = fieldText(input);

    const specificConfigPatterns = [
      /\bfv_\d+_portedit\b/i,
      /\bportedit\b/i,
      /setbladedefaultnameflag/i,
      /\bblade\b.*\bname\b/i,
      /\bport\b.*\bname\b/i,
      /\bdongle\b/i,
      /\btarget\b.*\bname\b/i,
      /\bdevice\b.*\bname\b/i
    ];

    const genericConfigPatterns = [
      /\bconfig\b/i,
      /\bsetting\b/i,
      /\bsettings\b/i,
      /\bdescription\b/i,
      /\bcomment\b/i,
      /\bnote\b/i,
      /\bsearch\b/i,
      /\bfilter\b/i,
      /\baddress\b/i,
      /\burl\b/i,
      /\bpath\b/i,
      /\bip\b/i
    ];

    if (specificConfigPatterns.some((pattern) => pattern.test(text))) {
      log(`Excluding known config input: ${text}`);
      return true;
    }

    if (genericConfigPatterns.some((pattern) => pattern.test(text))) {
      log(`Excluding likely non-login input: ${text}`);
      return true;
    }

    const clearlyLoginField = isUsernameInput(input) || isPasswordInput(input);
    if (!clearlyLoginField && (input.hasAttribute("onchange") || input.hasAttribute("oninput"))) {
      log(`Excluding input with config-like event handler: ${text}`);
      return true;
    }

    return false;
  }

  function findUsername(root) {
    const selectors = [
      "input[name='login']",
      "input[name='username']",
      "input#username",
      "input[autocomplete='username']",
      "input[placeholder*='User Name' i]",
      "input[placeholder*='Username' i]",
      "input[aria-label*='User Name' i]",
      "input[aria-label*='Username' i]"
    ];

    for (const selector of selectors) {
      const input = qs(selector, root);
      if (input && !shouldExcludeInput(input)) return input;
    }

    return qsa("input:not([type]), input[type='text'], input[type='email']", root)
      .find((input) => isUsernameInput(input) && !shouldExcludeInput(input)) || null;
  }

  function findPassword(root) {
    const selectors = [
      "input[name='password']",
      "input#password",
      "input[type='password']",
      "input[placeholder*='Password' i]",
      "input[aria-label*='Password' i]"
    ];

    for (const selector of selectors) {
      const input = qs(selector, root);
      if (input && !shouldExcludeInput(input)) return input;
    }

    return qsa("input", root).find((input) => isPasswordInput(input) && !shouldExcludeInput(input)) || null;
  }

  function findSubmit(root) {
    return (
      qs("input[name='action_login']", root) ||
      qs("button[name='action_login']", root) ||
      qs("button#submit", root) ||
      qs("button[type='submit']", root) ||
      qs("input[type='submit']", root) ||
      qs("button[value='Submit']", root) ||
      qs(".btn-primary", root)
    );
  }

  function scopeLooksLikeLogin(root, usernameInput, passwordInput, submitButton) {
    if (!usernameInput || !passwordInput) return false;
    if (shouldExcludeInput(usernameInput) || shouldExcludeInput(passwordInput)) return false;

    const form = usernameInput.closest("form") || passwordInput.closest("form");
    const sameForm = form && passwordInput.closest("form") === form;
    const action = lower(form?.getAttribute("action") || form?.action || "");
    const scopeText = elementText(root);
    const btnText = buttonText(submitButton);

    const actionSignal =
      action.includes("auth") ||
      action.includes("login") ||
      action.includes("signin") ||
      action.includes("client=javascript");

    const textSignal =
      scopeText.includes("login") ||
      scopeText.includes("log in") ||
      scopeText.includes("sign in") ||
      scopeText.includes("authenticate") ||
      scopeText.includes("user name") ||
      scopeText.includes("username") ||
      scopeText.includes("password");

    const buttonSignal =
      btnText.includes("login") ||
      btnText.includes("log in") ||
      btnText.includes("sign in") ||
      btnText.includes("authenticate") ||
      (btnText.includes("submit") && (actionSignal || textSignal));

    const fieldSignal = isUsernameInput(usernameInput) && isPasswordInput(passwordInput);

    if (sameForm && (actionSignal || textSignal || fieldSignal || buttonSignal)) return true;
    if (!sameForm && fieldSignal && (textSignal || hasPduSignal() || hasRaritanSignal())) return true;

    return false;
  }

  function findControlsInRoot(root) {
    const usernameInput = findUsername(root);
    const passwordInput = findPassword(root);
    const submitButton = findSubmit(root);

    if (!scopeLooksLikeLogin(root, usernameInput, passwordInput, submitButton)) return null;

    const form =
      usernameInput.closest("form") ||
      passwordInput.closest("form") ||
      qs("form[action*='auth.asp']", root) ||
      qs("form", root);

    return { usernameInput, passwordInput, submitButton, form };
  }

  function findLoginControls() {
    for (const form of qsa("form")) {
      const controls = findControlsInRoot(form);
      if (controls) return controls;
    }

    const scopes = [
      ...qsa("#login"),
      ...qsa("[id*='login' i]"),
      ...qsa("[class*='login' i]"),
      ...qsa("div[id*='login_form' i]"),
      ...qsa("main"),
      ...qsa("body")
    ];

    for (const scope of [...new Set(scopes.filter(Boolean))]) {
      const controls = findControlsInRoot(scope);
      if (controls) return controls;
    }

    return null;
  }

  function detectTypeFromControls(controls) {
    if (!controls) return "unknown";

    const { usernameInput, passwordInput, submitButton, form } = controls;
    const combined = [
      fieldText(usernameInput),
      fieldText(passwordInput),
      buttonText(submitButton),
      elementText(form)
    ].join(" ");

    const formAction = lower(form?.getAttribute("action") || form?.action || "");

    const looksPdu =
      hasPduSignal() ||
      combined.includes("btn-primary") ||
      combined.includes("btn-block") ||
      combined.includes("form-control") ||
      lower(usernameInput.id).includes("username") ||
      lower(passwordInput.id).includes("password");

    const looksKvm =
      hasKvmSignal() ||
      combined.includes("action_login") ||
      combined.includes("is_javascript_kvm_client") ||
      combined.includes("is_javascript_rsc_client") ||
      formAction.includes("auth.asp");

    if (looksPdu) return "pdu";
    if (looksKvm) return "kvm";
    return hasRaritanSignal() ? "kvm" : "unknown";
  }

  function detectPageType() {
    if (!hasRaritanSignal()) {
      detectedPageType = "unknown";
      return "unknown";
    }

    const controls = findLoginControls();
    if (!controls) {
      log("No positive login-form match found");
      detectedPageType = "unknown";
      return "unknown";
    }

    detectedPageType = detectTypeFromControls(controls);
    log(`Positive login-form match found; detected page type: ${detectedPageType}`);
    return detectedPageType;
  }

  function dispatchEventSafe(element, event) {
    try {
      element.dispatchEvent(event);
    } catch (_) {}
  }

  function triggerValidation(input) {
    if (!input) return;

    ["input", "change", "keyup", "keydown", "blur", "focus"].forEach((eventType) => {
      dispatchEventSafe(input, new Event(eventType, { bubbles: true, cancelable: true }));
    });

    try {
      dispatchEventSafe(input, new InputEvent("input", {
        bubbles: true,
        cancelable: true,
        inputType: "insertText",
        data: input.value || ""
      }));
    } catch (_) {}

    const form = input.closest("form");
    if (form) {
      dispatchEventSafe(form, new Event("input", { bubbles: true, cancelable: true }));
      dispatchEventSafe(form, new Event("change", { bubbles: true, cancelable: true }));
    }
  }

  function setInputValue(input, value) {
    if (!input) return;

    input.focus();

    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value");
    if (descriptor && typeof descriptor.set === "function") {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    // Do not write passwords into DOM attributes.
    if (lower(input.type) !== "password") input.setAttribute("value", value);

    triggerValidation(input);
    setTimeout(() => {
      triggerValidation(input);
      input.blur();
    }, 40);
  }

  function isDisabled(button) {
    if (!button) return false;
    return (
      button.hasAttribute("disabled") ||
      Boolean(button.disabled) ||
      lower(button.getAttribute("aria-disabled")) === "true" ||
      Boolean(button.classList && button.classList.contains("disabled"))
    );
  }

  async function waitForButton(button, usernameInput, passwordInput, maxWait) {
    if (!button) return true;

    const started = Date.now();
    while (Date.now() - started <= maxWait) {
      triggerValidation(usernameInput);
      triggerValidation(passwordInput);
      if (!isDisabled(button)) return true;
      await sleep(100);
    }

    return false;
  }

  function readyToLogin() {
    if (!config.enabled) return false;
    if (!config.username || !config.password) return false;
    if (!isApprovedHost()) return false;
    return detectPageType() !== "unknown";
  }

  async function attemptLogin(reason = "auto") {
    if (loginSubmitted || loginInProgress) return false;
    loginInProgress = true;

    try {
      if (!readyToLogin()) {
        log(`Login attempt skipped (${reason})`);
        return false;
      }

      const controls = findLoginControls();
      if (!controls) {
        log(`Login controls not found after detection (${reason})`);
        return false;
      }

      const { usernameInput, passwordInput, submitButton, form } = controls;
      log(`Attempting login (${reason}) on ${detectedPageType.toUpperCase()} page`);

      if (usernameInput.value !== config.username) {
        setInputValue(usernameInput, config.username);
        log("Username filled");
      }

      await sleep(detectedPageType === "pdu" ? TIMING.afterUserPdu : TIMING.afterUserKvm);

      if (passwordInput.value !== config.password) {
        setInputValue(passwordInput, config.password);
        log("Password filled");
      }

      await sleep(detectedPageType === "pdu" ? TIMING.afterPassPdu : TIMING.afterPassKvm);

      if (submitButton) {
        const maxWait = detectedPageType === "pdu" ? TIMING.buttonPdu : TIMING.buttonKvm;
        log(`Waiting for submit button to become enabled, max ${maxWait} ms`);

        const enabled = await waitForButton(submitButton, usernameInput, passwordInput, maxWait);
        if (!enabled) {
          log("Submit button did not become enabled yet; will retry later");
          return false;
        }

        log(`Submitting Raritan ${detectedPageType.toUpperCase()} login (${reason})`);
        loginSubmitted = true;
        submitButton.click();
        return true;
      }

      if (form) {
        log(`No submit button found; submitting form directly (${reason})`);
        loginSubmitted = true;

        if (typeof form.requestSubmit === "function") form.requestSubmit();
        else if (typeof form.submit === "function") form.submit();
        else {
          loginSubmitted = false;
          log("Form exists but has no usable submit method");
          return false;
        }

        return true;
      }

      log("No submit method found");
      return false;
    } finally {
      loginInProgress = false;
    }
  }

  function startContinuousMonitoring() {
    let count = 0;
    const maxAttempts = detectedPageType === "pdu" ? TIMING.attemptsPdu : TIMING.attemptsKvm;
    const interval = detectedPageType === "pdu" ? TIMING.intervalPdu : TIMING.intervalKvm;

    if (monitorIntervalId) clearInterval(monitorIntervalId);

    monitorIntervalId = setInterval(async () => {
      count += 1;
      const success = await attemptLogin("interval");
      if (success || count > maxAttempts) {
        clearInterval(monitorIntervalId);
        monitorIntervalId = null;
      }
    }, interval);
  }

  function startMutationObserver() {
    if (!document.body) return;
    if (observer) observer.disconnect();

    observer = new MutationObserver(async (mutations) => {
      const shouldCheck = mutations.some((mutation) => {
        if (mutation.type === "childList" && mutation.addedNodes.length > 0) return true;
        if (mutation.type !== "attributes") return false;

        const target = mutation.target;
        const tag = target && target.tagName ? target.tagName.toLowerCase() : "";
        return (
          tag === "button" ||
          tag === "input" ||
          ["disabled", "class", "aria-disabled", "value"].includes(mutation.attributeName)
        );
      });

      if (!shouldCheck) return;

      const success = await attemptLogin("mutation");
      if (success && observer) {
        observer.disconnect();
        observer = null;
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "disabled", "aria-disabled", "ng-class", "value"]
    });

    setTimeout(() => {
      if (observer) {
        observer.disconnect();
        observer = null;
      }
    }, detectedPageType === "pdu" ? TIMING.observerPdu : TIMING.observerKvm);
  }

  function initialize() {
    chrome.storage.local.get(DEFAULT_CONFIG, (storedConfig) => {
      config = { ...DEFAULT_CONFIG, ...storedConfig };

      log("Initializing with config:", {
        enabled: config.enabled,
        hasUsername: Boolean(config.username),
        hasPassword: Boolean(config.password),
        host: window.location.hostname
      });

      if (!config.enabled) return log("Disabled in settings");
      if (!isApprovedHost()) return log("Host is not approved:", window.location.hostname);

      const pageType = detectPageType();
      if (pageType === "unknown") {
        log("Approved host, but not a positive Raritan KVM/PDU login-form match");
        return;
      }

      log(`Approved Raritan ${pageType.toUpperCase()} login form detected`);
      const delay = pageType === "pdu" ? TIMING.initialPdu : TIMING.initialKvm;

      setTimeout(async () => {
        log("Starting login attempts");
        await attemptLogin("initial");
        startContinuousMonitoring();
        startMutationObserver();
      }, delay);
    });
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || request.action !== "manualLogin") return false;

    chrome.storage.local.get(DEFAULT_CONFIG, async (storedConfig) => {
      config = { ...DEFAULT_CONFIG, ...storedConfig };
      loginSubmitted = false;
      loginInProgress = false;
      const success = await attemptLogin("manual");
      sendResponse({ success });
    });

    return true;
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }

  setTimeout(initialize, TIMING.delayedInit);

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      setTimeout(async () => {
        loginSubmitted = false;
        await attemptLogin("visibilitychange");
      }, 500);
    }
  });

  window.addEventListener("focus", () => {
    setTimeout(async () => {
      loginSubmitted = false;
      await attemptLogin("focus");
    }, 500);
  });
})();
