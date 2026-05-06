# KVM Auto Login Helper

Chrome Manifest V3 extension that auto-fills repetitive authenticated logins for approved local lab KVM web interfaces.

This tool was created to reduce repeated manual logins in lab environments where KVM web sessions often disconnect and ask for credentials again.

## Related repositories

- [SmallScripts](https://github.com/AvrahamMakovsky/SmallScripts) - Small collection of utility scripts for everyday technical work, lab support, and system maintenance.

  
## What it does

- Detects Raritan-style KVM login pages using multiple page indicators.
- Runs only on configured host patterns, defaulting to:
  - `192.168.*`
  - `10.*`
- Fills the normal login form with user-provided credentials.
- Submits the login form automatically when enabled.
- Includes a manual "Try Login on Current Tab" button.
- Uses retry logic and a `MutationObserver` for delayed/dynamic login forms.

## What it does not do

This extension does not bypass authentication, exploit the KVM, or weaken the login process. It only submits credentials that the user already has.

## Security notes

Use only on trusted machines and approved local lab systems.

The extension stores credentials in Chrome extension local storage. Do not use it on shared or untrusted computers.

Do not publish real internal hostnames, IP addresses, usernames, passwords, screenshots, or company-specific details together with this project.

## Installation

1. Download or clone this repository.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select this extension folder.
6. Pin the extension if desired.
7. Open the extension popup and configure:
   - Username
   - Password
   - Allowed host patterns
   - Auto-login enabled/disabled

## Notes about host patterns

The extension uses broad Chrome content-script URL matching in the manifest, then applies its own runtime host allowlist before doing anything.

This is because Chrome extension manifest match patterns do not support CIDR-style private-network ranges such as `10.0.0.0/8`, and wildcard hosts are restricted by Chrome's match-pattern rules.

## Author

Avraham Makovsky
