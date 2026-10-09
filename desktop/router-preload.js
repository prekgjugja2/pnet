'use strict';

const { ipcRenderer } = require('electron');

let lastSent = '';
let lastSentAt = 0;

function sendLogin(creds) {
  if (!creds || !creds.password) return;
  const username = String(creds.username || '').trim();
  const password = String(creds.password);
  const url = String(creds.url || location.href || '');
  const key = `${username}\n${password}\n${url}`;
  const now = Date.now();
  if (key === lastSent && now - lastSentAt < 4000) return;
  lastSent = key;
  lastSentAt = now;
  ipcRenderer.send('router-login-captured', { username, password, url });
}

function pickUsername(form, passwordInput) {
  const named = form.querySelector(
    'input[name*="user" i], input[name*="login" i], input[name*="email" i], input[id*="user" i], input[id*="login" i], input[autocomplete="username"]'
  );
  if (named && named !== passwordInput && named.value) return named.value;

  const candidates = Array.from(
    form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]):not([type="password"])')
  ).filter((el) => el.offsetParent !== null || el.value);
  if (candidates.length) return candidates[0].value || '';

  const nearby = document.querySelector(
    'input[name*="user" i], input[name*="login" i], input[id*="user" i], input[autocomplete="username"]'
  );
  return nearby && nearby.value ? nearby.value : '';
}

function credsFromForm(form) {
  if (!(form instanceof HTMLFormElement)) return null;
  const passwordInput = form.querySelector('input[type="password"]');
  if (!passwordInput || !passwordInput.value) return null;
  return {
    username: pickUsername(form, passwordInput),
    password: passwordInput.value,
    url: location.href,
  };
}

function credsFromPage() {
  const passwordInput = document.querySelector('input[type="password"]');
  if (!passwordInput || !passwordInput.value) return null;
  const form = passwordInput.closest('form') || document.body;
  return {
    username: pickUsername(form, passwordInput),
    password: passwordInput.value,
    url: location.href,
  };
}

function installCapture() {
  document.addEventListener(
    'submit',
    (event) => {
      const form = event.target;
      const creds = credsFromForm(form);
      if (creds) sendLogin(creds);
    },
    true
  );

  document.addEventListener(
    'click',
    (event) => {
      const btn = event.target && event.target.closest
        ? event.target.closest('button, input[type="submit"], input[type="button"], a')
        : null;
      if (!btn) return;
      const label = `${btn.textContent || ''} ${btn.value || ''} ${btn.id || ''} ${btn.className || ''}`.toLowerCase();
      if (!/(log\s*in|sign\s*in|submit|ok|connect|auth|入)/i.test(label) && btn.type !== 'submit') {
        return;
      }
      const form = btn.closest('form');
      const creds = form ? credsFromForm(form) : credsFromPage();
      if (creds) sendLogin(creds);
    },
    true
  );

  document.addEventListener(
    'keydown',
    (event) => {
      if (event.key !== 'Enter') return;
      const el = event.target;
      if (!el || (el.tagName !== 'INPUT' && el.tagName !== 'SELECT')) return;
      const form = el.closest('form');
      const creds = form ? credsFromForm(form) : credsFromPage();
      if (creds) sendLogin(creds);
    },
    true
  );
}

function fillField(el, value) {
  if (!el || value == null || value === '') return;
  el.focus();
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

async function autofill() {
  let creds = null;
  try {
    creds = await ipcRenderer.invoke('router-autofill-creds');
  } catch (_) {
    return;
  }
  if (!creds || !creds.password) return;

  const tryFill = () => {
    const passwords = Array.from(document.querySelectorAll('input[type="password"]'));
    if (!passwords.length) return false;
    const passwordInput = passwords[0];
    const form = passwordInput.closest('form') || document;
    const userInput =
      form.querySelector(
        'input[name*="user" i], input[name*="login" i], input[name*="email" i], input[id*="user" i], input[id*="login" i], input[autocomplete="username"]'
      ) ||
      Array.from(
        form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]):not([type="password"])')
      )[0];

    if (userInput && creds.username) fillField(userInput, creds.username);
    fillField(passwordInput, creds.password);
    return true;
  };

  if (tryFill()) return;
  let attempts = 0;
  const timer = setInterval(() => {
    attempts += 1;
    if (tryFill() || attempts > 20) clearInterval(timer);
  }, 400);
}

installCapture();
window.addEventListener('DOMContentLoaded', () => {
  autofill();
});
if (document.readyState !== 'loading') {
  autofill();
}
