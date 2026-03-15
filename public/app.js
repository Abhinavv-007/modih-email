/* ========================================
   MODIH MAIL — Application Logic
   ======================================== */

// ========== STATE ==========
let currentInbox = null; // { id, email, created_at, expires_at, owner_token }
let currentMessages = [];
let currentMessageId = null;
let countdownInterval = null;
let refreshInterval = null;
let isMailWindowOpen = false;
let turnstileWidgetId = null;
let turnstileRequired = false;

// ========== BROWSER TOKEN (anonymous visitor tracking) ==========
function getBrowserToken() {
  let token = localStorage.getItem("modih_browser_token");
  if (!token) {
    token = crypto.randomUUID ? crypto.randomUUID() : generateFallbackUUID();
    localStorage.setItem("modih_browser_token", token);
  }
  return token;
}

function generateFallbackUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// ========== VIDEO CONTROLLER (play once → freeze at end) ==========
function initVideoController() {
  const videos = [
    document.getElementById('bg-video'),
    document.getElementById('bg-video-mobile')
  ].filter(Boolean);

  videos.forEach(video => {
    const tryPlay = () => {
      video.play().catch(() => {
        const retry = () => {
          video.play().catch(() => {});
          document.removeEventListener('click', retry);
          document.removeEventListener('touchstart', retry);
        };
        document.addEventListener('click', retry, { once: true });
        document.addEventListener('touchstart', retry, { once: true });
      });
    };

    if (video.readyState >= 3) {
      tryPlay();
    } else {
      video.addEventListener('canplay', tryPlay, { once: true });
    }
  });
}

// ========== TYPEWRITER EFFECT ==========
function initTypewriter() {
  const elements = document.querySelectorAll('.typewriter');
  elements.forEach((el, idx) => {
    const text = el.textContent;
    el.textContent = '';
    el.style.visibility = 'visible';
    const delay = idx * 800;
    let charIdx = 0;

    setTimeout(() => {
      const type = () => {
        if (charIdx < text.length) {
          el.textContent += text.charAt(charIdx);
          charIdx++;
          setTimeout(type, 35 + Math.random() * 25);
        }
      };
      type();
    }, 400 + delay);
  });
}

// ========== INIT ==========
document.addEventListener("DOMContentLoaded", () => {
  initScrollAnimations();
  initNavScroll();
  initSectionObserver();
  initVideoController();
  initTypewriter();
  initBillingToggle();

  // Initialize browser token early
  getBrowserToken();

  // Enter key on input
  document.getElementById("email-prefix").addEventListener("keydown", (e) => {
    if (e.key === "Enter") createInbox("custom");
  });

  // Restore session from localStorage
  restoreSession();
});

// ========== SCROLL ANIMATIONS ==========
function initScrollAnimations() {
  const elements = document.querySelectorAll(".fade-up");

  elements.forEach((el) => {
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight) {
      el.classList.add("visible");
    }
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
        }
      });
    },
    { threshold: 0.1, rootMargin: "0px 0px -50px 0px" }
  );

  elements.forEach((el) => observer.observe(el));
}

function initNavScroll() {
  const nav = document.getElementById("navbar");
  window.addEventListener("scroll", () => {
    if (window.scrollY > 50) {
      nav.classList.add("scrolled");
    } else {
      nav.classList.remove("scrolled");
    }
  });
}

function initSectionObserver() {
  const sections = document.querySelectorAll(".section");
  const navLinks = document.querySelectorAll(".nav-link");

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.id;
          navLinks.forEach((link) => {
            link.classList.toggle("active", link.dataset.section === id);
          });
        }
      });
    },
    { threshold: 0.3 }
  );

  sections.forEach((s) => observer.observe(s));
}

function scrollToSection(id) {
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: "smooth" });
}

// ========== AUTH HELPERS ==========
function authHeaders() {
  const token = currentInbox ? currentInbox.owner_token : "";
  return { "X-Owner-Token": token };
}

// ========== TURNSTILE ==========
function showTurnstile() {
  const container = document.getElementById("turnstile-container");
  container.style.display = "flex";

  // If widget already rendered, reset it
  if (turnstileWidgetId !== null && window.turnstile) {
    window.turnstile.reset(turnstileWidgetId);
    return;
  }

  // Render turnstile widget
  if (window.turnstile) {
    turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
      sitekey: window.TURNSTILE_SITE_KEY || '0x4AAAAAAAAAAAAAAAAAAAAAAA', // placeholder, replaced by config
      theme: 'dark',
      callback: function(token) {
        // Token is automatically picked up on next creation
      },
    });
  }
}

function hideTurnstile() {
  const container = document.getElementById("turnstile-container");
  container.style.display = "none";
}

function getTurnstileToken() {
  if (turnstileWidgetId !== null && window.turnstile) {
    return window.turnstile.getResponse(turnstileWidgetId) || "";
  }
  return "";
}

// ========== INBOX CREATION ==========
async function createInbox(type) {
  const errorEl = document.getElementById("generate-error");
  const upgradeEl = document.getElementById("generate-upgrade");
  const btnCustom = document.getElementById("btn-custom");
  const btnRandom = document.getElementById("btn-random");

  errorEl.style.display = "none";
  upgradeEl.style.display = "none";

  // ========== FREE TIER: Block custom prefix ==========
  if (type === "custom") {
    upgradeEl.style.display = "block";
    upgradeEl.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }

  // Loading state
  btnCustom.classList.add("loading");
  btnRandom.classList.add("loading");

  try {
    const body = {};

    // Include Turnstile token if widget is visible
    const turnstileToken = getTurnstileToken();
    if (turnstileToken) {
      body.turnstile_token = turnstileToken;
    }

    const headers = {
      "Content-Type": "application/json",
      "X-Browser-Token": getBrowserToken(),
    };

    // Include owner_token if we have one
    if (currentInbox && currentInbox.owner_token) {
      headers["X-Owner-Token"] = currentInbox.owner_token;
    }

    const res = await fetch("/api/inbox", {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    const data = await res.json();

    if (!res.ok) {
      // Handle specific free-tier errors
      if (data.upgrade_required) {
        showUpgradeError(data.error, data.feature);
        return;
      }
      if (data.turnstile_required) {
        showError(data.error || "Please complete the verification challenge.");
        showTurnstile();
        return;
      }
      if (res.status === 429) {
        showError(data.error || "Rate limit exceeded. Try again later.");
        return;
      }
      showError(data.error || "Failed to create inbox.");
      return;
    }

    // Save state (includes owner_token)
    currentInbox = data;
    currentMessages = [];
    saveSession();

    // Update creation counter
    if (data.creations_today !== undefined) {
      showCreationCounter(data.creations_today, data.max_creations);
    }

    // Show/hide turnstile based on server response
    if (data.turnstile_required) {
      turnstileRequired = true;
      showTurnstile();
    } else {
      hideTurnstile();
    }

    // Show result
    showEmailResult(data);
  } catch (e) {
    console.error("Create inbox error:", e);
    showError("Network error. Please try again.");
  } finally {
    btnCustom.classList.remove("loading");
    btnRandom.classList.remove("loading");
  }
}

function showError(msg) {
  const errorEl = document.getElementById("generate-error");
  errorEl.textContent = msg;
  errorEl.style.display = "block";
}

function showUpgradeError(msg, feature) {
  const upgradeEl = document.getElementById("generate-upgrade");
  const errorEl = document.getElementById("generate-error");
  errorEl.style.display = "none";

  // Show upgrade prompt with contextual message
  upgradeEl.style.display = "block";
  const inner = upgradeEl.querySelector(".upgrade-prompt-inner p");
  if (inner) {
    if (feature === "custom_prefix") {
      inner.innerHTML = 'Custom prefixes are a <strong>Pro</strong> feature. Upgrade to choose your own email name.';
    } else if (feature === "active_limit") {
      inner.innerHTML = 'Free accounts are limited to <strong>1 active inbox</strong>. Upgrade to Pro for up to 10.';
    } else if (feature === "creation_limit") {
      inner.innerHTML = "You've hit today's limit. Upgrade to <strong>Pro</strong> for 25 inboxes per day.";
    } else {
      inner.innerHTML = msg || 'Upgrade to <strong>Pro</strong> for more features.';
    }
  }
  upgradeEl.scrollIntoView({ behavior: "smooth", block: "center" });
}

function showCreationCounter(count, max) {
  const counterEl = document.getElementById("creation-counter");
  const textEl = document.getElementById("creation-count-text");
  if (counterEl && textEl) {
    counterEl.style.display = "block";
    textEl.textContent = `${count} of ${max} free inboxes used today`;
  }
}

function showEmailResult(inbox) {
  document.getElementById("generate-error").style.display = "none";
  document.getElementById("generate-upgrade").style.display = "none";

  const resultEl = document.getElementById("email-result");
  const addressEl = document.getElementById("result-email-address");

  addressEl.textContent = inbox.email;
  resultEl.style.display = "block";

  // Start countdown if we have an expiry
  if (inbox.expires_at) {
    startCountdown(inbox.expires_at);
  }

  // Smooth scroll to result
  resultEl.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ========== COUNTDOWN TIMER ==========
function startCountdown(expiresAt) {
  if (countdownInterval) clearInterval(countdownInterval);

  function update() {
    const now = Math.floor(Date.now() / 1000);
    const remaining = expiresAt - now;

    if (remaining <= 0) {
      clearInterval(countdownInterval);
      handleExpired();
      return;
    }

    const hours = Math.floor(remaining / 3600);
    const minutes = Math.floor((remaining % 3600) / 60);
    const seconds = remaining % 60;
    const timeStr = `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;

    // Update all countdown displays
    const timerEl = document.getElementById("countdown-timer");
    const mailTimerEl = document.getElementById("mail-countdown");

    if (timerEl) timerEl.textContent = timeStr;
    if (mailTimerEl) mailTimerEl.textContent = timeStr;
  }

  update();
  countdownInterval = setInterval(update, 1000);
}

function handleExpired() {
  currentInbox = null;
  currentMessages = [];
  clearSession();

  if (isMailWindowOpen) {
    closeMailWindow();
  }

  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";

  showToast("Inbox expired. Create a new one!");
}

// ========== MAIL WINDOW ==========
function openMailWindow() {
  if (!currentInbox) return;

  isMailWindowOpen = true;

  // Show mail backgrounds, hide landing backgrounds
  document.getElementById("bg-media").style.display = "none";
  document.getElementById("mail-bg-media").style.display = "block";

  // Show mail window with animation
  const mailWindow = document.getElementById("mail-window");
  mailWindow.style.display = "block";
  requestAnimationFrame(() => {
    mailWindow.classList.add("active");
  });

  // Hide main content sections
  document.getElementById("navbar").style.display = "none";
  document.querySelectorAll(".section").forEach((s) => (s.style.display = "none"));
  document.querySelector(".footer").style.display = "none";

  // Update header
  document.getElementById("mail-header-email").textContent = currentInbox.email;
  document.getElementById("mail-empty-addr").textContent = currentInbox.email;

  // Reset detail view
  closeMessageDetail();

  // Start fetching
  fetchMessages();
  startAutoRefresh();
}

function closeMailWindow() {
  isMailWindowOpen = false;

  // Animate out
  const mailWindow = document.getElementById("mail-window");
  mailWindow.classList.remove("active");

  // Wait for animation to finish, then hide
  setTimeout(() => {
    // Swap backgrounds back
    document.getElementById("bg-media").style.display = "block";
    document.getElementById("mail-bg-media").style.display = "none";

    mailWindow.style.display = "none";

    // Show main content
    document.getElementById("navbar").style.display = "block";
    document.querySelectorAll(".section").forEach((s) => (s.style.display = "flex"));
    document.querySelector(".footer").style.display = "block";
  }, 350);

  stopAutoRefresh();
}

// ========== MESSAGE FETCHING ==========
async function fetchMessages() {
  if (!currentInbox) return;

  try {
    const res = await fetch(`/api/messages?inbox_id=${encodeURIComponent(currentInbox.id)}`, {
      headers: authHeaders(),
    });
    const data = await res.json();

    if (res.status === 403 || res.status === 404) {
      handleSessionInvalid();
      return;
    }

    if (!res.ok) return;

    currentMessages = data.messages || [];
    renderMailList();
  } catch (e) {
    console.error("Fetch messages error:", e);
  }
}

function handleSessionInvalid() {
  currentInbox = null;
  currentMessages = [];
  clearSession();

  if (isMailWindowOpen) {
    closeMailWindow();
  }

  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";

  showToast("Session expired or inbox deleted. Create a new one.");
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(fetchMessages, 5000);
}

function stopAutoRefresh() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
}

async function refreshInbox() {
  const btn = document.getElementById("btn-refresh");
  btn.classList.add("spinning");
  await fetchMessages();
  setTimeout(() => btn.classList.remove("spinning"), 800);
  showToast("Inbox refreshed");
}

// ========== RENDER MAIL LIST ==========
function renderMailList() {
  if (currentMessageId) return;

  const listEl = document.getElementById("mail-list");
  const emptyEl = document.getElementById("mail-empty");

  if (currentMessages.length === 0) {
    listEl.style.display = "none";
    emptyEl.style.display = "flex";
    return;
  }

  emptyEl.style.display = "none";
  listEl.style.display = "flex";

  listEl.innerHTML = currentMessages
    .map((msg, index) => {
      const fromDisplay = msg.from_name || msg.from_address;
      const initial = fromDisplay.charAt(0).toUpperCase();
      const timeAgo = formatTimeAgo(msg.received_at);
      const otp = extractOTP(msg.subject + " " + msg.body_text + " " + msg.body_html);

      return `
      <div class="mail-item" onclick="openMessageByIndex(${index})" style="animation-delay: ${index * 0.08}s">
        <div class="mail-item-avatar">${initial}</div>
        <div class="mail-item-content">
          <div class="mail-item-top">
            <span class="mail-item-from">${escapeHtml(fromDisplay)}</span>
            <span class="mail-item-time">${timeAgo}</span>
          </div>
          <div class="mail-item-subject">${escapeHtml(msg.subject)}</div>
          ${otp ? `<div class="mail-item-otp">🔑 OTP: ${otp}</div>` : ""}
        </div>
      </div>
    `;
    })
    .join("");
}

// ========== MESSAGE DETAIL ==========
function openMessageByIndex(index) {
  const msg = currentMessages[index];
  if (!msg) return;
  openMessage(msg.id);
}

function openMessage(msgId) {
  const msg = currentMessages.find((m) => m.id === msgId);
  if (!msg) return;

  currentMessageId = msgId;

  document.getElementById("mail-list").style.display = "none";
  document.getElementById("mail-empty").style.display = "none";
  const detail = document.getElementById("mail-detail");
  detail.style.display = "block";

  document.getElementById("detail-subject").textContent = msg.subject;
  document.getElementById("detail-from").textContent = msg.from_name
    ? `${msg.from_name} <${msg.from_address}>`
    : msg.from_address;
  document.getElementById("detail-time").textContent = formatTime(msg.received_at);

  const bodyEl = document.getElementById("detail-body");
  if (msg.body_html) {
    bodyEl.innerHTML = sanitizeRenderedHtml(msg.body_html);
  } else {
    bodyEl.innerHTML = `<pre style="white-space:pre-wrap;font-family:inherit;">${escapeHtml(msg.body_text)}</pre>`;
  }

  const otp = extractOTP(msg.subject + " " + msg.body_text + " " + msg.body_html);
  const otpEl = document.getElementById("detail-otp");
  if (otp) {
    otpEl.style.display = "flex";
    document.getElementById("detail-otp-code").textContent = otp;
  } else {
    otpEl.style.display = "none";
  }
}

function closeMessageDetail() {
  document.getElementById("mail-detail").style.display = "none";
  currentMessageId = null;
  renderMailList();
}

// ========== DELETE ADDRESS & RESET ==========
async function deleteAddressAndReset() {
  if (!currentInbox) return;

  if (!confirm("Delete this address and all its messages? You'll need to create a new one.")) return;

  try {
    await fetch(`/api/inbox?id=${currentInbox.id}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
  } catch (e) {
    console.error("Delete inbox error:", e);
  }

  currentInbox = null;
  currentMessages = [];
  currentMessageId = null;
  clearSession();
  if (countdownInterval) clearInterval(countdownInterval);
  stopAutoRefresh();

  if (isMailWindowOpen) {
    closeMailWindow();
  }

  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";

  setTimeout(() => {
    scrollToSection('generate');
    showToast("Address deleted. Create a new one!");
  }, 400);
}

// ========== DELETE ALL MESSAGES (keep address) ==========
async function deleteAllMessages() {
  if (!currentInbox) return;

  if (!confirm("Delete all messages in this inbox?")) return;

  try {
    const res = await fetch(`/api/messages?inbox_id=${encodeURIComponent(currentInbox.id)}`, {
      method: "DELETE",
      headers: authHeaders(),
    });

    if (res.ok) {
      currentMessages = [];
      closeMessageDetail();
      renderMailList();
      showToast("All messages deleted");
    }
  } catch (e) {
    console.error("Delete all error:", e);
    showToast("Failed to delete messages");
  }
}

async function deleteCurrentMessage() {
  if (!currentInbox || !currentMessageId) return;

  try {
    const res = await fetch(
      `/api/messages?inbox_id=${encodeURIComponent(currentInbox.id)}&id=${encodeURIComponent(currentMessageId)}`,
      {
        method: "DELETE",
        headers: authHeaders(),
      }
    );

    if (res.ok) {
      currentMessages = currentMessages.filter((m) => m.id !== currentMessageId);
      closeMessageDetail();
      renderMailList();
      showToast("Message deleted");
    }
  } catch (e) {
    console.error("Delete message error:", e);
    showToast("Failed to delete message");
  }
}

// ========== COPY ==========
function copyEmail() {
  if (!currentInbox) return;
  navigator.clipboard.writeText(currentInbox.email)
    .then(() => {
      showToast("Email copied to clipboard");
    })
    .catch(() => {
      showToast("Unable to copy email");
    });
}

function copyOTP() {
  const otpCode = document.getElementById("detail-otp-code").textContent;
  if (otpCode) {
    navigator.clipboard.writeText(otpCode)
      .then(() => {
        showToast("OTP copied to clipboard");
      })
      .catch(() => {
        showToast("Unable to copy OTP");
      });
  }
}

// ========== OTP DETECTION ==========
function extractOTP(text) {
  if (!text) return null;

  const patterns = [
    /\b(?:otp|code|verify|verification|pin|passcode|token)[:\s]*(\d{4,8})\b/i,
    /\b(\d{4,8})\s*(?:is your|is the|is|as your)\s*(?:otp|code|verification|pin|passcode)/i,
    /(?:enter|use|submit|type)\s*(?:the\s*)?(?:code|otp|pin)?[:\s]*(\d{4,8})\b/i,
    /\b(?:one[- ]?time\s*(?:password|code|pin))[:\s]*(\d{4,8})\b/i,
    /\b(\d{6})\b(?=.*(?:verif|otp|code|confirm|expire))/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  return null;
}

// ========== UTILITIES ==========
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text || "";
  return div.innerHTML;
}

function sanitizeRenderedHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/on\w+\s*=\s*"[^"]*"/gi, "")
    .replace(/on\w+\s*=\s*'[^']*'/gi, "")
    .replace(/on\w+\s*=\s*[^\s>]+/gi, "")
    .replace(/javascript\s*:/gi, "blocked:")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
    .replace(/<object[\s\S]*?<\/object>/gi, "")
    .replace(/<embed[\s\S]*?>/gi, "")
    .replace(/<form[\s\S]*?<\/form>/gi, "")
    .replace(/<base[\s\S]*?>/gi, "")
    .replace(/<meta[\s\S]*?>/gi, "");
}

function formatTimeAgo(timestamp) {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;

  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(timestamp * 1000).toLocaleDateString();
}

function formatTime(timestamp) {
  return new Date(timestamp * 1000).toLocaleString();
}

// ========== TOAST ==========
function showToast(msg) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toast-msg");
  msgEl.textContent = msg;
  toast.style.display = "block";

  toast.style.animation = "none";
  toast.offsetHeight;
  toast.style.animation = "toastIn 0.3s ease";

  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => {
    toast.style.display = "none";
  }, 2500);
}

// ========== SESSION PERSISTENCE ==========
function saveSession() {
  if (currentInbox) {
    localStorage.setItem("modih_inbox", JSON.stringify({
      id: currentInbox.id,
      email: currentInbox.email,
      created_at: currentInbox.created_at,
      expires_at: currentInbox.expires_at,
      owner_token: currentInbox.owner_token,
    }));
  }
}

function clearSession() {
  localStorage.removeItem("modih_inbox");
}

async function restoreSession() {
  try {
    const saved = localStorage.getItem("modih_inbox");
    if (!saved) return;

    const inbox = JSON.parse(saved);

    if (!inbox.owner_token) {
      clearSession();
      return;
    }

    if (inbox.expires_at) {
      const now = Math.floor(Date.now() / 1000);
      if (inbox.expires_at < now) {
        clearSession();
        return;
      }
    }

    const res = await fetch(`/api/messages?inbox_id=${inbox.id}`, {
      headers: { "X-Owner-Token": inbox.owner_token },
    });

    if (res.ok) {
      const data = await res.json();
      if (data.inbox && data.inbox.expires_at) {
        inbox.expires_at = data.inbox.expires_at;
      }
      currentInbox = inbox;
      showEmailResult(inbox);
    } else {
      clearSession();
    }
  } catch (e) {
    clearSession();
  }
}

// ========== PRICING — BILLING PERIOD TOGGLE ==========
const PRICING = {
  pro: { monthly: 5, quarterly: 4, yearly: 2 },
  dev: { monthly: 30, quarterly: 25, yearly: 15 },
};

let currentPeriod = 'monthly';

function initBillingToggle() {
  updateBillingSlider('monthly');
}

function switchBillingPeriod(period) {
  if (period === currentPeriod) return;
  currentPeriod = period;

  // Update active button
  document.querySelectorAll('.billing-option').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.period === period);
  });

  // Update slider position
  updateBillingSlider(period);

  // Animate prices
  animatePrice('price-pro', PRICING.pro[period]);
  animatePrice('price-dev', PRICING.dev[period]);

  // Update period labels
  const periodLabel = period === 'monthly' ? '/ month' : period === 'quarterly' ? '/ month, billed quarterly' : '/ month, billed yearly';
  const periodProEl = document.getElementById('period-pro');
  const periodDevEl = document.getElementById('period-dev');
  if (periodProEl) periodProEl.textContent = periodLabel;
  if (periodDevEl) periodDevEl.textContent = periodLabel;

  // Update savings badges
  updateSavings('savings-pro', period, 'pro');
  updateSavings('savings-dev', period, 'dev');
}

function updateBillingSlider(period) {
  const slider = document.getElementById('billing-slider');
  const buttons = document.querySelectorAll('.billing-option');
  let targetBtn = null;

  buttons.forEach(btn => {
    if (btn.dataset.period === period) targetBtn = btn;
  });

  if (targetBtn && slider) {
    const parent = targetBtn.parentElement;
    const parentRect = parent.getBoundingClientRect();
    const btnRect = targetBtn.getBoundingClientRect();
    slider.style.width = btnRect.width + 'px';
    slider.style.transform = `translateX(${btnRect.left - parentRect.left}px)`;
  }
}

function animatePrice(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const startValue = parseFloat(el.textContent) || 0;
  const diff = targetValue - startValue;
  if (diff === 0) return;

  const duration = 800;
  const startTime = performance.now();
  const isDropping = diff < 0;
  const isIncreasing = diff > 0;
  const wrapper = el.parentElement;

  // Apply color state
  if (isDropping) {
    el.classList.add('price-dropping');
    // Trigger subtle strikethrough
    if (wrapper && wrapper.classList.contains('pricing-amount-wrapper')) {
      wrapper.classList.remove('slicing');
      void wrapper.offsetWidth;
      wrapper.classList.add('slicing');
    }
  } else if (isIncreasing) {
    el.classList.add('price-increasing');
  }

  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out cubic for smooth deceleration
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = startValue + diff * eased;

    // Format display value
    if (targetValue === 0) {
      el.textContent = '0';
    } else {
      el.textContent = current.toFixed(2).replace(/\.00$/, '');
    }

    if (progress < 1) {
      requestAnimationFrame(tick);
    } else {
      // Final value
      el.textContent = targetValue === Math.floor(targetValue)
        ? targetValue.toString()
        : targetValue.toFixed(2);

      // Fade color back to white via CSS transition
      el.classList.remove('price-dropping');
      el.classList.remove('price-increasing');

      // Clean up strikethrough
      if (wrapper && wrapper.classList.contains('pricing-amount-wrapper')) {
        setTimeout(() => wrapper.classList.remove('slicing'), 300);
      }
    }
  }

  requestAnimationFrame(tick);
}

function updateSavings(elementId, period, plan) {
  const el = document.getElementById(elementId);
  if (!el) return;

  if (period === 'monthly') {
    el.style.display = 'none';
    return;
  }

  const monthlyPrice = PRICING[plan].monthly;
  const periodPrice = PRICING[plan][period];
  const savedPerMonth = monthlyPrice - periodPrice;
  const savedTotal = period === 'quarterly' ? savedPerMonth * 3 : savedPerMonth * 12;

  el.style.display = 'block';
  el.querySelector('.savings-text').textContent = `Save $${savedTotal.toFixed(0)} ${period === 'quarterly' ? '/ quarter' : '/ year'}`;

  // Animate in
  el.style.animation = 'none';
  el.offsetHeight;
  el.style.animation = 'savingsPop 0.4s ease both';
}
