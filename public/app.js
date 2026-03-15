/* ========================================
   MODIH MAIL — Application Logic
   ======================================== */

// ========== STATE ==========
let currentInbox = null; // { id, email, created_at, owner_token }
let currentMessages = [];
let currentMessageId = null;
let refreshInterval = null;
let isMailWindowOpen = false;

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
    const delay = idx * 800; // stagger each element
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

  // Immediately show elements already in viewport (fixes refresh shift bug)
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

// ========== INBOX CREATION ==========
async function createInbox(type) {
  const prefixInput = document.getElementById("email-prefix");
  const errorEl = document.getElementById("generate-error");
  const btnCustom = document.getElementById("btn-custom");
  const btnRandom = document.getElementById("btn-random");

  errorEl.style.display = "none";

  const body = {};
  if (type === "custom") {
    const prefix = prefixInput.value.trim();
    if (!prefix || prefix.length < 2) {
      showError("Please enter at least 2 characters for your prefix.");
      return;
    }
    body.prefix = prefix;
  }

  // Loading state
  btnCustom.classList.add("loading");
  btnRandom.classList.add("loading");

  try {
    const headers = { "Content-Type": "application/json" };
    // Include owner_token if we have one (for re-claiming own inbox)
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
      if (res.status === 409) {
        showError("That email is already taken. Try another prefix.");
      } else if (res.status === 403) {
        showError(data.error || "This name is reserved.");
      } else {
        showError(data.error || "Failed to create inbox.");
      }
      return;
    }

    // Save state (includes owner_token)
    currentInbox = data;
    currentMessages = [];
    saveSession();

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

function showEmailResult(inbox) {
  document.getElementById("generate-error").style.display = "none";

  const resultEl = document.getElementById("email-result");
  const addressEl = document.getElementById("result-email-address");

  addressEl.textContent = inbox.email;
  resultEl.style.display = "block";

  // Smooth scroll to result
  resultEl.scrollIntoView({ behavior: "smooth", block: "center" });
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
      // Session invalid — inbox deleted or token mismatch
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
  // Don't re-render the list if we're viewing a message detail
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

  // Hide list, show detail
  document.getElementById("mail-list").style.display = "none";
  document.getElementById("mail-empty").style.display = "none";
  const detail = document.getElementById("mail-detail");
  detail.style.display = "block";

  // Fill in detail
  document.getElementById("detail-subject").textContent = msg.subject;
  document.getElementById("detail-from").textContent = msg.from_name
    ? `${msg.from_name} <${msg.from_address}>`
    : msg.from_address;
  document.getElementById("detail-time").textContent = formatTime(msg.received_at);

  // Render body
  const bodyEl = document.getElementById("detail-body");
  if (msg.body_html) {
    // Render sanitized HTML in a sandboxed way
    bodyEl.innerHTML = sanitizeRenderedHtml(msg.body_html);
  } else {
    bodyEl.innerHTML = `<pre style="white-space:pre-wrap;font-family:inherit;">${escapeHtml(msg.body_text)}</pre>`;
  }

  // OTP detection
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

  // Clear everything
  currentInbox = null;
  currentMessages = [];
  currentMessageId = null;
  clearSession();
  stopAutoRefresh();

  // Close mail window if open
  if (isMailWindowOpen) {
    closeMailWindow();
  }

  // Hide the result section
  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";

  // Scroll back to generate section
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

  // Common OTP patterns
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
  // Additional client-side sanitization
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

  // Reset animation
  toast.style.animation = "none";
  toast.offsetHeight; // trigger reflow
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

    // Must have an owner_token to be valid (old sessions without token are cleared)
    if (!inbox.owner_token) {
      clearSession();
      return;
    }

    // Validate with the server by trying to fetch messages
    const res = await fetch(`/api/messages?inbox_id=${inbox.id}`, {
      headers: { "X-Owner-Token": inbox.owner_token },
    });

    if (res.ok) {
      currentInbox = inbox;
      showEmailResult(inbox);
    } else {
      // Token invalid or inbox deleted
      clearSession();
    }
  } catch (e) {
    clearSession();
  }
}
