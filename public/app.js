/* ========================================
   MODIH MAIL — Application Logic
   ======================================== */

// ========== STATE ==========
let currentInbox = null;      // { id, email, created_at, expires_at, owner_token, reserved }
let sessionInboxes = [];      // All inboxes created this session (Pro/Dev multi-inbox)
let inactiveInboxesExpanded = false;
let currentMessages = [];
let currentMessageId = null;
let countdownInterval = null;
let refreshInterval = null;
let accountSyncInterval = null;
let isMailWindowOpen = false;
let turnstileWidgetId = null;
let turnstileRequired = false;
let currentUser = null;       // Firebase user { uid, email, plan }
let blocklistCache = null;    // Cached array of blocked senders (loaded on Pro/Dev signin)
let _lastRenderedMsgIds = ""; // For change detection in renderMailList (no DOM touch when stable)

// Plan helper — returns 'free' | 'pro' | 'developer'
function userPlan() {
  return currentUser?.plan || 'free';
}
function isPaidUser() {
  const p = userPlan();
  return p === 'pro' || p === 'developer';
}

// ========== FIREBASE AUTH ==========
const FIREBASE_CONFIG = {
  apiKey: "AIzaSyDzUpWLWZDn20MlacZHjeBXDe8yyI1QSp4",
  authDomain: "modih-mail.firebaseapp.com",
  projectId: "modih-mail",
  storageBucket: "modih-mail.firebasestorage.app",
  messagingSenderId: "333202273259",
  appId: "1:333202273259:web:279c458fa1c57b99d81fae"
};

let firebaseAuth = null;

function initFirebase() {
  try {
    if (typeof firebase !== 'undefined') {
      if (!firebase.apps.length) firebase.initializeApp(FIREBASE_CONFIG);
      firebaseAuth = firebase.auth();

      firebaseAuth.onAuthStateChanged(async (user) => {
        if (user) {
          try {
            const token = await user.getIdToken(); // cached token — reliable, no network required
            const res = await fetch('/api/auth/me', {
              headers: { 'Authorization': `Bearer ${token}` },
              cache: 'no-store'
            });
            if (res.ok) {
              const data = await res.json();
              currentUser = { uid: data.uid, email: data.email, plan: data.plan };
              console.log('[Auth] Plan from backend:', data.plan);
            } else {
              const errData = await res.json().catch(() => ({}));
              console.error('[Auth] /api/auth/me error:', res.status, errData);
              currentUser = { uid: user.uid, email: user.email, plan: 'free' };
            }
          } catch (e) {
            console.error('[Auth] Token fetch failed:', e);
            currentUser = { uid: user.uid, email: user.email, plan: 'free' };
          }
        } else {
          currentUser = null;
        }
        renderNavAuth();
      });
    }
  } catch (e) {
    console.error('Firebase init error:', e);
  }
}

function renderNavAuth() {
  const area = document.getElementById('nav-auth-area');
  if (!area) return;

  if (currentUser) {
    const planClass = currentUser.plan === 'pro' ? 'pro' : currentUser.plan === 'developer' ? 'developer' : '';
    const rawEmail = currentUser.email || '';
    const safeEmail = escapeHtml(rawEmail);
    const short = escapeHtml(rawEmail ? rawEmail.split('@')[0].slice(0, 14) : 'Account');
    const planLabel = currentUser.plan === 'developer' ? 'Dev' : currentUser.plan === 'pro' ? 'Pro' : 'Free';
    const devLinkDesktop = currentUser.plan === 'developer'
      ? `<a href="/developer.html" style="font-size:0.72rem;color:var(--text-muted);text-decoration:none;border-left:1px solid rgba(255,255,255,0.1);padding-left:0.5rem;transition:color 0.2s;" onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-muted)'">API</a>`
      : '';
    const devLinkMobile = currentUser.plan === 'developer'
      ? `<a href="/developer.html" class="nav-mobile-menu-link">🔑 API Dashboard</a>`
      : '';
    area.innerHTML = `
      <!-- Desktop pill (hidden on mobile) -->
      <div class="nav-auth-desktop">
        <span class="nav-plan-dot ${planClass}" title="${planLabel} plan"></span>
        <span class="nav-user-email" title="${safeEmail}">${short}</span>
        <span style="font-size:0.68rem;color:var(--text-muted);border-left:1px solid rgba(255,255,255,0.1);padding-left:0.5rem;">${planLabel}</span>
        ${devLinkDesktop}
        <button class="nav-sign-out-btn" onclick="handleSignOut()">Sign Out</button>
      </div>
      <!-- Mobile hamburger (shown only on mobile) -->
      <button class="nav-hamburger" id="nav-hamburger-btn" onclick="toggleMobileNav()" aria-label="Menu" aria-expanded="false">
        <span class="nav-plan-dot ${planClass}"></span>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
        </svg>
      </button>
      <!-- Mobile dropdown -->
      <div class="nav-mobile-menu" id="nav-mobile-menu">
        <div class="nav-mobile-menu-user">
          <span class="nav-plan-dot ${planClass}"></span>
          <span title="${safeEmail}">${safeEmail || short}</span>
          <span class="nav-mobile-plan-badge ${planClass}">${planLabel}</span>
        </div>
        ${devLinkMobile}
        <button class="nav-mobile-signout" onclick="handleSignOut()">Sign Out</button>
      </div>`;
  } else {
    area.innerHTML = `
      <div style="display:flex;gap:0.5rem;align-items:center;">
        <a href="/signup.html" class="nav-sign-in-btn">Sign Up</a>
      </div>`;
  }

  // Update pricing CTAs and custom prefix state based on plan
  const plan = currentUser?.plan || 'free';
  updatePricingUI(plan);
  updatePrefixUI(plan);

  // Update auto-expire stat bubble
  const expireStat = document.getElementById('stat-expire-label');
  if (expireStat) {
    expireStat.textContent = plan === 'developer' ? '30d' : plan === 'pro' ? '7d' : '3h';
  }

  // Reveal Pro-only mail-window buttons (block list, reserve) when paid.
  const proOnly = document.querySelectorAll('.pro-only');
  proOnly.forEach((el) => {
    el.style.display = (plan === 'pro' || plan === 'developer') ? '' : 'none';
  });

  // Account history: every signed-in user gets their server-side address
  // history, while paid users also unlock Pro-only mail controls.
  if (firebaseAuth?.currentUser) {
    syncInboxesFromServer().catch((e) => console.warn('[Sync] failed:', e?.message));
    startAccountSync();
  } else {
    stopAccountSync();
  }
  if ((plan === 'pro' || plan === 'developer') && firebaseAuth?.currentUser) {
    fetchBlocklist().catch((e) => console.warn('[Blocklist] fetch failed:', e?.message));
  }

  // Update generate section description
  const genDesc = document.getElementById('generate-section-desc');
  if (genDesc) {
    if (plan === 'developer') {
      genDesc.textContent = 'Generate or name a custom inbox — stays active for 30 days. Use the API for automation.';
    } else if (plan === 'pro') {
      genDesc.textContent = 'Generate a random address or enter a custom prefix — your inbox stays active for 7 days.';
    } else {
      genDesc.textContent = 'Generate a random address — your inbox will be ready instantly. Free plan: 3 inboxes per day.';
    }
  }

  // Show/hide Developer API callout in generate section
  const devCallout = document.getElementById('dev-api-callout');
  if (devCallout) {
    devCallout.style.display = plan === 'developer' ? 'block' : 'none';
  }
}

// ========== PLAN-AWARE PRICING UI ==========
function updatePricingUI(plan) {
  const ctaFree = document.getElementById('cta-free');
  const ctaPro  = document.getElementById('cta-pro');
  const ctaDev  = document.getElementById('cta-developer');

  function markCurrent(btn) {
    if (!btn) return;
    btn.onclick = null;
    btn.style.cssText = 'background:rgba(52,211,153,0.12);border:1px solid rgba(52,211,153,0.35);color:#34d399;cursor:default;';
    btn.innerHTML = '<span>\u2713 Current Plan</span>';
  }

  function markFreeDefault(btn) {
    if (!btn) return;
    btn.onclick = () => scrollToSection('generate');
    btn.style.cssText = '';
    btn.innerHTML = '<span>Get Started Free</span>';
  }

  function markUpgrade(btn, planKey) {
    if (!btn) return;
    btn.onclick = () => handleUpgradeClick(planKey);
    btn.style.cssText = '';
    btn.innerHTML = planKey === 'pro'
      ? '<span>Upgrade to Pro \u2197</span><span style="font-size:0.65rem;font-weight:400;opacity:0.7;">(Contact Sales)</span>'
      : '<span>Contact Sales \u2197</span>';
  }

  if (plan === 'pro') {
    markFreeDefault(ctaFree);
    markCurrent(ctaPro);
    markUpgrade(ctaDev, 'developer');
  } else if (plan === 'developer') {
    markFreeDefault(ctaFree);
    markUpgrade(ctaPro, 'pro');
    markCurrent(ctaDev);
  } else {
    // Free (default / not logged in)
    markCurrent(ctaFree);
    markUpgrade(ctaPro, 'pro');
    markUpgrade(ctaDev, 'developer');
  }
}

// ========== PLAN-AWARE CUSTOM PREFIX UI ==========
function updatePrefixUI(plan) {
  const isPro = plan === 'pro' || plan === 'developer';
  const prefixInput = document.getElementById('email-prefix');
  const customBtn = document.getElementById('btn-custom');
  const proBadgePill = document.querySelector('.pro-input-badge');
  const proBtnBadge = document.querySelector('.pro-btn-badge');

  if (isPro) {
    // Unlock the custom prefix field
    if (prefixInput) {
      prefixInput.disabled = false;
      prefixInput.placeholder = 'Your custom prefix';
    }
    if (customBtn) {
      customBtn.disabled = false;
      customBtn.classList.remove('btn-pro-lock');
    }
    // Hide PRO badges — they're now unlocked
    if (proBadgePill) proBadgePill.style.display = 'none';
    if (proBtnBadge) proBtnBadge.style.display = 'none';
  } else {
    // Re-lock for free users
    if (prefixInput) {
      prefixInput.disabled = true;
      prefixInput.placeholder = 'Custom prefix';
    }
    if (customBtn) {
      customBtn.disabled = true;
      customBtn.classList.add('btn-pro-lock');
    }
    if (proBadgePill) proBadgePill.style.display = '';
    if (proBtnBadge) proBtnBadge.style.display = '';
  }
}

async function handleSignOut() {
  if (firebaseAuth) {
    await firebaseAuth.signOut();
  }
  currentUser = null;
  stopAccountSync();
  clearSession();
  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";
  renderNavAuth();
  showToast('Signed out');
}

// ========== MOBILE NAV TOGGLE ==========
function toggleMobileNav() {
  const menu = document.getElementById('nav-mobile-menu');
  const btn = document.getElementById('nav-hamburger-btn');
  if (!menu) return;
  const isOpen = menu.classList.toggle('open');
  if (btn) btn.setAttribute('aria-expanded', String(isOpen));
  if (isOpen) {
    // Close when clicking outside
    setTimeout(() => {
      document.addEventListener('click', function closeMobileNav(e) {
        if (!menu.contains(e.target) && (!btn || !btn.contains(e.target))) {
          menu.classList.remove('open');
          if (btn) btn.setAttribute('aria-expanded', 'false');
        }
        document.removeEventListener('click', closeMobileNav);
      });
    }, 10);
  }
}

// ========== UPGRADE CLICK HANDLER ==========
// If user is logged in → open contact modal (contact sales)
// If not logged in → redirect to signup with plan param
function handleUpgradeClick(plan) {
  if (currentUser) {
    openContactModal(plan);
  } else {
    window.location.href = `/signup.html?plan=${plan}&redirect=${encodeURIComponent(window.location.pathname)}`;
  }
}

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

// ========== VIDEO CONTROLLER ==========
function initVideoController() {
  // On mobile: skip video entirely — poster image prevents scroll lag caused by
  // GPU compositing layers (will-change + position:fixed) on iOS Safari.
  if (window.innerWidth <= 768) return;

  const video = document.getElementById('bg-video');
  if (!video) return;

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
  initFirebase(); // Firebase auth + nav rendering

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
async function authHeaders() {
  const headers = {};
  if (currentInbox?.owner_token) {
    headers["X-Owner-Token"] = currentInbox.owner_token;
  }
  if (currentInbox?.access_via_auth || !currentInbox?.owner_token) {
    return authedHeaders(headers);
  }
  return headers;
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

  // Refuse to render with a missing/placeholder site key. A bogus key here
  // would silently fail and break inbox creation for free-tier users — better
  // to skip the captcha and let the server reject the request with a clear
  // error so the operator sees the misconfiguration in logs.
  const siteKey = window.TURNSTILE_SITE_KEY;
  if (!siteKey || typeof siteKey !== "string" || siteKey.length < 10) {
    console.warn("[Turnstile] No site key configured — captcha disabled.");
    return;
  }

  // Render turnstile widget
  if (window.turnstile) {
    turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
      sitekey: siteKey,
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

  // Block custom prefix for free users only
  if (type === "custom") {
    const plan = currentUser?.plan || 'free';
    if (plan !== 'pro' && plan !== 'developer') {
      upgradeEl.style.display = "block";
      upgradeEl.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
  }

  // Loading state — button spinners + a skeleton card so the page never
  // looks frozen during the API round-trip (D1 + KV writes typically take
  // 1–3s). The skeleton appears immediately and is replaced by the real
  // address as soon as `showEmailResult` runs.
  btnCustom.classList.add("loading");
  btnRandom.classList.add("loading");
  showGeneratingSkeleton();

  try {
    const body = {};

    // For custom inboxes, grab the text from the prefix input
    if (type === "custom") {
      const prefixInput = document.getElementById("email-prefix");
      const requestedPrefix = prefixInput ? prefixInput.value.trim() : "";
      if (!requestedPrefix) {
        showError("Please enter a custom prefix.");
        btnCustom.classList.remove("loading");
        btnRandom.classList.remove("loading");
        return;
      }
      body.prefix = requestedPrefix;
    }

    // Include Turnstile token if widget is visible
    const turnstileToken = getTurnstileToken();
    if (turnstileToken) {
      body.turnstile_token = turnstileToken;
    }

    const headers = {
      "Content-Type": "application/json",
      "X-Browser-Token": getBrowserToken(),
    };

    // Pass Firebase token so backend can verify plan (Pro/Dev features)
    if (firebaseAuth?.currentUser) {
      try {
        const token = await firebaseAuth.currentUser.getIdToken();
        headers["Authorization"] = `Bearer ${token}`;
      } catch (e) {
        // Non-fatal — backend will default to free plan
        console.warn("[Inbox] Could not get auth token:", e.message);
      }
    }

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
      hideGeneratingSkeleton();
      // Handle specific free-tier errors (new envelope: data.error.{code,message,...})
      if (data.error?.upgrade_required) {
        showUpgradeError(data.error.message, data.error.feature);
        return;
      }
      if (data.error?.code === 'CAPTCHA_REQUIRED') {
        showError(data.error.message || "Please complete the verification challenge.");
        showTurnstile();
        return;
      }
      if (res.status === 429) {
        showError(data.error?.message || "Rate limit exceeded. Try again later.");
        return;
      }
      showError(data.error?.message || "Failed to create inbox.");
      return;
    }

    // Unwrap new envelope: { success, data: {...}, meta: { request_id } }
    const inboxData = data.data || data; // fallback keeps old single-tab sessions working
    currentInbox = inboxData;
    currentMessages = [];

    // Use plan from backend response OR currentUser (whichever is available)
    const backendPlan = inboxData.plan || 'free';
    const currentPlan = currentUser?.plan || 'free';

    // If backend knows we are pro but frontend didn't (e.g. admin upgrade without reload),
    // instantly update the frontend state so the UI (like "3 inboxes per day" text) updates!
    if (backendPlan !== 'free' && currentUser && currentPlan === 'free') {
      currentUser.plan = backendPlan;
      renderNavAuth(); // Instantly clears the "Free plan: 3 inboxes per day" text!
    }

    const finalPlan = currentUser?.plan || backendPlan;
    const isPaid = finalPlan === 'pro' || finalPlan === 'developer';

    if (isPaid || currentUser) {
      // Signed-in users get address history, so keep previous rows and merge
      // the newly-created inbox instead of wiping the account list.
      if (!sessionInboxes.find(i => i.id === inboxData.id)) {
        sessionInboxes.push(inboxData);
      }
    } else {
      // Free: only track current one
      sessionInboxes = [inboxData];
    }

    saveSession();

    // Update creation counter
    if (inboxData.creations_today !== undefined) {
      showCreationCounter(inboxData.creations_today, inboxData.max_creations);
    }

    // Show/hide turnstile based on server response
    if (inboxData.turnstile_required) {
      turnstileRequired = true;
      showTurnstile();
    } else {
      hideTurnstile();
    }

    // Show result
    showEmailResult(inboxData);
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

// Show a shimmering placeholder card the instant the user clicks
// "Random / Custom" so the UI doesn't appear frozen during the inbox
// creation round-trip. `showEmailResult` replaces the content on success
// and `hideGeneratingSkeleton` clears it on error.
function showGeneratingSkeleton() {
  const resultEl = document.getElementById("email-result");
  if (!resultEl) return;
  resultEl.classList.add("is-generating");
  const addressEl = document.getElementById("result-email-address");
  if (addressEl) {
    addressEl.textContent = "Generating your inbox\u2026";
  }
  resultEl.style.display = "block";
  // Smoothly bring it into view so the user sees the loading state immediately.
  resultEl.scrollIntoView({ behavior: "smooth", block: "center" });
}

function hideGeneratingSkeleton() {
  const resultEl = document.getElementById("email-result");
  if (!resultEl) return;
  resultEl.classList.remove("is-generating");
  // Only hide if we never got real data (i.e. address is still the placeholder).
  if (currentInbox) return;
  resultEl.style.display = "none";
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

  resultEl.classList.remove("is-generating");
  addressEl.textContent = inbox.email;
  resultEl.style.display = "block";

  // Update expire hint dynamically
  const hintEl = document.getElementById('result-expire-hint');
  if (hintEl) {
    const plan = currentUser?.plan;
    if (plan === 'developer') {
      hintEl.textContent = 'Your inbox is active for 30 days. Enjoy Developer! ✦';
    } else if (plan === 'pro' || (inbox.expires_at && inbox.expires_at - inbox.created_at > 6 * 24 * 60 * 60)) {
      hintEl.textContent = 'Your inbox is active for 7 days. Enjoy Pro! ✦';
    } else {
      hintEl.textContent = 'Your inbox will auto-expire after 3 hours. Upgrade to Pro for 7-day retention.';
    }
  }
  // Render the inbox tab strip (for Pro/Dev with multiple inboxes)
  renderInboxTabs();

  // Start countdown if we have an expiry
  if (inbox.expires_at) {
    startCountdown(inbox.expires_at);
  }

  // Smooth scroll to result
  resultEl.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ========== INBOX TAB SWITCHER (Pro/Dev) ==========
function isInboxExpired(inbox, now = Math.floor(Date.now() / 1000)) {
  return !!inbox?.expires_at && inbox.expires_at > 0 && inbox.expires_at <= now;
}

function isInboxUsable(inbox, now = Math.floor(Date.now() / 1000)) {
  return !!inbox?.id && !!inbox?.email && (!!inbox?.owner_token || !!inbox?.access_via_auth) && !isInboxExpired(inbox, now) && !inbox.inactive_reason;
}

function inactiveLabelForInbox(inbox) {
  if (isInboxExpired(inbox)) return 'Expired';
  if (inbox?.inactive_reason) return inbox.inactive_reason;
  if (!inbox?.owner_token && !inbox?.access_via_auth) return 'Unavailable';
  return 'Inactive';
}

function getInboxBuckets() {
  const now = Math.floor(Date.now() / 1000);
  const byId = new Map();
  for (const inbox of sessionInboxes) {
    if (!inbox?.id) continue;
    const previous = byId.get(inbox.id) || {};
    byId.set(inbox.id, { ...previous, ...inbox });
  }

  const sorted = Array.from(byId.values()).sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return {
    active: sorted.filter((inbox) => isInboxUsable(inbox, now)),
    inactive: sorted.filter((inbox) => !isInboxUsable(inbox, now)),
  };
}

function renderInboxRow(inbox, options = {}) {
  const { active = false, disabled = false } = options;
  const isViewing = currentInbox?.id === inbox.id;
  const reserved = !!inbox.reserved;
  const safeEmail = escapeHtml(inbox.email || '');
  const safeIdArg = escapeHtml(JSON.stringify(String(inbox.id || '')));
  const createdAt = inbox.created_at ? new Date(inbox.created_at * 1000).toLocaleDateString() : 'Unknown date';
  const statusText = escapeHtml(disabled ? inactiveLabelForInbox(inbox) : (isViewing ? 'Viewing' : 'Open'));
  const reserveAction = !disabled && isPaidUser()
    ? `<button class="inbox-tab-mini-action ${reserved ? 'is-reserved' : ''}" type="button" onclick="toggleReserveInbox(${safeIdArg}, event)" title="${reserved ? 'Remove reservation' : 'Reserve alias'}">${reserved ? 'Reserved' : 'Reserve'}</button>`
    : '';
  const rowClass = [
    'inbox-tab',
    active && isViewing ? 'active' : '',
    disabled ? 'is-inactive' : '',
  ].filter(Boolean).join(' ');
  const actionAttrs = disabled
    ? 'aria-disabled="true"'
    : `onclick="switchToInbox(${safeIdArg})" role="button" tabindex="0" aria-current="${isViewing ? 'true' : 'false'}"`;

  return `
    <div class="${rowClass}" ${actionAttrs}>
      <div class="inbox-tab-content">
        <span class="inbox-tab-email">${safeEmail}</span>
        <span class="inbox-tab-meta">
          <span>Created ${createdAt}</span>
          ${reserved && disabled ? '<span class="reserved-flag">Reserved</span>' : ''}
        </span>
      </div>
      <div class="inbox-tab-actions">
        ${reserveAction}
        <span class="inbox-tab-pill ${disabled ? 'is-muted' : ''}">${statusText}</span>
      </div>
    </div>`;
}

// Renders live inboxes separately from previous/unusable ones so stale rows do
// not compete with the inbox the user can actually open in this browser.
function renderInboxTabs() {
  const tabEl = document.getElementById('inbox-tabs');
  if (!tabEl) return;

  const { active, inactive } = getInboxBuckets();
  const total = active.length + inactive.length;

  if (total < 2 && inactive.length === 0) {
    tabEl.style.display = 'none';
    tabEl.className = '';
    tabEl.innerHTML = '';
    return;
  }

  tabEl.className = 'inbox-tabs-wrap';
  tabEl.style.display = 'flex';

  const activeHtml = active.length
    ? active.map((inbox) => renderInboxRow(inbox, { active: true })).join('')
    : '<div class="inbox-tabs-empty">No active inbox in this browser.</div>';

  const historyToggleLabel = currentUser ? 'Email address history' : 'Previous inactive inboxes';
  const inactiveHtml = inactive.length ? `
    <button class="inbox-history-toggle" type="button" onclick="toggleInactiveInboxes()" aria-expanded="${inactiveInboxesExpanded ? 'true' : 'false'}">
      <span>${historyToggleLabel}</span>
      <span class="inbox-history-count">${inactive.length}</span>
      <span class="inbox-history-chevron">${inactiveInboxesExpanded ? '-' : '+'}</span>
    </button>
    <div class="inbox-history-menu${inactiveInboxesExpanded ? ' open' : ''}">
      ${inactive.map((inbox) => renderInboxRow(inbox, { disabled: true })).join('')}
    </div>` : '';

  tabEl.innerHTML = `
    <div class="inbox-tabs-header">
      <div>
        <div class="inbox-tabs-label">Active inboxes</div>
        <div class="inbox-tabs-subtitle">${active.length} ready to view</div>
      </div>
    </div>
    <div class="inbox-tabs-active-list">${activeHtml}</div>
    ${inactiveHtml}`;
}

function toggleInactiveInboxes() {
  inactiveInboxesExpanded = !inactiveInboxesExpanded;
  renderInboxTabs();
}

function switchToInbox(inboxId) {
  const inbox = sessionInboxes.find(i => i.id === inboxId);
  if (!inbox || currentInbox?.id === inboxId) return;
  if (!isInboxUsable(inbox)) {
    showToast("That inbox is no longer active in this browser.");
    renderInboxTabs();
    return;
  }
  currentInbox = inbox;
  currentMessages = [];
  saveSession();
  showEmailResult(inbox);
  fetchMessages();
}

async function toggleReserveInbox(inboxId, event) {
  event?.stopPropagation?.();
  const inbox = sessionInboxes.find(i => i.id === inboxId);
  if (!inbox || !isInboxUsable(inbox)) return;
  const previousId = currentInbox?.id;
  currentInbox = inbox;
  await toggleReserveCurrent();
  if (previousId && previousId !== inboxId) {
    currentInbox = sessionInboxes.find(i => i.id === previousId) || currentInbox;
    saveSession();
  }
  renderInboxTabs();
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
  if (currentInbox) currentInbox.inactive_reason = 'Expired';
  const expiredId = currentInbox?.id;
  if (expiredId) {
    const stored = sessionInboxes.find((i) => i.id === expiredId);
    if (stored) stored.inactive_reason = 'Expired';
  }
  currentInbox = null;
  currentMessages = [];
  saveSession();
  renderInboxTabs();

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
      headers: await authHeaders(),
    });
    const data = await res.json();

    if (res.status === 403 || res.status === 404) {
      handleSessionInvalid();
      return;
    }

    if (!res.ok) return;

    currentMessages = data.data?.messages || data.messages || [];
    renderMailList();
  } catch (e) {
    console.error("Fetch messages error:", e);
  }
}

function handleSessionInvalid() {
  if (currentInbox) currentInbox.inactive_reason = 'Unavailable';
  const invalidId = currentInbox?.id;
  if (invalidId) {
    const stored = sessionInboxes.find((i) => i.id === invalidId);
    if (stored) stored.inactive_reason = 'Unavailable';
  }
  currentInbox = null;
  currentMessages = [];
  saveSession();
  renderInboxTabs();

  if (isMailWindowOpen) {
    closeMailWindow();
  }

  const resultEl = document.getElementById("email-result");
  if (resultEl) resultEl.style.display = "none";

  showToast("Session expired or inbox deleted. Create a new one.");
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  // Bumped from 5s -> 12s. With the diff renderer + change detection below,
  // a stable inbox now produces ZERO DOM mutations per poll (no visible
  // refresh activity). Most mail providers deliver in 2-15s anyway, so 12s
  // strikes the right balance between snappy delivery and battery / network
  // friendliness.
  refreshInterval = setInterval(fetchMessages, 12000);
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
//
// Diff-based renderer with CHANGE DETECTION. Previously, even though we kept
// keyed DOM nodes, every 5s poll would still walk the list and update text
// nodes in place — visually a no-op but enough to trigger micro-repaints that
// the user perceived as "blinking every 5 seconds". We now compute a tiny
// fingerprint of the current message id-set + the list length and skip ALL
// work when nothing changed. The empty-state also won't get re-toggled when
// it's already empty.
function renderMailList() {
  if (currentMessageId) return;

  const listEl = document.getElementById("mail-list");
  const emptyEl = document.getElementById("mail-empty");

  // Apply client-side block list filter (paid users only — free users have
  // no UI to add blocklist entries so blocklistCache is always null).
  const visible = filterMessagesByBlocklist(currentMessages);

  // Cheap content-fingerprint. We only care about identity changes; new mail
  // arrives with a new id at the front, so this string changes only when the
  // set / order of messages changes. Read-state could be added later.
  const fingerprint = visible.map((m) => m.id).join("|");
  if (fingerprint === _lastRenderedMsgIds) {
    // Update the per-row relative time without touching the rest of the DOM.
    // formatTimeAgo only emits a new string when crossing a boundary (s→m→h),
    // so most polls produce zero text-node writes here.
    for (const msg of visible) {
      const node = listEl.querySelector(`[data-msg-id="${msg.id}"]`);
      if (node) updateMailItemNode(node, msg);
    }
    return;
  }

  if (visible.length === 0) {
    if (listEl.children.length > 0) listEl.innerHTML = "";
    listEl.style.display = "none";
    if (emptyEl.style.display !== "flex") emptyEl.style.display = "flex";
    _lastRenderedMsgIds = "";
    return;
  }

  emptyEl.style.display = "none";
  listEl.style.display = "flex";

  const existing = new Map();
  for (const node of Array.from(listEl.children)) {
    const id = node.getAttribute("data-msg-id");
    if (id) existing.set(id, node);
    else node.remove();
  }

  const seen = new Set();
  let prevNode = null;

  visible.forEach((msg, index) => {
    const id = String(msg.id);
    seen.add(id);
    let node = existing.get(id);
    if (!node) {
      node = buildMailItemNode(msg, index);
      // Insert in correct position to preserve order without re-creating siblings.
      if (prevNode && prevNode.nextSibling) {
        listEl.insertBefore(node, prevNode.nextSibling);
      } else if (prevNode) {
        listEl.appendChild(node);
      } else {
        listEl.insertBefore(node, listEl.firstChild);
      }
    } else {
      // Refresh the relative time in place (no reflow of the whole row).
      updateMailItemNode(node, msg, index);
    }
    prevNode = node;
  });

  // Remove nodes for messages that no longer exist.
  for (const [id, node] of existing) {
    if (!seen.has(id)) node.remove();
  }
}

function buildMailItemNode(msg, index) {
  const node = document.createElement("div");
  node.className = "mail-item mail-item-new";
  node.setAttribute("data-msg-id", String(msg.id));
  node.setAttribute("data-index", String(index));
  node.addEventListener("click", () => openMessageByIndex(Number(node.getAttribute("data-index"))));
  // Fresh items animate in; we strip the class on animation end so future
  // refreshes don't re-trigger the slide.
  node.addEventListener("animationend", () => node.classList.remove("mail-item-new"), { once: true });
  node.style.setProperty("--mail-item-delay", `${Math.min(index, 6) * 0.05}s`);

  const fromDisplay = msg.from_name || msg.from_address;
  const initial = (fromDisplay || "?").charAt(0).toUpperCase();
  const otp = extractOTP((msg.subject || "") + " " + (msg.body_text || "") + " " + (msg.body_html || ""));

  node.innerHTML = `
    <div class="mail-item-avatar">${initial}</div>
    <div class="mail-item-content">
      <div class="mail-item-top">
        <span class="mail-item-from"></span>
        <span class="mail-item-time" data-received="${msg.received_at}"></span>
      </div>
      <div class="mail-item-subject"></div>
      ${otp ? `<div class="mail-item-otp">🔑 OTP: ${escapeHtml(otp)}</div>` : ""}
    </div>
  `;
  node.querySelector(".mail-item-from").textContent = fromDisplay;
  node.querySelector(".mail-item-subject").textContent = msg.subject;
  node.querySelector(".mail-item-time").textContent = formatTimeAgo(msg.received_at);
  return node;
}

function updateMailItemNode(node, msg, index) {
  node.setAttribute("data-index", String(index));
  const timeEl = node.querySelector(".mail-item-time");
  if (timeEl) timeEl.textContent = formatTimeAgo(msg.received_at);
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
  detail.scrollTop = 0;

  document.getElementById("detail-subject").textContent = msg.subject;
  document.getElementById("detail-from").textContent = msg.from_name
    ? `${msg.from_name} <${msg.from_address}>`
    : msg.from_address;
  document.getElementById("detail-time").textContent = formatTime(msg.received_at);

  const bodyEl = document.getElementById("detail-body");
  renderMessageBody(bodyEl, msg);

  const otp = extractOTP(msg.subject + " " + (msg.body_text || "") + " " + (msg.body_html || ""));
  const otpEl = document.getElementById("detail-otp");
  if (otp) {
    otpEl.style.display = "flex";
    document.getElementById("detail-otp-code").textContent = otp;
  } else {
    otpEl.style.display = "none";
  }
}

// Render an email body inside an isolated sandboxed iframe with a clean,
// light "paper" surface. This is how mature webmail clients (Gmail, Yahoo,
// Apple Mail) render messages — emails ship their own colors and fonts that
// usually assume a light background, and stuffing them into the page's dark
// glass card produces unreadable dark-on-dark text (verification codes,
// hyperlinks, etc.).
//
// The iframe has `sandbox="allow-same-origin"` only — no allow-scripts, so
// any active content surviving the sanitizer can't execute. Height is
// observed and synced to the content so the iframe doesn't show an inner
// scrollbar.
function renderMessageBody(host, msg) {
  host.innerHTML = "";
  host.classList.add("detail-body-paper");

  const iframe = document.createElement("iframe");
  iframe.className = "detail-body-frame";
  iframe.setAttribute("sandbox", "allow-same-origin");
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.setAttribute("title", "Message body");
  iframe.setAttribute("loading", "eager");
  iframe.style.width = "100%";
  iframe.style.border = "0";
  iframe.style.display = "block";
  iframe.style.height = "120px";
  iframe.style.colorScheme = "light";
  host.appendChild(iframe);

  const bodyHtml = (typeof msg.body_html === "string" && msg.body_html.trim())
    ? sanitizeRenderedHtml(msg.body_html)
    : null;
  const bodyText = typeof msg.body_text === "string" ? msg.body_text : "";

  // Real `<img>` tags survive the server sanitizer now (only tracking
  // pixels are stripped). For older messages stored back when the
  // sanitizer wrote the literal text "[image removed]" we still swap that
  // for a small styled pill so it doesn't read as a broken word.
  const inner = bodyHtml
    ? bodyHtml.replace(
        /\[image removed\]/g,
        '<span class="image-placeholder" aria-label="Image blocked for privacy">image hidden</span>'
      )
    : `<pre class="plain-text-body">${escapeHtml(bodyText)}</pre>`;

  const srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><base target="_blank"><style>${MESSAGE_FRAME_CSS}</style></head><body>${inner}</body></html>`;
  iframe.srcdoc = srcdoc;

  const syncHeight = () => {
    try {
      const doc = iframe.contentDocument;
      if (!doc) return;
      const target = doc.body || doc.documentElement;
      const h = Math.max(
        target.scrollHeight,
        target.offsetHeight,
        doc.documentElement.scrollHeight
      );
      iframe.style.height = `${Math.max(h + 16, 120)}px`;
    } catch {
      /* cross-origin or detached — ignore */
    }
  };

  iframe.addEventListener("load", () => {
    syncHeight();
    try {
      const doc = iframe.contentDocument;
      if (!doc) return;
      // Re-measure when images / fonts arrive.
      if (typeof ResizeObserver === "function" && doc.body) {
        const ro = new ResizeObserver(syncHeight);
        ro.observe(doc.body);
        iframe._modihResizeObserver = ro;
      }
      // Force external links to open in a new tab and block javascript: hrefs
      // that may have survived (defense in depth — sanitizer already neutralises them).
      doc.querySelectorAll("a").forEach((a) => {
        const href = a.getAttribute("href") || "";
        if (/^\s*(javascript|vbscript|livescript|data|blob|file|blocked):/i.test(href)) {
          a.removeAttribute("href");
          a.style.pointerEvents = "none";
          a.style.opacity = "0.6";
          a.title = "Link blocked for safety";
        } else if (href) {
          a.setAttribute("target", "_blank");
          a.setAttribute("rel", "noopener noreferrer");
        }
      });
    } catch {
      /* ignore */
    }
  });
}

// `sanitizeRenderedHtml` replaces every `<img>` with the literal string
// "[image removed]". Inside an `<a>` tag wrapping a tracking pixel this
// renders as a clickable orange word, which looks like a broken link.
// Wrap it in a styled span so it reads as a visual placeholder instead.
function prettifyImagePlaceholders(html) {
  if (typeof html !== "string") return "";
  return html.replace(/\[image removed\]/g,
    '<span class="image-placeholder" aria-label="Image blocked for privacy">🛡️ image hidden</span>'
  );
}

// CSS injected into the message-body iframe. A neutral, readable "paper"
// surface that ignores the dark page theme. Constraints applied to images
// and tables prevent runaway-wide emails from bursting the layout.
const MESSAGE_FRAME_CSS = `
  :root { color-scheme: light; }
  html, body {
    margin: 0;
    padding: 18px 20px;
    background: #ffffff;
    color: #1f2937;
    font: 15px/1.65 -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    word-wrap: break-word;
    overflow-wrap: anywhere;
  }
  body { max-width: 100%; }
  a { color: #2563eb; text-decoration: underline; word-break: break-all; }
  a:hover { color: #1d4ed8; }
  p { margin: 0 0 0.9em; }
  h1, h2, h3, h4, h5, h6 { color: #111827; margin: 1.1em 0 0.55em; line-height: 1.3; }
  ul, ol { padding-left: 1.4em; margin: 0 0 0.9em; }
  li { margin: 0.25em 0; }
  pre, code, kbd, samp {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    background: #f3f4f6;
    color: #111827;
    border-radius: 6px;
    padding: 1px 6px;
  }
  pre.plain-text-body {
    white-space: pre-wrap;
    background: transparent;
    padding: 0;
    margin: 0;
    font: inherit;
    color: inherit;
  }
  blockquote {
    border-left: 3px solid #d1d5db;
    margin: 0.6em 0;
    padding: 0.2em 0 0.2em 0.9em;
    color: #4b5563;
  }
  hr { border: 0; border-top: 1px solid #e5e7eb; margin: 1.2em 0; }
  table { border-collapse: collapse; max-width: 100%; }
  td, th { padding: 6px 10px; border: 1px solid #e5e7eb; }
  img, video, iframe, object { max-width: 100% !important; height: auto !important; border-radius: 6px; }
  .image-placeholder {
    display: inline-flex;
    align-items: center;
    gap: 0.35em;
    padding: 2px 10px;
    margin: 2px 0;
    font-size: 0.8em;
    font-weight: 500;
    color: #6b7280;
    background: #f3f4f6;
    border: 1px dashed #d1d5db;
    border-radius: 100px;
  }
  /* Force-recolor common dark-on-dark email templates whose own inline
     styles assumed a dark host page. Email authors rarely set background
     AND color together, so a default light background + a default dark
     text color produces the closest thing to "open in any mail client". */
  body, body * { background-color: transparent !important; }
  body { background: #ffffff !important; }
`;

function closeMessageDetail() {
  document.getElementById("mail-detail").style.display = "none";
  currentMessageId = null;
  // Force re-render after closing a detail view since we skipped renders
  // while the detail was open.
  _lastRenderedMsgIds = "";
  renderMailList();
}

// Context-aware Back button in the mail-window header. If a message detail
// is open, go back to the inbox list (not all the way to the landing page).
// If we're on the inbox list, close the mail window.
function mailHeaderBack() {
  if (currentMessageId) {
    closeMessageDetail();
  } else {
    closeMailWindow();
  }
}

// ========== DELETE ADDRESS & RESET ==========
async function deleteAddressAndReset() {
  if (!currentInbox) return;

  const ok = await showConfirm({
    title: "Delete this address?",
    message: "This permanently removes the address and every message inside it. You'll need to create a new one to receive mail again.",
    okLabel: "Delete address",
    danger: true,
  });
  if (!ok) return;

  let deleteOk = false;
  try {
    const res = await fetch(`/api/inbox?id=${currentInbox.id}`, {
      method: "DELETE",
      headers: await authHeaders(),
    });
    deleteOk = res.ok;
    if (!deleteOk) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error?.message || data.error || "Failed to delete address. Please try again.");
      return; // Keep local state — inbox is still live on the server
    }
  } catch (e) {
    console.error("Delete inbox error:", e);
    showToast("Network error. Could not delete address. Please try again.");
    return; // Keep local state on network failure
  }

  // Only clear state after confirmed server deletion
  const deletedId = currentInbox.id;
  currentInbox = null;
  currentMessages = [];
  currentMessageId = null;
  
  sessionInboxes = sessionInboxes.filter(i => i.id !== deletedId);
  saveSession();

  if (countdownInterval) clearInterval(countdownInterval);
  stopAutoRefresh();

  if (isMailWindowOpen) {
    closeMailWindow();
  }

  if (sessionInboxes.length > 0) {
    // Switch to another valid inbox
    currentInbox = sessionInboxes[0];
    showEmailResult(currentInbox);
    fetchMessages();
    showToast("Address deleted.");
  } else {
    // No more active inboxes
    clearSession();
    const resultEl = document.getElementById("email-result");
    if (resultEl) resultEl.style.display = "none";

    setTimeout(() => {
      scrollToSection('generate');
      showToast("Address deleted. Create a new one!");
    }, 400);
  }
}

// ========== DELETE ALL MESSAGES (keep address) ==========
async function deleteAllMessages() {
  if (!currentInbox) return;

  const ok = await showConfirm({
    title: "Empty this inbox?",
    message: "All messages currently in this inbox will be permanently deleted. The address itself stays active.",
    okLabel: "Empty inbox",
    danger: true,
  });
  if (!ok) return;

  try {
    const res = await fetch(`/api/messages?inbox_id=${encodeURIComponent(currentInbox.id)}`, {
      method: "DELETE",
      headers: await authHeaders(),
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
        headers: await authHeaders(),
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
//
// Pulls a verification code out of an email subject + body. Most providers
// use either pure-digit codes (Google, banks) or alphanumeric upper-case
// codes (Atlassian, Discord, etc. — e.g. "Q36P4I"). The patterns below
// look for both shapes in order: explicit "code:" / "is your code" phrases
// first, then more permissive fallbacks. Returning the longer of the two
// shapes when both match keeps `123456` over a noisy `2024` near the date.
function extractOTP(text) {
  if (!text) return null;

  // Alphanumeric tokens must contain at least one digit to avoid matching
  // random capitalised words like "PLEASE" or "REVIEW".
  const ALNUM = "[A-Z0-9]{4,10}";
  const alnumWithDigit = (s) => /[A-Z]/.test(s) && /[0-9]/.test(s) || /^[0-9]{4,8}$/.test(s);

  const patterns = [
    new RegExp(`\\b(?:otp|code|verify|verification|pin|passcode|token)[:\\s]+(${ALNUM})\\b`, "i"),
    new RegExp(`\\b(${ALNUM})\\s+(?:is your|is the|is|as your)\\s+(?:otp|code|verification|pin|passcode)`, "i"),
    new RegExp(`(?:enter|use|submit|type)\\s+(?:the\\s+)?(?:code|otp|pin)?[:\\s]+(${ALNUM})\\b`, "i"),
    new RegExp(`\\b(?:one[- ]?time\\s+(?:password|code|pin))[:\\s]+(${ALNUM})\\b`, "i"),
    /\b(\d{6})\b(?=[\s\S]*?(?:verif|otp|code|confirm|expire))/i,
  ];

  // Patterns are case-insensitive but real OTPs are almost always upper-case.
  // Look at the original text in upper case so `\b` still picks up word
  // boundaries around the candidate.
  const upper = String(text).toUpperCase();
  for (const pattern of patterns) {
    const match = upper.match(pattern);
    if (match && match[1] && alnumWithDigit(match[1])) {
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

// Defensive HTML sanitizer for rendered email bodies.
//
// The email-worker also sanitizes server-side, but defense-in-depth matters:
// a misbehaving worker, a stale cache, or future schema changes shouldn't
// expose users to script execution or tracking pixels.
//
// IMPORTANT: keep these rules in sync with functions/_sanitize-html.js.
// Both files run the same logic — this one inline because public/app.js is
// loaded as a plain <script> (no bundler), and the other as an ES module
// for the email-worker and Pages Functions tests.
//
// Strategy:
//   - Strip every active-content tag (script/style/iframe/object/embed/form/
//     base/meta/svg/math/link/source/track) along with their contents.
//   - Strip every on* event-handler attribute regardless of quoting style.
//   - Neutralize every dangerous URL scheme (javascript:/data:/vbscript:/
//     blob:/file:) — including HTML-entity-encoded variants.
//   - Block all <img> tags so remote tracking pixels never leak the user's IP.
//
// Note: this is intentionally regex-based to avoid a heavy DOMPurify
// dependency on a privacy-focused page. The sanitizer must stay strict —
// favour false positives (over-blocking) over false negatives.
function sanitizeRenderedHtml(html) {
  if (typeof html !== "string") return "";

  // Normalise NULL bytes — some HTML parsers ignore them, our regex
  // wouldn't, which historically allowed attackers to smuggle attributes.
  const denul = html.replace(/\u0000/g, "");

  // Decode numeric HTML entities for the printable ASCII range. The browser
  // decodes these when parsing href/src values, so an attacker can sneak
  // `java&#115;cript:` past a literal `javascript:` check otherwise. Named
  // entities (&lt; &gt; &amp;) are intentionally left alone — those are how
  // legitimate authors escape `<>&` for display.
  //
  // TAB / LF / CR (`&#9;` `&#10;` `&#13;`) decode to a real SPACE rather
  // than the literal control char. The WHATWG URL parser strips those
  // three chars from URLs before reading the scheme, so leaving them
  // intact would let `<a href="java&#9;script:alert(1)">` render as
  // `javascript:alert(1)` despite the literal `javascript|...` check
  // below. A space is NOT stripped, so the scheme name stays corrupted.
  const decoded = denul.replace(/&#(x?)([0-9a-fA-F]+);/g, (match, hex, num) => {
    const code = parseInt(num, hex ? 16 : 10);
    if (!Number.isFinite(code)) return match;
    if (code === 0x09 || code === 0x0a || code === 0x0d) return " ";
    if (code >= 0x20 && code <= 0x7e) return String.fromCharCode(code);
    return match;
  });

  // The same bypass works through the named entities `&Tab;`, `&NewLine;`,
  // `&CR;`, `&LF;`. Decode each to a literal space (same reason as above).
  const namedDecoded = decoded.replace(/&(Tab|NewLine|CR|LF);/g, " ");

  // Replace any remaining literal TAB / LF / CR / NULL inside tag
  // delimiters with a space — covers payloads supplied as raw control
  // chars rather than entities. We only touch text inside `<...>` so
  // legitimate whitespace in body text (e.g. inside <pre>) is preserved.
  const normalised = namedDecoded.replace(/<[^>]+>/g, m =>
    m.replace(/[\t\n\r\u0000]/g, " ")
  );

  // Strip pairs of dangerous tags including their content.
  const STRIP_PAIR   = /<(script|style|iframe|object|form|svg|math|noscript|template)\b[\s\S]*?<\/\1\s*>/gi;
  // Strip self-closing / standalone dangerous tags.
  const STRIP_SINGLE = /<(embed|link|base|meta|source|track)\b[^>]*>/gi;
  // Catch any unmatched openers (truncated / malformed HTML).
  const STRIP_OPENER = /<\/?(script|style|iframe|object|svg|math|form|noscript|template)\b[^>]*>/gi;

  return normalised
    .replace(STRIP_PAIR,   "")
    .replace(STRIP_SINGLE, "")
    .replace(STRIP_OPENER, "")
    // on* event handlers — quoted, single-quoted, and unquoted forms.
    // The leading `[\s/]` handles slash-delimited attributes too — HTML
    // parsers treat `<a/onclick=…>` exactly the same as `<a onclick=…>`,
    // so the older `\son\w+` pattern was bypassable.
    // We replace the match with a single space so the tag stays well-formed.
    .replace(/[\s/]on\w+\s*=\s*"[^"]*"/gi, " ")
    .replace(/[\s/]on\w+\s*=\s*'[^']*'/gi, " ")
    .replace(/[\s/]on\w+\s*=\s*[^\s/>]+/gi, " ")
    // Dangerous URL schemes — covers entity-encoded colons that bypass the
    // literal `:` check (`java&#115;cript&#58;` etc.).
    .replace(/(javascript|vbscript|livescript|data|blob|file)\s*(?:&#0*58;?|&#x0*3a;?|:)/gi, "blocked:")
    // Block ALL <img …> tags (tracking pixels + onerror handlers + remote
    // URLs). The `\b` boundary catches the slash-delimited form too.
    .replace(/<img\b[^>]*>/gi, "[image removed]");
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
  if (sessionInboxes.length) {
    const dataToSave = sessionInboxes.map(inbox => ({
      id: inbox.id,
      email: inbox.email,
      created_at: inbox.created_at,
      expires_at: inbox.expires_at,
      owner_token: inbox.owner_token,
      access_via_auth: !!inbox.access_via_auth,
      reserved: !!inbox.reserved,
      inactive_reason: inbox.inactive_reason || '',
    }));
    localStorage.setItem("modih_inboxes_v2", JSON.stringify(dataToSave));
  }
  if (currentInbox) {
    localStorage.setItem("modih_active_inbox_id", currentInbox.id);
  } else {
    localStorage.removeItem("modih_active_inbox_id");
  }
}

function clearSession() {
  localStorage.removeItem("modih_inboxes_v2");
  localStorage.removeItem("modih_active_inbox_id");
  localStorage.removeItem("modih_inbox"); // legacy cleanup
  sessionInboxes = [];
  currentInbox = null;
}

async function restoreSession() {
  try {
    // 1. Try V2 persistence (array of inboxes)
    const savedV2 = localStorage.getItem("modih_inboxes_v2");
    const activeId = localStorage.getItem("modih_active_inbox_id");
    
    // 2. Fallback to older V1 persistence
    const savedV1 = localStorage.getItem("modih_inbox");
    
    let inboxesToRestore = [];
    let inboxToActivate = null;

    if (savedV2) {
      inboxesToRestore = JSON.parse(savedV2);
      if (activeId) {
        inboxToActivate = inboxesToRestore.find(i => i.id === activeId) || inboxesToRestore[0];
      } else {
        inboxToActivate = inboxesToRestore[0];
      }
    } else if (savedV1) {
      const legacyInbox = JSON.parse(savedV1);
      inboxesToRestore = [legacyInbox];
      inboxToActivate = legacyInbox;
    } else {
      return;
    }

    if (!inboxesToRestore.length) return;

    // Validate every locally usable inbox so old/expired records do not render
    // as active just because they were still in localStorage.
    const now = Math.floor(Date.now() / 1000);
    const checkedInboxes = await Promise.all(inboxesToRestore.map(async (ibx) => {
      if (isInboxExpired(ibx, now)) return { ...ibx, inactive_reason: 'Expired' };
      if (ibx.access_via_auth && !ibx.owner_token) return { ...ibx, inactive_reason: '' };
      if (!ibx.owner_token) return { ...ibx, inactive_reason: ibx.inactive_reason || 'Unavailable' };
      try {
        const res = await fetch(`/api/messages?inbox_id=${encodeURIComponent(ibx.id)}`, {
          headers: { "X-Owner-Token": ibx.owner_token },
        });
        if (!res.ok) return { ...ibx, inactive_reason: 'Unavailable' };
        const data = await res.json();
        const payload = data.data || data;
        const inboxPayload = payload.inbox;
        return {
          ...ibx,
          expires_at: inboxPayload?.expires_at ?? ibx.expires_at,
          inactive_reason: '',
        };
      } catch {
        return { ...ibx, inactive_reason: ibx.inactive_reason || 'Unavailable' };
      }
    }));

    sessionInboxes = checkedInboxes;
    const activeInboxes = getInboxBuckets().active;

    if (activeInboxes.length) {
      inboxToActivate = activeInboxes.find(i => i.id === activeId) || activeInboxes[0];
      currentInbox = inboxToActivate;
      showEmailResult(currentInbox);
    } else {
      currentInbox = null;
      renderInboxTabs();
    }
    saveSession();
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

  // Get or create arrow span
  let arrow = wrapper ? wrapper.querySelector('.price-trend-arrow') : null;
  if (wrapper && !arrow) {
    arrow = document.createElement('span');
    arrow.className = 'price-trend-arrow';
    wrapper.appendChild(arrow);
  }

  // Apply color state and arrows
  if (isDropping) {
    el.classList.add('price-dropping');
    if (arrow) {
      arrow.textContent = '↓';
      arrow.classList.remove('trending-up');
      arrow.classList.add('trending-down');
    }
  } else if (isIncreasing) {
    el.classList.add('price-increasing');
    if (arrow) {
      arrow.textContent = '↑';
      arrow.classList.remove('trending-down');
      arrow.classList.add('trending-up');
    }
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
      el.classList.remove('price-dropping', 'price-increasing');

      // Clear arrow
      if (arrow) {
        setTimeout(() => {
          arrow.classList.remove('trending-down', 'trending-up');
        }, 500); // 500ms delay to keep the arrow visible a tiny bit after price settles
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

// ========== CONTACT MODAL & FORM ==========
function openContactModal(plan) {
  try {
    const modal = document.getElementById('contact-modal');
    modal.style.display = 'flex';

    // Update badge and description based on plan
    const badge = document.getElementById('contact-plan-badge');
    const badgeText = document.getElementById('contact-plan-text');
    const desc = document.getElementById('contact-modal-desc');
    const messageField = document.getElementById('contact-message');

    if (plan === 'pro' || plan === 'developer') {
      badge.style.display = 'block';
      
      // Determine active billing cycle to format the message
      let activeCycle = 'monthly';
      const cycleBtns = document.querySelectorAll('.cycle-btn');
      cycleBtns.forEach(btn => {
        if (btn.classList.contains('active')) {
          activeCycle = btn.dataset.cycle;
        }
      });
      
      const price = PRICING[plan][activeCycle];
      let formattedCycle = '';
      if (activeCycle === 'monthly') formattedCycle = '/month';
      else if (activeCycle === 'quarterly') formattedCycle = '/month billed quarterly';
      else if (activeCycle === 'yearly') formattedCycle = '/month billed yearly';

      if (plan === 'pro') {
        badgeText.textContent = '⭐ Pro Plan';
        desc.textContent = "Interested in the Pro plan? Leave your details and we'll get back to you!";
        if (!messageField.value) messageField.value = `Hi, I'm interested in the Pro plan ($${price}${formattedCycle}). Can you tell me more about how to get started?`;
      } else if (plan === 'developer') {
        badgeText.textContent = '🔑 Developer Plan';
        desc.textContent = "Interested in the Developer API plan? Leave your details and we'll get back to you!";
        if (!messageField.value) messageField.value = `Hi, I'm interested in the Developer API plan ($${price}${formattedCycle}). Can you tell me more about the API access and getting started?`;
      }
    } else {
      badge.style.display = 'none';
      desc.textContent = 'Have a question or want to get early access? Send us a message.';
    }

    // Auto-fill email if logged in
    const emailField = document.getElementById('contact-email');
    if (emailField && currentUser && currentUser.email && !emailField.value) {
      emailField.value = currentUser.email;
    }
    
    requestAnimationFrame(() => {
      modal.classList.add('active');
    });
  } catch (e) {
    console.error('Failed to open modal:', e);
  }
}

function closeContactModal() {
  const modal = document.getElementById('contact-modal');
  modal.classList.remove('active');
  
  setTimeout(() => {
    modal.style.display = 'none';
    document.getElementById('contact-form').reset();
  }, 300);
}

// Close on escape key or clicking outside
document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.getElementById('contact-modal').classList.contains('active')) {
      closeContactModal();
    }
  });
  const contactModal = document.getElementById('contact-modal');
  if (contactModal) {
    contactModal.addEventListener('click', (e) => {
      if (e.target === contactModal) closeContactModal();
    });
  }
});


async function submitContactForm(e) {
  e.preventDefault();

  const btn = document.getElementById('btn-submit-contact');
  const originalHTML = btn.innerHTML;
  const originalStyle = btn.getAttribute('style') || '';

  const name    = document.getElementById('contact-name').value;
  const email   = document.getElementById('contact-email').value;
  const message = document.getElementById('contact-message').value;

  let turnstileToken = '';
  if (window.turnstile && window.contactTurnstileWidgetId) {
    turnstileToken = window.turnstile.getResponse(window.contactTurnstileWidgetId);
  }

  // Loading state — shimmer
  btn.disabled = true;
  btn.style.pointerEvents = 'none';
  btn.style.position = 'relative';
  btn.style.overflow = 'hidden';
  btn.style.opacity = '0.85';
  btn.innerHTML = 'Sending\u2026';

  // Shimmer overlay
  const shimmer = document.createElement('span');
  shimmer.style.cssText = 'position:absolute;inset:0;background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.18) 50%,transparent 100%);animation:btn-shimmer 1.2s ease infinite;';
  btn.appendChild(shimmer);

  try {
    const res = await fetch('/api/contact', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Browser-Token': getBrowserToken()
      },
      body: JSON.stringify({ name, email, message, turnstile_token: turnstileToken })
    });

    shimmer.remove();

    if (res.ok) {
      // Stripe-style success: green fill + checkmark
      btn.style.opacity = '1';
      btn.style.background = 'linear-gradient(135deg,#34d399,#10b981)';
      btn.style.color = '#fff';
      btn.style.boxShadow = '0 4px 20px rgba(52,211,153,0.45)';
      btn.style.border = 'none';
      btn.innerHTML = '<span style="display:inline-block;animation:checkPop 0.4s cubic-bezier(0.34,1.56,0.64,1) both;">\u2713</span>\u2002Message sent!';

      // Inject checkPop keyframe if not already present
      if (!document.getElementById('check-pop-kf')) {
        const s = document.createElement('style');
        s.id = 'check-pop-kf';
        s.textContent = '@keyframes checkPop{from{opacity:0;transform:scale(0.4) rotate(-20deg)}to{opacity:1;transform:scale(1) rotate(0deg)}} @keyframes btn-shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}';
        document.head.appendChild(s);
      }

      setTimeout(() => {
        closeContactModal();
        setTimeout(() => showToast("Message sent! We\u2019ll reply soon."), 350);
      }, 1800);
    } else {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Failed to send message. Please try again.");
      if (window.turnstile && window.contactTurnstileWidgetId) {
        window.turnstile.reset(window.contactTurnstileWidgetId);
      }
      btn.disabled = false;
      btn.style.cssText = originalStyle;
      btn.innerHTML = originalHTML;
    }
  } catch (error) {
    shimmer.remove();
    console.error("Submit error:", error);
    showToast("Network error. Could not send message.");
    btn.disabled = false;
    btn.style.cssText = originalStyle;
    btn.innerHTML = originalHTML;
  }
}

/* ============================================================================
   ============== CUSTOM CONFIRM DIALOG (replaces native confirm()) ===========
   ============================================================================ */

// Promise-based confirm modal. Usage:
//   const ok = await showConfirm({ title, message, okLabel?, danger? });
// Returns true when the user clicks OK, false when they cancel / dismiss.
function showConfirm({ title, message, okLabel = "Confirm", cancelLabel = "Cancel", danger = true } = {}) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("confirm-modal");
    if (!overlay) {
      // Fallback to native confirm if the modal markup is missing (shouldn't happen).
      resolve(window.confirm(message || title || "Are you sure?"));
      return;
    }

    const titleEl  = document.getElementById("confirm-title");
    const msgEl    = document.getElementById("confirm-message");
    const okBtn    = document.getElementById("confirm-ok-btn");
    const okLabel2 = document.getElementById("confirm-ok-label");
    const cancelBtn= document.getElementById("confirm-cancel-btn");
    const iconEl   = document.getElementById("confirm-icon");

    titleEl.textContent  = title || "Are you sure?";
    msgEl.textContent    = message || "";
    okLabel2.textContent = okLabel;
    cancelBtn.textContent= cancelLabel;
    okBtn.classList.toggle("confirm-danger", !!danger);
    okBtn.classList.toggle("confirm-primary", !danger);
    iconEl.classList.toggle("info", !danger);

    overlay.style.display = "flex";
    requestAnimationFrame(() => overlay.classList.add("active"));
    setTimeout(() => okBtn.focus(), 200);

    const finish = (result) => {
      overlay.classList.remove("active");
      setTimeout(() => { overlay.style.display = "none"; }, 280);
      okBtn.removeEventListener("click", onOk);
      cancelBtn.removeEventListener("click", onCancel);
      overlay.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKey);
      resolve(result);
    };
    const onOk     = () => finish(true);
    const onCancel = () => finish(false);
    const onBackdrop = (e) => { if (e.target === overlay) finish(false); };
    const onKey    = (e) => {
      if (e.key === "Escape") finish(false);
      else if (e.key === "Enter") finish(true);
    };

    okBtn.addEventListener("click", onOk);
    cancelBtn.addEventListener("click", onCancel);
    overlay.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
  });
}

/* ============================================================================
   ====================== BLOCK LIST (Pro / Developer) ========================
   Backend: /api/blocklist (GET / POST / DELETE). Stored per-user in D1.
   Email worker should consult this list when delivering mail; on the client
   we also filter messages defensively so the list updates feel instant.
   ============================================================================ */

async function authedHeaders(extra = {}) {
  const headers = { "Content-Type": "application/json", ...extra };
  if (firebaseAuth?.currentUser) {
    try {
      const token = await firebaseAuth.currentUser.getIdToken();
      headers["Authorization"] = `Bearer ${token}`;
    } catch (e) {
      // best-effort, server will 401 if it really needs auth
    }
  }
  return headers;
}

async function fetchBlocklist() {
  if (!isPaidUser()) return;
  try {
    const headers = await authedHeaders();
    const res = await fetch("/api/blocklist", { headers, cache: "no-store" });
    if (!res.ok) return;
    const data = await res.json().catch(() => ({}));
    blocklistCache = Array.isArray(data?.data?.entries) ? data.data.entries : (data?.entries || []);
    renderBlocklist();
    // Re-render mail list so newly fetched blocks apply immediately.
    _lastRenderedMsgIds = "";
    renderMailList();
  } catch (e) {
    console.warn("[Blocklist] fetch error:", e?.message);
  }
}

function renderBlocklist() {
  const listEl = document.getElementById("blocklist-items");
  const emptyEl = document.getElementById("blocklist-empty");
  if (!listEl || !emptyEl) return;

  const entries = blocklistCache || [];
  if (entries.length === 0) {
    listEl.innerHTML = "";
    emptyEl.style.display = "block";
    return;
  }
  emptyEl.style.display = "none";
  listEl.innerHTML = entries.map((e) => {
    const safe = escapeHtml(e);
    return `<li><span>${safe}</span><button type="button" onclick="removeBlocklistEntry('${safe.replace(/'/g, "&#39;")}')">Unblock</button></li>`;
  }).join("");
}

function openBlocklistModal() {
  if (!isPaidUser()) {
    showToast("Block list is a Pro feature. Upgrade to unlock!");
    return;
  }
  const overlay = document.getElementById("blocklist-modal");
  if (!overlay) return;
  overlay.style.display = "flex";
  requestAnimationFrame(() => overlay.classList.add("active"));
  fetchBlocklist();
  setTimeout(() => document.getElementById("blocklist-input")?.focus(), 150);
}

function closeBlocklistModal() {
  const overlay = document.getElementById("blocklist-modal");
  if (!overlay) return;
  overlay.classList.remove("active");
  setTimeout(() => { overlay.style.display = "none"; }, 280);
}

async function addBlocklistEntry(event) {
  event?.preventDefault?.();
  if (!isPaidUser()) {
    showToast("Block list is a Pro feature. Upgrade to unlock!");
    return;
  }
  const input = document.getElementById("blocklist-input");
  if (!input) return;
  const raw = (input.value || "").trim().toLowerCase();
  if (!raw) return;

  // Basic validation: address or domain only.
  const looksLikeEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw);
  const looksLikeDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/.test(raw);
  if (!looksLikeEmail && !looksLikeDomain) {
    showToast("Enter a full email (foo@bar.com) or domain (bar.com).");
    return;
  }

  const btn = document.getElementById("blocklist-add-btn");
  if (btn) btn.classList.add("is-loading-shimmer");

  try {
    const headers = await authedHeaders();
    const res = await fetch("/api/blocklist", {
      method: "POST",
      headers,
      body: JSON.stringify({ entry: raw }),
    });
    if (res.ok) {
      blocklistCache = Array.from(new Set([...(blocklistCache || []), raw]));
      input.value = "";
      renderBlocklist();
      _lastRenderedMsgIds = "";
      renderMailList();
      showToast(`Blocked: ${raw}`);
    } else {
      const data = await res.json().catch(() => ({}));
      showToast(data.error?.message || data.error || "Could not block. Try again.");
    }
  } catch (e) {
    console.error("[Blocklist] add error:", e);
    showToast("Network error.");
  } finally {
    if (btn) btn.classList.remove("is-loading-shimmer");
  }
}

async function removeBlocklistEntry(entry) {
  if (!isPaidUser() || !entry) return;
  try {
    const headers = await authedHeaders();
    const res = await fetch(`/api/blocklist?entry=${encodeURIComponent(entry)}`, {
      method: "DELETE",
      headers,
    });
    if (res.ok) {
      blocklistCache = (blocklistCache || []).filter((e) => e !== entry);
      renderBlocklist();
      _lastRenderedMsgIds = "";
      renderMailList();
      showToast(`Unblocked: ${entry}`);
    }
  } catch (e) {
    console.error("[Blocklist] remove error:", e);
  }
}

// Returns the subset of `msgs` that aren't from a blocked sender.
function filterMessagesByBlocklist(msgs) {
  if (!Array.isArray(msgs)) return [];
  const list = blocklistCache;
  if (!Array.isArray(list) || list.length === 0) return msgs;
  const blockedAddrs = new Set(list.filter((e) => e.includes("@")));
  const blockedDomains = new Set(list.filter((e) => !e.includes("@")));
  return msgs.filter((m) => {
    const addr = (m.from_address || "").toLowerCase();
    if (!addr) return true;
    if (blockedAddrs.has(addr)) return false;
    const domain = addr.split("@")[1] || "";
    if (blockedDomains.has(domain)) return false;
    return true;
  });
}

async function blockSenderFromCurrent() {
  if (!isPaidUser()) {
    showToast("Block list is a Pro feature.");
    return;
  }
  const msg = currentMessages.find((m) => m.id === currentMessageId);
  if (!msg?.from_address) return;
  const entry = (msg.from_address || "").toLowerCase();
  const ok = await showConfirm({
    title: "Block this sender?",
    message: `All future messages from ${entry} will be filtered out across every inbox you own.`,
    okLabel: "Block sender",
    danger: false,
  });
  if (!ok) return;
  // Reuse the add path
  const input = document.getElementById("blocklist-input");
  if (input) input.value = entry;
  await addBlocklistEntry({ preventDefault() {} });
}

/* ============================================================================
   =================== EXPORT MESSAGE (.txt / .eml) ===========================
   Client-side export. Free users get a friendly upgrade nudge; Pro/Dev get
   the actual download. RFC 5322-ish .eml; not bit-perfect (we don't have the
   raw MIME) but the headers + body are reconstructed correctly so most mail
   clients can open it.
   ============================================================================ */

function exportCurrentMessage(format) {
  if (!currentMessageId) return;
  if (!isPaidUser()) {
    showToast("Export is a Pro feature. Upgrade to download messages!");
    return;
  }
  const msg = currentMessages.find((m) => m.id === currentMessageId);
  if (!msg) return;

  const safeName = sanitizeFileName(msg.subject || "message");
  if (format === "txt") {
    const blob = new Blob([buildTxtExport(msg)], { type: "text/plain;charset=utf-8" });
    downloadBlob(blob, `${safeName}.txt`);
    showToast("Exported as .txt");
  } else if (format === "eml") {
    const blob = new Blob([buildEmlExport(msg)], { type: "message/rfc822;charset=utf-8" });
    downloadBlob(blob, `${safeName}.eml`);
    showToast("Exported as .eml");
  }
}

function sanitizeFileName(s) {
  return (s || "message").replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "message";
}

function downloadBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function buildTxtExport(msg) {
  const from = msg.from_name ? `${msg.from_name} <${msg.from_address}>` : (msg.from_address || "");
  const date = msg.received_at ? new Date(msg.received_at * 1000).toUTCString() : "";
  const to = currentInbox?.email || "";
  const subj = msg.subject || "(no subject)";
  const body = (msg.body_text || stripHtmlForText(msg.body_html || "") || "").trim();
  return [
    `From:    ${from}`,
    `To:      ${to}`,
    `Date:    ${date}`,
    `Subject: ${subj}`,
    "",
    body,
    "",
    "-- Exported from Modih Mail (modih.in) --",
  ].join("\r\n");
}

function buildEmlExport(msg) {
  const from = msg.from_name ? `${msg.from_name} <${msg.from_address}>` : (msg.from_address || "");
  const date = msg.received_at ? new Date(msg.received_at * 1000).toUTCString() : new Date().toUTCString();
  const to = currentInbox?.email || "";
  const subj = msg.subject || "(no subject)";
  const messageId = msg.id || `${Date.now()}@modih.in`;

  const text = (msg.body_text || stripHtmlForText(msg.body_html || "") || "").trim();
  const html = (msg.body_html || "").trim();

  if (html) {
    const boundary = `=_modih_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
    const headers = [
      `From: ${encodeHeader(from)}`,
      `To: ${encodeHeader(to)}`,
      `Subject: ${encodeHeader(subj)}`,
      `Date: ${date}`,
      `Message-ID: <${messageId}@modih.in>`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      `X-Exported-By: Modih Mail`,
    ].join("\r\n");
    return [
      headers,
      "",
      `--${boundary}`,
      `Content-Type: text/plain; charset="utf-8"`,
      `Content-Transfer-Encoding: 8bit`,
      "",
      text || "(no plain-text body)",
      "",
      `--${boundary}`,
      `Content-Type: text/html; charset="utf-8"`,
      `Content-Transfer-Encoding: 8bit`,
      "",
      html,
      "",
      `--${boundary}--`,
      "",
    ].join("\r\n");
  }
  // text-only
  const headers = [
    `From: ${encodeHeader(from)}`,
    `To: ${encodeHeader(to)}`,
    `Subject: ${encodeHeader(subj)}`,
    `Date: ${date}`,
    `Message-ID: <${messageId}@modih.in>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset="utf-8"`,
    `Content-Transfer-Encoding: 8bit`,
    `X-Exported-By: Modih Mail`,
  ].join("\r\n");
  return `${headers}\r\n\r\n${text}\r\n`;
}

// Very loose RFC 2047 encoded-word for non-ASCII header values; keeps
// ASCII-only headers untouched so .eml files are human-readable.
function encodeHeader(v) {
  const s = String(v || "");
  if (/^[\x20-\x7E]*$/.test(s)) return s;
  try {
    return `=?UTF-8?B?${btoa(unescape(encodeURIComponent(s)))}?=`;
  } catch {
    return s;
  }
}

function stripHtmlForText(html) {
  if (!html) return "";
  // Replace block tags with newlines, then strip remaining tags.
  return html
    .replace(/<\s*(br|p|div|tr|li|h[1-6])[^>]*>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])\s*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\r\n?/g, "\n")
    .replace(/\n{3,}/g, "\n\n");
}

/* ============================================================================
   ================== RESERVE ALIAS (Pro / Developer: up to 3) ================
   Server-side flag stored on the inbox row in D1. Reserved aliases survive
   the periodic cleanup job — they're effectively "permanent" until the user
   deletes them or unreserves.
   ============================================================================ */

async function toggleReserveCurrent() {
  if (!currentInbox) return;
  if (!isPaidUser()) {
    showToast("Reserved aliases are a Pro feature.");
    return;
  }
  const willReserve = !currentInbox.reserved;

  // 3-alias cap (defensive — server enforces too)
  if (willReserve) {
    const reservedCount = sessionInboxes.filter((i) => i.reserved).length;
    if (reservedCount >= 3) {
      showToast("You can reserve up to 3 aliases. Unreserve one first.");
      return;
    }
  }

  try {
    const headers = await authedHeaders();
    const res = await fetch(`/api/inbox/reserve?id=${encodeURIComponent(currentInbox.id)}`, {
      method: willReserve ? "POST" : "DELETE",
      headers,
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error?.message || data.error || "Could not update reservation.");
      return;
    }
    currentInbox.reserved = willReserve;
    const stored = sessionInboxes.find((i) => i.id === currentInbox.id);
    if (stored) stored.reserved = willReserve;
    saveSession();
    updateReserveButtonState();
    renderInboxTabs();
    showToast(willReserve ? "Alias reserved ⭐" : "Reservation removed");
  } catch (e) {
    console.error("[Reserve] error:", e);
    showToast("Network error.");
  }
}

function updateReserveButtonState() {
  const btn = document.getElementById("btn-reserve");
  if (!btn) return;
  if (!currentInbox) {
    btn.classList.remove("is-active-state");
    return;
  }
  btn.classList.toggle("is-active-state", !!currentInbox.reserved);
  btn.title = currentInbox.reserved
    ? "Reserved ⭐ — click to remove (Pro: keeps across expiry, up to 3)"
    : "Reserve alias (Pro: keeps across expiry, up to 3)";
}

/* ============================================================================
   ====================== ACCOUNT ADDRESS HISTORY =============================
   GET /api/inbox/mine returns signed-in address history keyed by Firebase UID.
   Live rows are reopened through auth; expired/deleted rows remain as history.
   ============================================================================ */

async function syncInboxesFromServer() {
  if (!firebaseAuth?.currentUser) return;
  try {
    const headers = await authedHeaders();
    const res = await fetch("/api/inbox/mine", { headers, cache: "no-store" });
    if (!res.ok) return;
    const data = await res.json().catch(() => ({}));
    const payload = data.data || data;
    const history = Array.isArray(payload.history) ? payload.history : [];
    const live = Array.isArray(payload.inboxes) ? payload.inboxes : [];
    const remote = history.length ? history : live;
    if (!remote.length && !sessionInboxes.length) return;
    const liveAccess = await validateRemoteInboxAccess(live);

    // Merge remote into local (remote wins on shared id).
    const byId = new Map(sessionInboxes.map((i) => [i.id, i]));
    for (const r of remote) {
      if (!r?.id || !r?.email) continue;
      const existing = byId.get(r.id) || {};
      const wasReportedLive = !!r.active || live.some((i) => i.id === r.id);
      const validation = liveAccess.get(r.id);
      const isLive = wasReportedLive && validation?.ok === true;
      const inactiveReason = isLive ? '' : (wasReportedLive ? (validation?.reason || 'Unavailable') : 'History');
      byId.set(r.id, {
        ...existing,
        ...r,
        owner_token: existing.owner_token,
        access_via_auth: isLive,
        inactive_reason: inactiveReason,
      });
    }
    sessionInboxes = Array.from(byId.values()).sort((a, b) => b.created_at - a.created_at);
    saveSession();

    // If we don't have a current inbox, surface the most recent one.
    const activeInboxes = getInboxBuckets().active;
    if (!currentInbox && activeInboxes[0]) {
      currentInbox = activeInboxes[0];
      showEmailResult(currentInbox);
    } else if (currentInbox) {
      // Pull updated reserved flag etc. into the live reference
      const fresh = sessionInboxes.find((i) => i.id === currentInbox.id);
      if (fresh) currentInbox = { ...currentInbox, ...fresh };
      updateReserveButtonState();
      renderInboxTabs();
    } else {
      renderInboxTabs();
    }
  } catch (e) {
    console.warn("[Sync] error:", e?.message);
  }
}

async function validateRemoteInboxAccess(inboxes) {
  const result = new Map();
  const liveInboxes = (Array.isArray(inboxes) ? inboxes : []).filter((i) => i?.id);
  if (!liveInboxes.length || !firebaseAuth?.currentUser) return result;

  const headers = await authedHeaders();
  await Promise.all(liveInboxes.map(async (inbox) => {
    try {
      const res = await fetch(`/api/messages?inbox_id=${encodeURIComponent(inbox.id)}`, {
        headers,
        cache: "no-store",
      });
      if (res.ok) {
        result.set(inbox.id, { ok: true });
        return;
      }
      let reason = 'Unavailable';
      if (res.status === 404) reason = 'Expired';
      if (res.status === 403 || res.status === 401) reason = 'Unavailable';
      result.set(inbox.id, { ok: false, reason });
    } catch {
      result.set(inbox.id, { ok: false, reason: 'Unavailable' });
    }
  }));
  return result;
}

function startAccountSync() {
  if (accountSyncInterval || !firebaseAuth?.currentUser) return;
  accountSyncInterval = setInterval(() => {
    if (document.visibilityState !== 'hidden') {
      syncInboxesFromServer().catch((e) => console.warn('[Sync] failed:', e?.message));
    }
  }, 30000);
}

function stopAccountSync() {
  if (accountSyncInterval) {
    clearInterval(accountSyncInterval);
    accountSyncInterval = null;
  }
}

window.addEventListener('focus', () => {
  if (firebaseAuth?.currentUser) {
    syncInboxesFromServer().catch((e) => console.warn('[Sync] failed:', e?.message));
  }
});

/* ============================================================================
   ============= UNIVERSAL CLICK RIPPLE / PRESS ANIMATIONS =====================
   Attaches a tiny pointerdown listener at the document level so every
   .btn-primary / .glow-btn gets a ripple effect without per-call wiring.
   ============================================================================ */
function initButtonAnimations() {
  if (window._modihRippleInstalled) return;
  window._modihRippleInstalled = true;
  document.addEventListener("pointerdown", (e) => {
    const btn = e.target?.closest?.(".btn-primary, .glow-btn");
    if (!btn || btn.disabled) return;
    const rect = btn.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    btn.style.setProperty("--ripple-x", `${x}%`);
    btn.style.setProperty("--ripple-y", `${y}%`);
    btn.classList.remove("is-rippling");
    // restart animation
    void btn.offsetWidth;
    btn.classList.add("is-rippling");
    setTimeout(() => btn.classList.remove("is-rippling"), 650);
  }, { passive: true });
}

// Auto-initialise on DOMContentLoaded (additive — doesn't replace existing init).
if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initButtonAnimations);
  } else {
    initButtonAnimations();
  }
}
