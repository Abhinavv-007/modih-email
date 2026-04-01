/* ========================================
   MODIH MAIL — Application Logic
   ======================================== */

// ========== STATE ==========
let currentInbox = null;      // { id, email, created_at, expires_at, owner_token }
let sessionInboxes = [];      // All inboxes created this session (Pro/Dev multi-inbox)
let currentMessages = [];
let currentMessageId = null;
let countdownInterval = null;
let refreshInterval = null;
let isMailWindowOpen = false;
let turnstileWidgetId = null;
let turnstileRequired = false;
let currentUser = null;       // Firebase user { uid, email, plan }

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
    const short = currentUser.email ? currentUser.email.split('@')[0].slice(0, 14) : 'Account';
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
        <span class="nav-plan-dot ${planClass}" title="${currentUser.plan} plan"></span>
        <span class="nav-user-email" title="${currentUser.email}">${short}</span>
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
          <span title="${currentUser.email}">${currentUser.email || short}</span>
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

  // Block custom prefix for free users only
  if (type === "custom") {
    const plan = currentUser?.plan || 'free';
    if (plan !== 'pro' && plan !== 'developer') {
      upgradeEl.style.display = "block";
      upgradeEl.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
  }

  // Loading state
  btnCustom.classList.add("loading");
  btnRandom.classList.add("loading");

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

    if (isPaid) {
      // Pro/Dev: accumulate inboxes instead of replacing
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
function renderInboxTabs() {
  const tabEl = document.getElementById('inbox-tabs');
  if (!tabEl) return;

  if (sessionInboxes.length < 2) {
    tabEl.style.display = 'none';
    return;
  }

  tabEl.style.display = 'flex';
  
  // Sort inboxes newest first
  const sorted = [...sessionInboxes].sort((a, b) => b.created_at - a.created_at);

  tabEl.innerHTML = `
    <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.25rem;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">Your Active Inboxes</div>
    ` + sorted.map(inbox => {
      const isActive = currentInbox?.id === inbox.id;
      return `
        <div 
          onclick="switchToInbox('${inbox.id}')"
          style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            padding:0.75rem 1rem;
            background:${isActive ? 'rgba(40,40,50,0.6)' : 'rgba(30,30,40,0.45)'};
            backdrop-filter:blur(10px);
            -webkit-backdrop-filter:blur(10px);
            border:1px solid ${isActive ? 'rgba(212,167,106,0.5)' : 'rgba(255,255,255,0.12)'};
            border-radius:12px;
            cursor:pointer;
            transition:all 0.2s ease;
            box-shadow:0 4px 12px rgba(0,0,0,0.2);
          "
          onmouseover="this.style.background='rgba(50,50,60,0.65)';"
          onmouseout="this.style.background='${isActive ? 'rgba(40,40,50,0.6)' : 'rgba(30,30,40,0.45)'}';"
        >
          <div style="display:flex;flex-direction:column;gap:0.2rem;">
            <span style="font-family:'Cormorant Garamond',serif;font-size:1.2rem;font-weight:700;color:${isActive ? 'var(--accent)' : 'var(--text)'};">${inbox.email}</span>
            <span style="font-size:0.7rem;color:var(--text-muted);">Created ${new Date(inbox.created_at * 1000).toLocaleDateString()}</span>
          </div>
          <div>
            ${isActive 
              ? `<span style="font-size:0.65rem;text-transform:uppercase;letter-spacing:0.1em;background:var(--accent);color:#000;padding:2px 6px;border-radius:4px;font-weight:700;">Viewing</span>`
              : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted);"><polyline points="9 18 15 12 9 6"/></svg>`
            }
          </div>
        </div>
      `;
    }).join('');
}

function switchToInbox(inboxId) {
  const inbox = sessionInboxes.find(i => i.id === inboxId);
  if (!inbox || currentInbox?.id === inboxId) return;
  currentInbox = inbox;
  currentMessages = [];
  saveSession();
  showEmailResult(inbox);
  fetchMessages();
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

    currentMessages = data.data?.messages || data.messages || [];
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

  let deleteOk = false;
  try {
    const res = await fetch(`/api/inbox?id=${currentInbox.id}`, {
      method: "DELETE",
      headers: authHeaders(),
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
    .replace(/<meta[\s\S]*?>/gi, "")
    // Block remote images (tracking pixels, attacker-controlled URLs)
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
  if (currentInbox) {
    const dataToSave = sessionInboxes.map(inbox => ({
      id: inbox.id,
      email: inbox.email,
      created_at: inbox.created_at,
      expires_at: inbox.expires_at,
      owner_token: inbox.owner_token,
    }));
    localStorage.setItem("modih_inboxes_v2", JSON.stringify(dataToSave));
    localStorage.setItem("modih_active_inbox_id", currentInbox.id);
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

    if (!inboxToActivate || !inboxToActivate.owner_token) {
      clearSession();
      return;
    }

    // Filter out expired inboxes from the array
    const now = Math.floor(Date.now() / 1000);
    const validInboxes = [];
    for (const ibx of inboxesToRestore) {
      if (!ibx.expires_at || ibx.expires_at > now) {
        validInboxes.push(ibx);
      }
    }

    if (validInboxes.length === 0) {
      clearSession();
      return;
    }

    // If active one expired, pick the first valid one
    if (!validInboxes.find(i => i.id === inboxToActivate.id)) {
      inboxToActivate = validInboxes[0];
    }
    
    sessionInboxes = validInboxes;

    // Validate the active inbox by calling backend
    const res = await fetch(`/api/messages?inbox_id=${inboxToActivate.id}`, {
      headers: { "X-Owner-Token": inboxToActivate.owner_token },
    });

    if (res.ok) {
      const data = await res.json();
      if (data.inbox && data.inbox.expires_at) {
        inboxToActivate.expires_at = data.inbox.expires_at;
        // Also update it in the array
        const idx = sessionInboxes.findIndex(i => i.id === inboxToActivate.id);
        if (idx >= 0) sessionInboxes[idx].expires_at = data.inbox.expires_at;
      }
      currentInbox = inboxToActivate;
      showEmailResult(currentInbox);
    } else {
      // If the backend call fails, just use the validInboxes we have but maybe the server wiped it
      // In a robust implementation we'd check each inbox, but for now just clear if the active one is dead
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
  const originalText = btn.innerHTML;
  
  const name = document.getElementById('contact-name').value;
  const email = document.getElementById('contact-email').value;
  const message = document.getElementById('contact-message').value;
  
  let turnstileToken = '';
  if (window.turnstile && window.contactTurnstileWidgetId) {
    turnstileToken = window.turnstile.getResponse(window.contactTurnstileWidgetId);
  }

  // Note: Turnstile is optional for the contact form — backend rate limiting handles spam
  
  btn.innerHTML = '<span>Sending...</span><div class="loading-dots" style="margin-top:0;"><span></span><span></span><span></span></div>';
  btn.style.pointerEvents = 'none';
  btn.style.opacity = '0.7';

  try {
    const res = await fetch('/api/contact', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Browser-Token': getBrowserToken() // For rate-limiting identical to inbox creation
      },
      body: JSON.stringify({
        name,
        email,
        message,
        turnstile_token: turnstileToken
      })
    });
    
    if (res.ok) {
      closeContactModal();
      setTimeout(() => {
        showToast("Message sent successfully! We'll reply soon.");
      }, 400);
    } else {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Failed to send message. Please try again.");
      if (window.turnstile && window.contactTurnstileWidgetId) {
        window.turnstile.reset(window.contactTurnstileWidgetId);
      }
    }
  } catch (error) {
    console.error("Submit error:", error);
    showToast("Network error. Could not send message.");
  } finally {
    btn.innerHTML = originalText;
    btn.style.pointerEvents = 'auto';
    btn.style.opacity = '1';
  }
}

