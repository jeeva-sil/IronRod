/**
 * IronRod — Firebase Analytics
 *
 * Shared analytics module loaded on every page.
 * Requires the Firebase SDK scripts to be included before this file:
 *   <script src="https://www.gstatic.com/firebasejs/11.6.0/firebase-app-compat.js"></script>
 *   <script src="https://www.gstatic.com/firebasejs/11.6.0/firebase-analytics-compat.js"></script>
 *
 * ⚠️  Replace the firebaseConfig values below with your actual Firebase project config.
 *     Find them in the Firebase Console → Project Settings → General → Your apps → Config.
 */

(function () {
    'use strict';

    // ─── Firebase Configuration ──────────────────────────────
    // TODO: Replace with your real Firebase project config
    const firebaseConfig = {
        apiKey: "AIzaSyAgXhqDCrujDfhUcCTOqA3omX1SAWZOBZA",
        authDomain: "ironrod-d3493.firebaseapp.com",
        projectId: "ironrod-d3493",
        storageBucket: "ironrod-d3493.firebasestorage.app",
        messagingSenderId: "484911446513",
        appId: "1:484911446513:web:928fa4e3733e98fa9b6c50",
        measurementId: "G-DG3TFEB0B6"
    };

    // ─── Initialise Firebase ─────────────────────────────────
    if (typeof firebase === 'undefined') {
        console.warn('[Analytics] Firebase SDK not loaded — skipping analytics.');
        return;
    }

    firebase.initializeApp(firebaseConfig);
    const analytics = firebase.analytics();

    // Expose a lightweight helper for inline usage if needed
    window.irAnalytics = {
        log: function (event, params) {
            try { analytics.logEvent(event, params || {}); } catch (_) { /* swallow */ }
        }
    };

    // ─── Helpers ─────────────────────────────────────────────
    function pageName() {
        var path = location.pathname;
        if (path === '/' || path.endsWith('/index.html')) return 'home';
        if (path.endsWith('/tutorial.html')) return 'tutorial';
        if (path.endsWith('/404.html')) return '404';
        return path.replace(/^\/|\.html$/g, '') || 'unknown';
    }

    // ─── 1. Page‑level metadata ──────────────────────────────
    analytics.setUserProperties({ site_version: '1.0.6' });

    // ─── 2. Scroll‑depth tracking (25 / 50 / 75 / 100 %) ───
    (function () {
        var milestones = [25, 50, 75, 100];
        var fired = {};
        function onScroll() {
            var scrollTop = window.scrollY || document.documentElement.scrollTop;
            var docHeight = document.documentElement.scrollHeight - window.innerHeight;
            if (docHeight <= 0) return;
            var pct = Math.round((scrollTop / docHeight) * 100);
            milestones.forEach(function (m) {
                if (pct >= m && !fired[m]) {
                    fired[m] = true;
                    analytics.logEvent('scroll_depth', {
                        page: pageName(),
                        percent: m
                    });
                }
            });
        }
        window.addEventListener('scroll', onScroll, { passive: true });
    })();

    // ─── 3. Section visibility tracking ──────────────────────
    (function () {
        var tracked = {};
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (e.isIntersecting) {
                    var id = e.target.id || e.target.getAttribute('data-section');
                    if (id && !tracked[id]) {
                        tracked[id] = true;
                        analytics.logEvent('section_view', {
                            page: pageName(),
                            section: id
                        });
                    }
                }
            });
        }, { threshold: 0.3 });

        // Observe all <section> elements with an id
        document.querySelectorAll('section[id]').forEach(function (s) { io.observe(s); });
        // Also observe elements with data-section attribute
        document.querySelectorAll('[data-section]').forEach(function (s) { io.observe(s); });
    })();

    // ─── 4. Navigation link clicks ──────────────────────────
    document.querySelectorAll('nav a').forEach(function (a) {
        a.addEventListener('click', function () {
            analytics.logEvent('nav_click', {
                page: pageName(),
                link_text: (a.textContent || '').trim().substring(0, 50),
                link_url: a.getAttribute('href') || ''
            });
        });
    });

    // ─── 5. Download button clicks ──────────────────────────
    document.querySelectorAll('.dl-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var href = btn.getAttribute('href') || '';
            var os = 'unknown';
            var format = 'unknown';

            if (href.includes('macOS')) os = 'macos';
            else if (href.includes('Windows')) os = 'windows';
            else if (href.includes('Linux') || href.includes('linux') || href.includes('amd64')) os = 'linux';

            if (href.includes('.dmg')) format = 'dmg';
            else if (href.includes('.msix')) format = 'msix';
            else if (href.includes('.AppImage')) format = 'appimage';
            else if (href.includes('.deb')) format = 'deb';
            else if (href.includes('.tar.gz')) format = 'tar.gz';
            else if (href.includes('.zip')) format = 'zip';

            // Determine sub-variant (e.g. Intel vs Apple Silicon)
            var label = (btn.textContent || '').trim();

            analytics.logEvent('download_click', {
                os: os,
                format: format,
                label: label.substring(0, 100),
                url: href
            });
        });
    });

    // ─── 6. Hero CTA buttons ────────────────────────────────
    document.querySelectorAll('.hero-buttons .btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            analytics.logEvent('hero_cta_click', {
                button_text: (btn.textContent || '').trim().substring(0, 50),
                link_url: btn.getAttribute('href') || ''
            });
        });
    });

    // ─── 7. Final CTA section buttons ──────────────────────
    document.querySelectorAll('.cta-box .btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            analytics.logEvent('cta_click', {
                button_text: (btn.textContent || '').trim().substring(0, 50),
                link_url: btn.getAttribute('href') || ''
            });
        });
    });

    // ─── 8. Buy Me a Coffee clicks ──────────────────────────
    document.querySelectorAll('a[href*="buymeacoffee"]').forEach(function (a) {
        a.addEventListener('click', function () {
            var inNav = !!a.closest('nav');
            analytics.logEvent('buy_coffee_click', {
                page: pageName(),
                location: inNav ? 'navbar' : 'footer'
            });
        });
    });

    // ─── 9. Interstitial ad events ──────────────────────────
    (function () {
        var overlay = document.getElementById('interstitial');
        var skipBtn = document.getElementById('skip-btn');
        if (!overlay) return;

        // Shown — observed via class change
        var mo = new MutationObserver(function (mutations) {
            mutations.forEach(function (m) {
                if (m.attributeName === 'class') {
                    if (overlay.classList.contains('active')) {
                        analytics.logEvent('interstitial_shown', { page: pageName() });
                    }
                }
            });
        });
        mo.observe(overlay, { attributes: true });

        // Completed (skip clicked)
        if (skipBtn) {
            skipBtn.addEventListener('click', function () {
                analytics.logEvent('interstitial_completed', { page: pageName() });
            });
        }
    })();

    // ─── 10. Tutorial‑specific: step visibility ─────────────
    (function () {
        var steps = document.querySelectorAll('.tutorial-step');
        if (!steps.length) return;

        var tracked = {};
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (e.isIntersecting) {
                    var id = e.target.id;
                    if (id && !tracked[id]) {
                        tracked[id] = true;
                        var heading = e.target.querySelector('h2');
                        analytics.logEvent('tutorial_step_view', {
                            step_id: id,
                            step_name: heading ? heading.textContent.trim().substring(0, 80) : id
                        });
                    }
                }
            });
        }, { threshold: 0.35 });

        steps.forEach(function (s) { io.observe(s); });
    })();

    // ─── 11. Tutorial‑specific: OS tab switches ─────────────
    document.querySelectorAll('.os-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            var group = (tab.parentElement && tab.parentElement.getAttribute('data-group')) || '';
            analytics.logEvent('os_tab_switch', {
                page: pageName(),
                group: group,
                os: tab.getAttribute('data-os') || (tab.textContent || '').trim()
            });
        });
    });

    // ─── 12. FAQ interactions ────────────────────────────────
    document.querySelectorAll('.faq-q').forEach(function (q) {
        q.addEventListener('click', function () {
            var faqItem = q.closest('.faq-item');
            // Only track opens (not closes)
            if (faqItem && !faqItem.classList.contains('open')) {
                analytics.logEvent('faq_open', {
                    page: pageName(),
                    question: (q.textContent || '').replace(/[▼▲]/g, '').trim().substring(0, 100)
                });
            }
        });
    });

    // ─── 13. 404 page tracking ──────────────────────────────
    if (pageName() === '404') {
        analytics.logEvent('page_not_found', {
            page_location: location.href,
            referrer: document.referrer || 'direct'
        });
    }

    // ─── 14. Outbound link tracking ─────────────────────────
    document.querySelectorAll('a[href^="http"]').forEach(function (a) {
        var href = a.getAttribute('href') || '';
        // Skip if it's an internal link
        if (href.includes(location.hostname)) return;

        a.addEventListener('click', function () {
            analytics.logEvent('outbound_click', {
                page: pageName(),
                link_url: href,
                link_text: (a.textContent || '').trim().substring(0, 50)
            });
        });
    });

    // ─── 15. Time on page ───────────────────────────────────
    (function () {
        var startTime = Date.now();
        window.addEventListener('beforeunload', function () {
            var duration = Math.round((Date.now() - startTime) / 1000);
            // Use sendBeacon-backed logEvent
            analytics.logEvent('page_engagement', {
                page: pageName(),
                duration_seconds: duration
            });
        });
    })();

})();
