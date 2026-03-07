# Feature 089: Mobile Responsive

## Status: Planned
## Phase: 9 (v2.9)
## Priority: Low

## Problem

The PQVault web dashboard is designed for desktop viewports and becomes unusable on
mobile devices. Tables overflow horizontally, buttons are too small for touch targets,
and navigation requires horizontal scrolling. During incidents, engineers on-call may
need to check a secret from their phone, and the current UI makes this impossible.

## Solution

Make the dashboard fully responsive using CSS media queries, a mobile-first layout
approach, and touch-friendly interaction patterns. Tables transform into card layouts
on small screens, the navigation collapses into a hamburger menu, and key operations
use appropriately sized touch targets. The mobile view prioritizes quick lookups:
search, view value, copy to clipboard.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  static/
    css/
      responsive.css    # Media queries and mobile styles
      mobile-nav.css    # Mobile navigation styles
  templates/
    components/
      mobile_nav.html   # Hamburger menu navigation
      card_layout.html  # Card-based key listing for mobile
  static/
    js/
      mobile.js         # Touch interactions and mobile menu
```

### Data Model Changes

No backend changes. Mobile responsiveness is entirely CSS/HTML.

### MCP Tools

No new MCP tools.

### CLI Commands

No new CLI commands.

### Web UI Changes

```css
/* responsive.css */

/* Mobile breakpoint: 768px */
@media (max-width: 768px) {
    /* Hide table headers, show card layout */
    .key-table thead {
        display: none;
    }

    .key-table tbody tr {
        display: block;
        margin-bottom: 1rem;
        padding: 1rem;
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
    }

    .key-table tbody td {
        display: flex;
        justify-content: space-between;
        padding: 0.5rem 0;
        border: none;
    }

    .key-table tbody td::before {
        content: attr(data-label);
        font-weight: 600;
        color: var(--text-secondary);
    }

    /* Stack action buttons */
    .key-actions {
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
    }

    .key-actions button {
        flex: 1;
        min-height: 44px;  /* iOS minimum touch target */
        min-width: 44px;
    }

    /* Hamburger navigation */
    .desktop-nav {
        display: none;
    }

    .mobile-nav-toggle {
        display: block;
        font-size: 1.5rem;
        padding: 0.5rem;
        min-height: 44px;
        min-width: 44px;
    }

    .mobile-nav {
        position: fixed;
        top: 0;
        left: -100%;
        width: 80%;
        height: 100vh;
        background: var(--bg-primary);
        z-index: 1000;
        transition: left 0.3s ease;
        padding: 1rem;
    }

    .mobile-nav.open {
        left: 0;
    }

    .mobile-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        z-index: 999;
        display: none;
    }

    .mobile-overlay.visible {
        display: block;
    }

    /* Full-width search bar */
    .search-container {
        width: 100%;
        padding: 0 1rem;
    }

    .search-input {
        width: 100%;
        min-height: 44px;
        font-size: 16px; /* Prevents iOS zoom on focus */
    }

    /* Key detail page - stack panels */
    .info-grid {
        grid-template-columns: 1fr;
    }

    .tab-nav {
        overflow-x: auto;
        white-space: nowrap;
        -webkit-overflow-scrolling: touch;
    }

    /* Larger copy button for mobile */
    .copy-btn {
        min-height: 48px;
        padding: 0 1.5rem;
        font-size: 1rem;
    }
}

/* Tablet breakpoint: 1024px */
@media (max-width: 1024px) {
    .info-grid {
        grid-template-columns: 1fr 1fr;
    }

    .sidebar {
        display: none;
    }
}

/* Touch-specific styles */
@media (pointer: coarse) {
    /* Larger tap targets for touch devices */
    .key-row {
        min-height: 56px;
        padding: 1rem;
    }

    .btn, button {
        min-height: 44px;
        min-width: 44px;
    }

    /* Disable hover effects on touch */
    .key-row:hover {
        background: inherit;
    }

    /* Enable active state instead */
    .key-row:active {
        background: var(--bg-tertiary);
    }
}
```

```javascript
// mobile.js
class MobileUI {
    constructor() {
        this.menuOpen = false;
        this.init();
    }

    init() {
        // Hamburger menu toggle
        const toggle = document.getElementById('mobile-nav-toggle');
        if (toggle) {
            toggle.addEventListener('click', () => this.toggleMenu());
        }

        // Close menu on overlay click
        const overlay = document.getElementById('mobile-overlay');
        if (overlay) {
            overlay.addEventListener('click', () => this.closeMenu());
        }

        // Swipe to close menu
        let touchStartX = 0;
        document.addEventListener('touchstart', (e) => {
            touchStartX = e.touches[0].clientX;
        });
        document.addEventListener('touchmove', (e) => {
            if (this.menuOpen && e.touches[0].clientX < touchStartX - 50) {
                this.closeMenu();
            }
        });

        // Pull-to-refresh
        this.initPullToRefresh();
    }

    toggleMenu() {
        this.menuOpen = !this.menuOpen;
        document.getElementById('mobile-nav').classList.toggle('open');
        document.getElementById('mobile-overlay').classList.toggle('visible');
    }

    closeMenu() {
        this.menuOpen = false;
        document.getElementById('mobile-nav').classList.remove('open');
        document.getElementById('mobile-overlay').classList.remove('visible');
    }

    initPullToRefresh() {
        let startY = 0;
        let pulling = false;

        document.addEventListener('touchstart', (e) => {
            if (window.scrollY === 0) {
                startY = e.touches[0].clientY;
                pulling = true;
            }
        });

        document.addEventListener('touchmove', (e) => {
            if (pulling && e.touches[0].clientY - startY > 80) {
                location.reload();
            }
        });

        document.addEventListener('touchend', () => { pulling = false; });
    }
}

const mobileUI = new MobileUI();
```

## Dependencies

No new dependencies. Uses CSS media queries and vanilla JavaScript.

## Testing

### Integration Tests

```rust
#[tokio::test]
async fn test_dashboard_includes_responsive_css() {
    let app = test_app().await;
    let response = app.get("/dashboard").await;
    let body = response.text().await;
    assert!(body.contains("responsive.css"));
}

#[tokio::test]
async fn test_responsive_css_serves() {
    let app = test_app().await;
    let response = app.get("/static/css/responsive.css").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await;
    assert!(body.contains("@media"));
    assert!(body.contains("max-width: 768px"));
}
```

### Visual Tests (using Playwright MCP)

```
# Test mobile viewport
playwright.browser_resize(width=375, height=812)  # iPhone dimensions
playwright.browser_navigate(url="http://localhost:3001/dashboard")
playwright.browser_snapshot()  # Verify card layout rendered
playwright.browser_verify_element_visible(element="mobile-nav-toggle")
playwright.browser_take_screenshot()  # Visual evidence

# Test tablet viewport
playwright.browser_resize(width=768, height=1024)
playwright.browser_navigate(url="http://localhost:3001/dashboard")
playwright.browser_snapshot()

# Test desktop viewport
playwright.browser_resize(width=1440, height=900)
playwright.browser_navigate(url="http://localhost:3001/dashboard")
playwright.browser_verify_element_visible(element="desktop-nav")
```

## Example Usage

```
Desktop (1440px):
┌─────────────────────────────────────────────────────┐
│ PQVault  Dashboard  Keys  Health  Settings  [Dark]  │
├──────────────────────────────┬──────────────────────┤
│ Key Name      Cat    Health  │ Preview Panel        │
│ STRIPE_KEY    pay    good    │                      │
│ AWS_KEY       cloud  good    │ Selected key detail  │
│ DB_URL        db     warn    │ shows here           │
└──────────────────────────────┴──────────────────────┘

Mobile (375px):
┌──────────────────────┐
│ [=] PQVault    [Dark]│
├──────────────────────┤
│ [Search...         ] │
├──────────────────────┤
│ ┌──────────────────┐ │
│ │ STRIPE_KEY       │ │
│ │ Category: payment│ │
│ │ Health: good     │ │
│ │ [Copy] [Rotate]  │ │
│ └──────────────────┘ │
│ ┌──────────────────┐ │
│ │ AWS_KEY          │ │
│ │ Category: cloud  │ │
│ │ Health: good     │ │
│ │ [Copy] [Rotate]  │ │
│ └──────────────────┘ │
│ ┌──────────────────┐ │
│ │ DATABASE_URL     │ │
│ │ Category: db     │ │
│ │ Health: warning  │ │
│ │ [Copy] [Rotate]  │ │
│ └──────────────────┘ │
└──────────────────────┘
```
