---
name: Sentinel Enterprise
colors:
  surface: '#f7f9fb'
  surface-dim: '#d8dadc'
  surface-bright: '#f7f9fb'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f2f4f6'
  surface-container: '#eceef0'
  surface-container-high: '#e6e8ea'
  surface-container-highest: '#e0e3e5'
  on-surface: '#191c1e'
  on-surface-variant: '#45464d'
  inverse-surface: '#2d3133'
  inverse-on-surface: '#eff1f3'
  outline: '#76777d'
  outline-variant: '#c6c6cd'
  surface-tint: '#565e74'
  primary: '#000000'
  on-primary: '#ffffff'
  primary-container: '#131b2e'
  on-primary-container: '#7c839b'
  inverse-primary: '#bec6e0'
  secondary: '#0058be'
  on-secondary: '#ffffff'
  secondary-container: '#2170e4'
  on-secondary-container: '#fefcff'
  tertiary: '#000000'
  on-tertiary: '#ffffff'
  tertiary-container: '#00201d'
  on-tertiary-container: '#0c9488'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dae2fd'
  primary-fixed-dim: '#bec6e0'
  on-primary-fixed: '#131b2e'
  on-primary-fixed-variant: '#3f465c'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#adc6ff'
  on-secondary-fixed: '#001a42'
  on-secondary-fixed-variant: '#004395'
  tertiary-fixed: '#89f5e7'
  tertiary-fixed-dim: '#6bd8cb'
  on-tertiary-fixed: '#00201d'
  on-tertiary-fixed-variant: '#005049'
  background: '#f7f9fb'
  on-background: '#191c1e'
  surface-variant: '#e0e3e5'
typography:
  display:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.05em
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '450'
    lineHeight: 18px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  gutter: 16px
  component-gap: 12px
  sidebar-width: 260px
---

## Brand & Style

The design system is engineered for high-stakes cybersecurity environments where clarity, speed of cognition, and trust are paramount. The personality is **Corporate Modern** with a lean toward **Minimalism**, stripping away visual noise to prioritize data density and threat detection.

The target audience consists of Security Operations Center (SOC) analysts and C-suite executives who require an interface that feels authoritative and institutional. The UI avoids "cyber-noir" tropes in favor of a bright, clinical, and high-legibility workspace. It utilizes a structured grid, ample whitespace, and a sophisticated light-mode palette to ensure long-term comfort during extended monitoring sessions.

## Colors

This design system utilizes a "Clinical Tech" palette. The primary **Deep Navy** provides the grounding for navigation and headers, while **Vibrant Blue** acts as the primary action color. 

- **Backgrounds:** Use the neutral `#F8FAFC` for the global canvas to reduce eye strain. 
- **Surfaces:** All interactive cards and containers must use pure `#FFFFFF` to create a clear "lift" from the background.
- **Semantic Colors:** These are strictly reserved for status indicators (Critical, Warning, Healthy). Do not use them for decorative elements. 
- **Data Visualization:** Use a sequence starting with the Secondary Blue, followed by the Tertiary Teal, then complementary shades of indigo and slate to maintain a professional, monochromatic-adjacent feel.

## Typography

The typography system prioritizes the "Inter" family for its exceptional legibility in dense UI environments. 

- **Hierarchy:** Use `headline-md` for card titles and `body-md` for the standard interface text. 
- **Data Display:** For IP addresses, hash values, and log entries, use the `data-mono` role (JetBrains Mono) to ensure character alignment and prevent misreading of similar characters (like 0 and O).
- **Labels:** Small uppercase labels (`label-caps`) should be used for table headers and section overline text to provide structure without overwhelming the content.

## Layout & Spacing

The system follows a strict **4px baseline grid**. 

- **Grid System:** Use a 12-column fluid grid for the main dashboard area. Gutters are fixed at 16px to maintain high data density.
- **Sidebar:** A fixed left-hand navigation (260px) is required for enterprise scalability.
- **Responsive Behavior:** 
  - **Desktop (1280px+):** Full sidebar and 12-column layout.
  - **Tablet (768px - 1279px):** Sidebar collapses to icons; 8-column layout.
  - **Mobile (<767px):** Single column; navigation moves to a bottom bar or hamburger menu.
- **Padding:** Content cards use 24px internal padding for standard views, reducing to 16px for data-heavy utility panels.

## Elevation & Depth

Hierarchy is established through **Tonal Layers** and **Low-Contrast Outlines** rather than aggressive shadows.

1.  **Level 0 (Background):** `#F8FAFC` - The lowest layer.
2.  **Level 1 (Surfaces):** Pure White `#FFFFFF` with a 1px solid border of `#E2E8F0`. This is the standard for dashboard cards.
3.  **Level 2 (Interactive/Floating):** Used for dropdowns and tooltips. Apply a soft, diffused shadow: `0px 4px 12px rgba(15, 23, 42, 0.08)`.
4.  **Level 3 (Modals):** Centered overlays with a backdrop blur (8px) and a more pronounced shadow to focus user attention.

Avoid using shadows on the primary dashboard cards; let the borders and background contrast do the work to keep the interface feeling crisp and "flat."

## Shapes

The shape language is "Approachable Professional." 

- **Base Radius:** 8px (`rounded`) for buttons, inputs, and small components.
- **Large Radius:** 12px to 16px (`rounded-lg` / `rounded-xl`) for main dashboard cards and containers to soften the technical nature of the data.
- **Strictness:** Do not use 0px sharp corners, as it feels too aggressive, nor pill-shapes for primary containers, as it wastes space in data-heavy layouts.

## Components

### Buttons
- **Primary:** Deep Navy background, white text. 8px radius.
- **Secondary:** White background, 1px `#E2E8F0` border, Navy text.
- **Ghost:** No border or background unless hovered. Used for utility actions in tables.

### Data Tables
- **Header:** Use `label-caps` typography with a subtle grey background.
- **Rows:** 48px minimum height. Use a subtle bottom border (`#F1F5F9`). Hover state should change row background to `#F8FAFC`.
- **Status Badges:** Small, 4px radius, using low-opacity versions of semantic colors (e.g., 10% opacity Emerald background with 100% opacity Emerald text).

### Input Fields
- White background, 1px border. On focus, the border changes to Vibrant Blue with a 2px outer glow of the same color at 10% opacity.

### Cards
- Always use the White surface. 
- Headers within cards should have a thin bottom divider if the card contains a list or table.
- Use "Empty States" with subtle line-art icons and `body-sm` text when data is unavailable.

### Sidebar Navigation
- Deep Navy background.
- Active state: Vibrant Blue left-border (4px) and a subtle background highlight.
- Icons: Use 20px 2pt stroke icons for visual balance with the Inter typeface.