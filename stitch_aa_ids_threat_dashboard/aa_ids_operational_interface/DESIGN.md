---
name: AA-IDS Operational Interface
colors:
  surface: '#10131a'
  surface-dim: '#10131a'
  surface-bright: '#363941'
  surface-container-lowest: '#0b0e15'
  surface-container-low: '#191b23'
  surface-container: '#1d2027'
  surface-container-high: '#272a31'
  surface-container-highest: '#32353c'
  on-surface: '#e1e2ec'
  on-surface-variant: '#c2c6d6'
  inverse-surface: '#e1e2ec'
  inverse-on-surface: '#2e3038'
  outline: '#8c909f'
  outline-variant: '#424754'
  surface-tint: '#adc6ff'
  primary: '#adc6ff'
  on-primary: '#002e6a'
  primary-container: '#4d8eff'
  on-primary-container: '#00285d'
  inverse-primary: '#005ac2'
  secondary: '#c0c1ff'
  on-secondary: '#1000a9'
  secondary-container: '#3131c0'
  on-secondary-container: '#b0b2ff'
  tertiary: '#ffb786'
  on-tertiary: '#502400'
  tertiary-container: '#df7412'
  on-tertiary-container: '#461f00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a42'
  on-primary-fixed-variant: '#004395'
  secondary-fixed: '#e1e0ff'
  secondary-fixed-dim: '#c0c1ff'
  on-secondary-fixed: '#07006c'
  on-secondary-fixed-variant: '#2f2ebe'
  tertiary-fixed: '#ffdcc6'
  tertiary-fixed-dim: '#ffb786'
  on-tertiary-fixed: '#311400'
  on-tertiary-fixed-variant: '#723600'
  background: '#10131a'
  on-background: '#e1e2ec'
  surface-variant: '#32353c'
typography:
  display-lg:
    fontFamily: inter
    fontSize: 30px
    fontWeight: '600'
    lineHeight: 38px
    letterSpacing: -0.02em
  h1:
    fontFamily: inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  h2:
    fontFamily: inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 26px
  body-md:
    fontFamily: inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  mono-code:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  mono-label:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  gutter: 16px
  margin: 24px
---

## Brand & Style

The design system is engineered for high-stakes Security Operations Center (SOC) environments where cognitive load management and rapid data synthesis are paramount. The aesthetic follows a **Minimalist-Modern** approach with a heavy emphasis on "maximum signal, minimum chrome." 

By stripping away unnecessary decorative elements, the system ensures that security analysts can focus entirely on threat detection and incident response. The visual language conveys institutional credibility and technical precision through a disciplined dark-mode palette, sharp geometry, and high-density information layouts. The atmosphere is one of focused urgency, mirroring the professional rigor found in industry-leading observability platforms.

## Colors

The palette is optimized for long-duration monitoring under low-light conditions. The core background uses a deep obsidian to provide maximum contrast for active signals. 

- **Primary & Action:** Electric Blue is reserved for primary actions and active states to guide the eye toward intent.
- **Surface Hierarchy:** Three distinct layers of slate-grays define spatial depth without the need for heavy shadows.
- **Semantic Signals:** Status colors are high-chroma to ensure critical alerts are never missed. "Critical" Red and "Warning" Amber are used sparingly to prevent alarm fatigue.
- **Borders:** A consistent low-contrast border color defines structure while remaining secondary to the content.

## Typography

This system employs a dual-font strategy to distinguish between UI navigation and technical forensics.

- **Inter:** Used for all standard interface elements, navigation, and instructional text. Its high x-height ensures legibility at the small scale required for data-dense dashboards.
- **JetBrains Mono:** Used exclusively for technical data points, including IP addresses, SHA-256 hashes, log entries, and CLI outputs. The monospaced nature allows for vertical alignment of data strings, making it easier for analysts to spot patterns and anomalies in log streams.
- **Scales:** Typography sizes are kept tight (11px to 30px) to maximize the amount of information visible on a single screen without scrolling.

## Layout & Spacing

The layout utilizes a **Fluid Grid** system based on a 4px baseline increment. This granular control allows for the high-density arrangement of cards and data tables.

- **Grid:** A 12-column grid is standard for main dashboard views.
- **Density:** Elements are packed tightly with minimal padding (8px–12px inside cards) to prioritize content. 
- **Alignment:** All components must align to the 4px grid. Use 16px gutters between major modules to provide just enough "breathing room" to distinguish between different data sets.

## Elevation & Depth

In this design system, depth is communicated through **Tonal Layers** and **Low-Contrast Outlines** rather than traditional shadows.

- **Level 0 (Background):** The base layer (#0A0D14) for the entire application.
- **Level 1 (Surface):** The primary container color (#111827) for cards and modules.
- **Level 2 (Elevated):** Used for hover states, tooltips, and modals (#1A2235).
- **Outlines:** Every container uses a 1px solid border (#1E2D45). This creates a "blueprint" feel that looks structural and precise. 
- **Interaction:** Shadows are only used on top-level modals and dropdowns, appearing as subtle, dark, 8px blurs with 40% opacity to provide a slight lift from the grid.

## Shapes

The shape language is disciplined and geometric. 

- **Containers:** All cards, modules, and main surfaces use a consistent 10px corner radius. This softens the technical aesthetic just enough to feel modern without losing its "utilitarian tool" identity.
- **Small Elements:** Buttons, input fields, and tags use a smaller 4px or 6px radius to maintain a sharper appearance relative to their size.
- **Icons:** Use 2px stroke weights with squared-off ends to match the architectural feel of the 1px borders.

## Components

- **Buttons:** Primary buttons are solid Electric Blue with white text. Secondary buttons are ghost-style with 1px borders. Sizes should be compact (28px - 32px height).
- **Data Tables:** The backbone of the system. Use zebra-striping (Surface vs Surface Elevated) only on hover. Headers must be in all-caps Mono-label style. Row heights should be kept to a 32px minimum.
- **Status Chips:** Small, low-profile badges using a subtle background tint (10% opacity of the status color) with high-contrast text and a 4px circular "dot" indicator.
- **Cards:** Utilize a header-body structure. Headers should have a bottom 1px border. 10px radius on the outer container.
- **Input Fields:** Darker than the surface color with a 1px border. On focus, the border transitions to the Primary Electric Blue.
- **Telemetry Charts:** Use 2px line weights for Sparklines. Background grid lines in charts should use the Border color at 50% opacity.
- **Log Viewer:** A dedicated component using JetBrains Mono, supporting syntax highlighting for common query languages (KQL/SQL).