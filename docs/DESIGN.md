# Interface design

Kaa's interface is plain HTML, CSS and JavaScript (`src/kaa/web`). No framework, no build step, no external request. The motion and material choices follow the fluid interface principles from Apple's WWDC talks (for example *Designing Fluid Interfaces*). Kaa is not affiliated with Apple.

## Principles

| Principle | How Kaa applies it |
|---|---|
| **Respond at once** | Buttons, filters, rows and alerts react on pointer down, not on release. |
| **Direct manipulation** | The drawer tracks the pointer one to one and keeps the offset from where you grabbed it. |
| **Interruptible** | Every drawer movement starts from its live position and velocity, so you can grab or reverse it at any frame, with no jump. Input is never locked during a transition. |
| **Springs, not timers** | The drawer uses a spring defined by a damping ratio and a response time. It is critically damped (no bounce) by default, and bounces slightly only when a flick carried momentum. |
| **Momentum** | On release, the pointer velocity is projected forward to decide whether the drawer closes or stays open, and is handed to the spring as its initial velocity. |
| **Symmetry** | The drawer enters from the right and leaves to the right. |
| **Soft boundaries** | Dragging past the open position meets progressive resistance instead of a hard stop. |
| **Materials** | The top bar and the drawer are translucent layers with a light top or side edge. The page steps back and dims while the drawer is open. The bar only draws its divider once content scrolls under it. |
| **Type** | Tracking is tightened on large figures and titles, and left neutral on body text. |

## Accessibility

- `prefers-reduced-motion`: the drawer fades instead of sliding, nothing springs, the page does not step back.
- `prefers-reduced-transparency`: translucent surfaces become solid.
- `prefers-contrast: more`: borders strengthen, translucent surfaces become solid.
- A closed drawer is removed from keyboard focus. While it is open, the page behind is inert and focus returns to the element that opened it.

## Where it lives

- Spring, drag and momentum: the "drawer physics" block in `src/kaa/web/app.js`.
- Tokens, materials, press feedback and media queries: `src/kaa/web/app.css`.
- Screenshots: `python scripts/demo.py`, then open `http://127.0.0.1:8480/?theme=dark&still` (add `#d1` for the device drawer). `still` freezes animations so the capture is stable.
