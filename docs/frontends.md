# Frontends and packaging

The authenticator is a daemon, not an application. That is a deliberate split and it is
what makes the many frontends below cheap: **every one of them is a view.** None of them
decides whether a request is authentic, none of them sees a key, and none of them can
approve anything on its own. They all do the same two things:

1. tell the user a request arrived — *who*, *what*, *which machine* — and
2. report the user's yes or no.

The judgement happens in `rbad`, against a signature over a challenge that is
consumed on arrival and bound to a Linux user. A frontend that gets this wrong is not a
smaller bug, it is the whole security model.

## The contract every frontend honours

```text
rba auth --user U --purpose P --service S
    -> ok / code        (never a key, never a signature, never a secret)
```

A frontend is a *trigger*, not an authority. Two rules follow, and both are load-bearing:

- **A denial is a normal outcome.** If the daemon is unreachable or no device is
  paired, the frontend says so and stops. It must not ask for a password as a
  fallback, retry in a loop, or pretend the action succeeded. Falling back to another
  credential is a *policy* decision, and policy belongs to the caller — for PAM and
  polkit it is made in the stack, not in our code.
- **A frontend never caches an approval.** Each request is answered on its own. A
  frontend that remembered "the user said yes to that laptop" has invented an ambient
  authorisation the protocol deliberately does not have.

## Why there is a daemon at all

Because every one of these frontends would otherwise re-implement the same three
things: the prompt, the socket client, and the failure handling. With the daemon they
share:

| Concern | Where it lives |
|---|---|
| Is this request authentic? | `rbad`, signature verification |
| Is it for *this* user, on *this* machine? | daemon, bound to the signed context |
| What does the device show? | the request's signed, unsigned-only prose fields |
| Rate limiting, replay, freshness | daemon and app, per protocol §10–§12 |

The cost is one more process and one socket. The benefit is that a KDE user and an XFCE
user are running *the same security code*, and a bug fixed once is fixed for everyone.

## Frontend matrix

Ordered by how much they are worth building first, not by how easy they are.

### 1. `rba` — the reference frontend (exists)

The CLI is the reference implementation of the contract above, and it is what the
integration tests drive. It is also genuinely useful on its own for a server or over
SSH, where there is no desktop to prompt on.

### 2. GTK4 / libadwaita — the widest reach

The largest installed base among the options, and libadwaita's `Adw.MessageDialog`
plus a `Gtk.ListBox` of pending requests maps almost one-to-one onto what we need.
Pairing wants a real dialog; approving wants a persistent notification with an
in-window fallback, because the user may be looking at another application.

Effort is low, and this is the frontend that makes the project usable to most people
first.

### 3. Tray — StatusNotifierItem / KStatusNotifierItem / AppIndicator

One idea, three implementations, and this is where it pays to be careful.

SNI is the freedesktop standard. `KStatusNotifierItem` is KDE's, `AppIndicator` is
GNOME's older interface. A tray icon can *show* that a request is pending, and it can
carry a single yes/no action — but a **fingerprint check cannot happen in a tooltip or
a context menu**, and a request must never be approved by a hover or by the icon
simply disappearing. Approving belongs in a window with a real button.

So the rule for the tray everywhere: **attention only.** It raises the window. The
window decides.

### 4. Qt 6 / KDE Plasma — widget and full window

Two distinct products:

- **Plasmoid (Plasma widget).** Glorious, but it lives *inside plasmashell*, which is
  running inside the X session we are trying to authenticate into. Useful for pairing
  and for status; a poor host for the approval dialog itself, because the thing being
  protected can be tampered with. If a Plasmoid ever offers approval, it is only ever
  as a mirror of a decision already made elsewhere.
- **Standalone Kirigami window.** The better KDE answer: an ordinary application window
  that can present a request properly, with the Plasmoid optionally mirroring it.

Same order as the tray: widget for attention, window for the decision.

### 5. LXQt panel plugin

The smallest surface and the least ceremony: an `ILXQtPanelPlugin` that shows pending
state and raises the main window. No signing, no key material, no new dependencies.

### 6. Xfce panel plugin

`libxfce4panel` / `XfcePanelPlugin`, same shape as LXQt. LXQt's plugin interface is a
useful reference for both, since the two are close relatives and a single small plugin
design covers them both.

### 7. GNOME Shell extension — future, deliberately

A GNOME Shell extension is an unusual package: it is a zip installed by `gnome-extensions
install`, with a `metadata.json`, bundled JS, and no compilation step. It reuses the
same GTK4 UI code as item 2, and it embeds the backend directly.

Two consequences worth stating before anyone starts:

- **It is exclusive to GNOME.** A user on KDE or XFCE gets nothing. That is a coverage
  decision, not a technical one, and it is why it is last.
- **It bundles the backend**, so the reviewable Rust core is not what runs on the
  user's machine. That is a real change in the trust story and it deserves a decision
  of its own, not a footnote in a roadmap. If it happens, it should call the daemon
  over the control socket like everything else, and the "backend built in" variant
  should be treated as a different product with a different threat model.

## What a frontend can and cannot see

| Shown to the user | Verifiable |
|---|---|
| Which Linux user is asking | signed |
| Which host, and its fingerprint | signed |
| The action, e.g. `sudo`, `org.freedesktop.systemd1.manage-units` | signed |
| The time the request was made | signed |
| A device-supplied description | **unverified** |

The last row is deliberate. `display_host_name` and `display_detail` are attacker-
supplied prose and are **outside the signature**. A frontend must render them as
unverified text and must never let them carry the weight of a real field — no styling
that looks like a system dialog, no wording that implies approval, no length limit
assumed. The protocol signs the facts; the prose is decoration, and a frontend that
treats decoration as fact has handed the attacker the UI.

## Sequencing

1. **CLI** — done, and the tests depend on it.
2. **GTK4** — widest reach, lowest effort.
3. **Tray (SNI + AppIndicator + KStatusNotifierItem)** — one small component, three
   integration points, attention only.
4. **Qt 6 window**, then the Plasma Plasmoid as a mirror.
5. **LXQt and Xfce panel plugins** — nearly free once 3 and 4 exist.
6. **GNOME Shell extension** — only after a deliberate decision about bundling the
   backend.

Everything above item 1 is a client of one socket, speaking one documented protocol.
None of them needs to know what a signature is.