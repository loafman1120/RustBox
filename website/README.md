# RustBox website

React + Vite product site for RustBox. GSAP ScrollTrigger drives section and
parallax animation; Lenis provides smooth scrolling.

The production build contains three coordinated surfaces:

- `/` — product overview;
- `/config/` — searchable native configuration reference generated from the
  versioned JSON Schema;
- `/api/` — Scalar-powered control API reference generated from Rust handlers.

```powershell
pnpm install
pnpm dev
```

Create a production build with `pnpm build`.

Refresh the checked-in OpenAPI document after changing the Clash-compatible
control surface:

```powershell
pnpm generate:openapi
```

## GitHub Pages

Changes under `website/` are deployed after they are pushed to `main`. A
deployment can also be started manually from **Actions → Deploy website to
GitHub Pages → Run workflow**. The workflow installs the locked pnpm
dependencies, builds with the repository's GitHub Pages base path, and deploys
the generated `dist` artifact.

The Vite build also publishes the checked-in native TOML/JSON contract at
`schema/rustbox-config-v1.schema.json`. The source artifact is generated from
the Rust deserialization model under `crates/rustbox-config-file/schema`; do
not edit either published copy by hand.

Before the first run, select **GitHub Actions** under **Settings → Pages → Build
and deployment → Source**.
