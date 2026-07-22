# RustBox website

React + Vite product site for RustBox. GSAP ScrollTrigger drives section and
parallax animation; Lenis provides smooth scrolling.

```powershell
pnpm install
pnpm dev
```

Create a production build with `pnpm build`.

## GitHub Pages

Changes under `website/` are deployed after they are pushed to `main`. A
deployment can also be started manually from **Actions → Deploy website to
GitHub Pages → Run workflow**. The workflow installs the locked pnpm
dependencies, builds with the repository's GitHub Pages base path, and deploys
the generated `dist` artifact.

Before the first run, select **GitHub Actions** under **Settings → Pages → Build
and deployment → Source**.
