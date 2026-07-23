import { useLayoutEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Lenis from 'lenis';

const REPO = 'https://github.com/loafman1120/RustBox';

const scenarios = {
  browser: {
    glyph: 'BR', kind: 'TCP / HTTPS', host: 'api.github.com:443', meta: 'browser.exe · Wi-Fi · work profile', result: 'PROXY / AUTO', resultClass: 'proxy',
    stages: ['TUN / TCP', 'DOMAIN + PROCESS', 'RULE SET: DEV', 'SELECTOR / AUTO', 'VLESS · 38 MS'],
  },
  dns: {
    glyph: 'DN', kind: 'UDP / DNS', host: 'dns.google:53', meta: 'captured packet · Ethernet · system', result: 'HIJACK / DOH', resultClass: 'dns',
    stages: ['TUN / UDP', 'QUERY + REVERSE MAP', 'RULE SET: DNS', 'DOH / PROXY', 'ANSWER · 24 MS'],
  },
  update: {
    glyph: 'UP', kind: 'TCP / HTTPS', host: 'updates.example.com:443', meta: 'updater.exe · Wi-Fi · background', result: 'DIRECT', resultClass: 'direct',
    stages: ['MIXED / TCP', 'DOMAIN + PROCESS', 'RULE: UPDATES', 'DIRECT', 'RELAY · 7 MS'],
  },
};

const integrations = {
  cli: {
    filename: 'POWERSHELL / CLI', kicker: 'REFERENCE HOST', title: 'Own the process and the device.',
    copy: 'The CLI loads native TOML/JSON or supported Clash YAML, owns the engine lifecycle, responds to network changes, and can expose local control APIs.',
    list: ['Typed validation before sockets open', 'Configuration reload without replacing the client', 'Detailed logs via RUSTBOX_LOG'],
    link: REPO, linkLabel: 'Open CLI guide',
    code: `# Build once, then start the local client\ncargo build --workspace\ncargo run -p rustbox-app -- run \\\n  --config examples/rustbox.toml\n\n# Validate before changing any network state\ncargo run -p rustbox-app -- check-config \\\n  --config examples/rustbox.toml`,
  },
  flutter: {
    filename: 'DART / FLUTTER', kicker: 'EMBEDDED ENGINE', title: 'A small API around the same core.',
    copy: 'Prebuilt native libraries package the Rust runtime behind an async lifecycle API. Client apps do not need Rust, Cargo, or a C toolchain.',
    list: ['Android, iOS, Windows, and Linux', 'Serialized lifecycle calls with typed errors', 'The same configuration accepted by the CLI'],
    link: `${REPO}/tree/main/apps/rustbox-flutter`, linkLabel: 'Open Flutter guide',
    code: `import 'package:rustbox_flutter/rustbox_flutter.dart';\n\nawait RustBox.initialize();\nfinal engine = await RustBoxEngine.create(\n  configToml: config,\n);\n\ntry {\n  await engine.start();\n  final snapshot = await engine.snapshot();\n  await engine.reload(nextConfig);\n  await engine.stop();\n} finally {\n  await engine.close();\n}`,
  },
  config: {
    filename: 'TOML / SHARED CONFIG', kicker: 'ONE CONFIGURATION', title: 'Describe a complete local runtime.',
    copy: 'Native TOML and JSON share one typed model and one generated JSON Schema contract. Import supported Clash YAML in the CLI, or keep full DNS and TUN control in RustBox-native configuration.',
    list: ['References resolved before runtime', 'Unsupported combinations fail explicitly', 'Versioned Schema for completion and tooling'],
    link: `${REPO}/blob/main/docs/configuration-contract.md`, linkLabel: 'Open configuration contract',
    code: `schema_version = 1\n\n[[inbounds]]\nid = "local"\ntype = "mixed"\nlisten = "127.0.0.1:2080"\n\n[[outbounds]]\nid = "direct"\ntype = "direct"\n\n[[routes]]\ntype = "default"\noutbound = "direct"`,
  },
};

function Brand({ footer = false }) {
  return (
    <a className="brand" href="#top" aria-label="RustBox home">
      <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
      <span>RUSTBOX</span>
      {!footer && <small>NETWORK ENGINE</small>}
    </a>
  );
}

function Header({ activeSection }) {
  const [open, setOpen] = useState(false);
  const links = [
    ['#capabilities', 'Capabilities', 'capabilities'],
    ['#runtime', 'Runtime', 'runtime'],
    ['#integrate', 'Integrate', 'integrate'],
    ['#control', 'Control', 'control'],
    ['./config/', 'Config', ''],
    ['./api/', 'API', ''],
    ['#start', 'Get started', 'start'],
  ];
  return (
    <header className="site-header">
      <Brand />
      <nav id="primary-nav" className={open ? 'is-open' : ''} aria-label="Primary navigation">
        {links.map(([href, label, id]) => <a key={href} className={activeSection === id ? 'is-active' : ''} href={href} onClick={() => setOpen(false)}>{label}</a>)}
      </nav>
      <div className="header-actions">
        <span className="project-state"><i />Active development</span>
        <a className="source-link" href={REPO}>GitHub <span>↗</span></a>
        <button className={`menu-toggle ${open ? 'is-open' : ''}`} type="button" aria-label={`${open ? 'Close' : 'Open'} navigation`} aria-controls="primary-nav" aria-expanded={open} onClick={() => setOpen(value => !value)}><i /><i /></button>
      </div>
    </header>
  );
}

function RuntimeCard() {
  const bars = ['24%', '34%', '27%', '48%', '43%', '61%', '54%', '76%', '63%', '86%', '72%', '96%', '84%', '68%', '74%', '58%', '70%', '52%', '63%', '44%'];
  return (
    <div className="runtime-card reveal" data-parallax="-28" aria-label="Example RustBox runtime snapshot">
      <div className="runtime-topbar"><div><i /><span>RUNTIME / LOCAL</span></div><span className="live-label">LIVE <b /></span></div>
      <div className="runtime-health"><div><small>ENGINE STATE</small><strong>Protected</strong><p>Policy loaded · system state tracked</p></div><div className="latency-gauge"><span>38</span><small>ms</small></div></div>
      <div className="traffic-list">
        <article><span className="app-glyph">BR</span><div><strong>Browser</strong><small>api.github.com:443</small></div><span className="route-tag proxy">PROXY</span></article>
        <article><span className="app-glyph">CD</span><div><strong>Code editor</strong><small>registry.npmjs.org:443</small></div><span className="route-tag direct">DIRECT</span></article>
        <article><span className="app-glyph">SY</span><div><strong>System</strong><small>dns.google:853</small></div><span className="route-tag dns">DOT</span></article>
      </div>
      <div className="throughput"><div className="throughput-copy"><span>THROUGHPUT / 60 SEC</span><strong>8.4 <small>MB/s</small></strong></div><div className="bar-chart" aria-hidden="true">{bars.map((height, index) => <i key={index} style={{ '--h': height }} />)}</div></div>
      <div className="runtime-footer"><span><i /> 18 active</span><span>↑ 6.7 MB/s</span><span>↓ 1.7 MB/s</span></div>
    </div>
  );
}

function Hero() {
  return (
    <>
      <section className="hero section-shell" id="top">
        <div className="hero-copy"><p className="eyebrow hero-kicker"><span>01</span> CLIENT-SIDE PROXY RUNTIME</p><h1 className="hero-title">The network engine<br /><em>your client can own.</em></h1><p className="lede hero-lede">Routing, DNS, proxy protocols, TUN, and runtime control in one Rust engine—built for a single app, a single device, and a lifecycle you can trust.</p><div className="hero-actions"><a className="button primary" href="#start">Run RustBox <span>↓</span></a><a className="button secondary" href={`${REPO}/tree/main/apps/rustbox-flutter`}>Embed in Flutter <span>↗</span></a></div><div className="trust-row" aria-label="Product highlights"><span><b>4</b> client platforms</span><span><b>5</b> DNS transports</span><span><b>2</b> local control APIs</span></div></div>
        <RuntimeCard />
      </section>
      <section className="premise section-shell reveal" aria-label="RustBox product principles"><article><span>01</span><h2>Own the lifecycle</h2><p>Start, reload, snapshot, and stop without leaving background tasks or device settings behind.</p></article><article><span>02</span><h2>Keep one policy</h2><p>Route TCP, UDP, and DNS through the same typed configuration and explicit decision model.</p></article><article><span>03</span><h2>Ship the same engine</h2><p>Use the CLI as a reference client or embed the Rust core behind a small Flutter API.</p></article></section>
    </>
  );
}

function SectionHeading({ index, kicker, children, copy }) {
  return <div className="section-heading reveal"><div><p className="eyebrow"><span>{index}</span> {kicker}</p><h2>{children}</h2></div><p>{copy}</p></div>;
}

function Capabilities() {
  return (
    <section className="capabilities section-shell" id="capabilities">
      <SectionHeading index="02" kicker="COMPLETE NETWORK TOOLKIT" copy="RustBox composes the parts a real proxy client needs without leaking protocol or platform concerns into the routing core.">Everything at the edge.<br /><em>One core underneath.</em></SectionHeading>
      <div className="capability-grid">
        <article className="capability-card featured reveal"><div className="card-index">A / ENTRY</div><div className="capability-icon icon-entry" aria-hidden="true"><i /><i /><i /></div><h3>Bring traffic in</h3><p>Serve explicit local proxy ports or capture device traffic through packet and transparent entry points.</p><div className="tag-list"><span>HTTP CONNECT</span><span>SOCKS5</span><span>MIXED</span><span>TUN</span><span>TRANSPARENT</span><span>ANYTLS</span></div></article>
        <article className="capability-card reveal"><div className="card-index">B / ROUTE</div><div className="capability-icon icon-route" aria-hidden="true"><i /><i /><i /></div><h3>Decide with context</h3><p>Match domain, IP, port, process, inbound, network type, interface, user, or Android package.</p><div className="card-note">Local & remote rule sets · URL testing · selector groups</div></article>
        <article className="capability-card reveal"><div className="card-index">C / RESOLVE</div><div className="capability-icon icon-dns" aria-hidden="true"><i /><i /><i /><i /></div><h3>Control DNS end to end</h3><p>Encrypted upstreams, per-rule resolution, FakeIP, cache, reverse mapping, and DNS hijacking.</p><div className="tag-list"><span>UDP</span><span>TCP</span><span>DoT</span><span>DoH</span><span>DoQ</span></div></article>
        <article className="capability-card wide reveal"><div className="card-index">D / CONNECT</div><h3>Reach the network your way</h3><p>Common modern proxy protocols share a consistent outbound interface, so routing stays independent from transport.</p><div className="protocol-cloud">{['DIRECT', 'SHADOWSOCKS', 'VMESS', 'VLESS', 'TROJAN', 'HYSTERIA2', 'TUIC V5', 'ANYTLS', 'NAIVEPROXY', 'WIREGUARD', 'SHADOWTLS V3'].map(item => <span key={item}>{item}</span>)}</div></article>
        <article className="capability-card transport reveal"><div className="card-index">E / TRANSPORT</div><h3>Compose transports</h3><p>TCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade, TLS, Reality, ECH, and Mux.Cool.</p><div className="transport-lines" aria-hidden="true"><i /><i /><i /><i /></div></article>
      </div>
    </section>
  );
}

function RouteLab() {
  const [selected, setSelected] = useState('browser');
  const scenario = scenarios[selected];
  const stageMeta = [['INBOUND', 'Accept a stream or datagram.'], ['ENRICH', 'Attach available local context.'], ['ROUTE', 'Pure metadata-to-decision logic.'], ['OUTBOUND', 'Open the chosen path.'], ['RELAY', 'Relay bidirectional traffic.']];
  return (
    <section className="runtime-section" id="runtime">
      <div className="section-shell">
        <SectionHeading index="03" kicker="EXPLICIT DATA PLANE" copy="Select a traffic scenario to see how RustBox enriches metadata and arrives at a route—before an outbound ever touches the network.">Trace every<br /><em>decision.</em></SectionHeading>
        <div className="route-lab reveal">
          <div className="scenario-picker" role="tablist" aria-label="Traffic scenario">{[['browser', '01', 'Browser request'], ['dns', '02', 'Captured DNS'], ['update', '03', 'App update']].map(([id, index, label]) => <button key={id} className={`scenario-tab ${selected === id ? 'is-active' : ''}`} type="button" role="tab" aria-selected={selected === id} onClick={() => setSelected(id)}><span>{index}</span> {label}</button>)}</div>
          <div className="scenario-summary"><span className="scenario-app">{scenario.glyph}</span><div><small>{scenario.kind}</small><strong>{scenario.host}</strong><p>{scenario.meta}</p></div><span className={`route-tag ${scenario.resultClass}`}>{scenario.result}</span></div>
          <div className="route-stages">{scenario.stages.map((value, index) => <article className={`route-stage ${index === 2 ? 'active' : ''}`} key={`${selected}-${value}`}><span>0{index + 1}</span><div><small>{stageMeta[index][0]}</small><strong>{value}</strong><p>{stageMeta[index][1]}</p></div></article>)}</div>
          <div className="invariant"><span>CORE INVARIANT</span><p>Routing performs no DNS, process lookup, or network I/O. Effects stay at explicit boundaries.</p><a href={`${REPO}/blob/main/docs/architecture.md`}>Read architecture ↗</a></div>
        </div>
      </div>
    </section>
  );
}

function IntegrationPanel() {
  const [selected, setSelected] = useState('cli');
  const [copied, setCopied] = useState(false);
  const data = integrations[selected];
  const copyCode = async () => { await navigator.clipboard.writeText(data.code); setCopied(true); window.setTimeout(() => setCopied(false), 1400); };
  return (
    <section className="integrate section-shell" id="integrate">
      <SectionHeading index="04" kicker="TWO CLIENT SURFACES" copy="Start with the reference CLI, then move the same configuration and lifecycle into your own Flutter client when you are ready.">Run it.<br /><em>Or build it in.</em></SectionHeading>
      <div className="integration-panel reveal">
        <div className="integration-tabs" role="tablist" aria-label="Integration example">{[['cli', '01', 'CLI client'], ['flutter', '02', 'Flutter package'], ['config', '03', 'Shared config']].map(([id, index, label]) => <button key={id} type="button" role="tab" aria-selected={selected === id} className={selected === id ? 'is-active' : ''} onClick={() => setSelected(id)}><span>{index}</span> {label}</button>)}</div>
        <div className="code-window"><div className="code-titlebar"><span>{data.filename}</span><button type="button" onClick={copyCode}>{copied ? 'Copied' : 'Copy'}</button></div><pre tabIndex="0"><code>{data.code}</code></pre></div>
        <aside className="integration-notes"><p className="integration-kicker">{data.kicker}</p><h3>{data.title}</h3><p>{data.copy}</p><ul>{data.list.map(item => <li key={item}>{item}</li>)}</ul><a href={data.link}>{data.linkLabel} <span>↗</span></a></aside>
      </div>
      <div className="platform-strip reveal"><div><span>SUPPORTED CLIENTS</span><p>One core, packaged for the places your app runs.</p></div><ul><li><b>WIN</b> Windows</li><li><b>LIN</b> Linux</li><li><b>AND</b> Android</li><li><b>IOS</b> iOS</li></ul></div>
    </section>
  );
}

function ControlSection() {
  const [selector, setSelector] = useState('Tokyo · VLESS');
  const nodes = [['Tokyo · VLESS', '38 ms'], ['Singapore · HY2', '54 ms'], ['Direct', '4 ms']];
  return (
    <section className="control-section" id="control">
      <div className="section-shell control-layout">
        <div className="control-copy reveal"><p className="eyebrow"><span>05</span> LOCAL CONTROL PLANE</p><h2>Your UI stays<br /><em>in the loop.</em></h2><p>Observe and operate the engine through one service layer. Build a native client with gRPC, or connect a familiar Clash/Mihomo-shaped dashboard over local HTTP and WebSocket.</p><div className="control-options"><article><span>01</span><div><h3>Native gRPC</h3><p>Start, stop, reload, snapshots, metrics, connections, selectors, logs, and rule sets.</p></div></article><article><span>02</span><div><h3>Clash-compatible API</h3><p>HTTP, NDJSON, and WebSocket endpoints for common local dashboard workflows.</p></div></article></div><div className="security-note"><span>!</span><p><b>Local by default.</b> Keep proxy and control listeners on loopback unless a trusted boundary provides authentication and transport security.</p></div><a className="button secondary" href={`${REPO}/blob/main/docs/control-api.md`}>Explore control APIs <span>↗</span></a></div>
        <div className="control-console reveal" data-parallax="-20" aria-label="Interactive control API dashboard example"><div className="console-header"><div><i /><span>RUSTBOX CONTROL</span></div><span>127.0.0.1:9090</span></div><div className="console-status"><div><small>RUNTIME</small><strong>RUNNING</strong></div><div><small>UPTIME</small><strong>02:18:46</strong></div><div><small>MEMORY</small><strong>42.8 MB</strong></div></div><div className="console-body"><div className="console-chart"><div className="chart-label"><span>TRAFFIC</span><span>LIVE / 5S</span></div><div className="line-chart" aria-hidden="true">{Array.from({ length: 12 }, (_, index) => <i key={index} />)}</div></div><div className="selector-card"><span>SELECTOR / AUTO</span>{nodes.map(([name, latency]) => <button key={name} className={selector === name ? 'is-selected' : ''} type="button" onClick={() => setSelector(name)}><i />{name}<b>{latency}</b></button>)}</div><div className="event-log"><span>EVENT STREAM</span><p><i>14:08:32</i> selector changed <b>→ {selector}</b></p><p><i>14:08:31</i> rule-set refreshed <b>8,412 rules</b></p><p><i>14:08:26</i> network changed <b>Wi-Fi</b></p></div></div><div className="console-footer"><span>gRPC</span><span>HTTP</span><span>WEBSOCKET</span><b>CONNECTED</b></div></div>
      </div>
    </section>
  );
}

function Architecture() {
  const layers = [['surface', 'CLIENT SURFACES', 'CLI · Flutter · Your application', 'Owns the process'], ['lifecycle', 'COMPOSITION', 'RustBox lifecycle', 'new · start · reload · snapshot · stop'], ['boundary', 'INTEGRATION', 'Config · Control · Modules · Platform', 'Effect boundaries'], ['kernel', 'PORTABLE CORE', 'Flow · Route · Relay · Host capabilities', 'Pure decisions'], ['foundation', 'FOUNDATION', 'Shared types · Tokio I/O contracts', 'Single executor']];
  return (
    <section className="architecture section-shell" id="architecture"><SectionHeading index="06" kicker="PORTABLE BY DESIGN" copy="Dependencies point inward. Platform behavior enters through explicit host capabilities; the core never guesses what the operating system can do.">Stable center.<br /><em>Replaceable edges.</em></SectionHeading><div className="layer-stack reveal">{layers.map(([type, label, title, note]) => <article className={`layer ${type}`} key={label}><span>{label}</span><strong>{title}</strong><small>{note}</small></article>)}</div><div className="architecture-foot reveal"><p><span /> Data plane</p><p><span /> Control plane</p><a href={`${REPO}/blob/main/docs/architecture.md`}>Open the architecture guide ↗</a></div></section>
  );
}

function StartSection() {
  const [copied, setCopied] = useState(false);
  const quickCode = `git clone https://github.com/loafman1120/RustBox.git\ncd RustBox\n\ncargo build --workspace\n\ncargo run -p rustbox-app -- run \\\n  --config examples/rustbox.toml\n\ncurl.exe -x http://127.0.0.1:18080 \\\n  https://example.com -I`;
  const copy = async () => { await navigator.clipboard.writeText(quickCode); setCopied(true); window.setTimeout(() => setCopied(false), 1400); };
  return (
    <section className="start section-shell" id="start"><div className="start-panel reveal"><div className="start-copy"><p className="eyebrow"><span>07</span> START LOCALLY</p><h2>From source<br />to <em>traffic.</em></h2><p>Build the workspace, start the example configuration, and verify the local HTTP CONNECT listener.</p></div><div className="terminal-window"><div className="terminal-title"><span>QUICK START / POWERSHELL</span><button type="button" onClick={copy}>{copied ? 'Copied' : 'Copy all'}</button></div><pre tabIndex="0"><code>{quickCode}</code></pre><div className="terminal-result"><i /><span>HTTP/2 200</span><small>Traffic is flowing through RustBox</small></div></div></div><div className="next-links reveal"><a href="./config/"><span>01 / REFERENCE</span><strong>Every configuration field</strong><i>→</i></a><a href="./api/"><span>02 / CONTROL</span><strong>Interactive API reference</strong><i>→</i></a><a href={`${REPO}/blob/main/docs/client-networking.md`}><span>03 / INTEGRATE</span><strong>TUN & client networking</strong><i>↗</i></a><a href={`${REPO}/tree/main/examples`}><span>04 / EXPLORE</span><strong>Runnable configurations</strong><i>↗</i></a></div></section>
  );
}

function Footer() {
  return <footer><div><Brand footer /><p>A dependable local network engine for desktop and mobile clients.</p></div><div className="footer-links"><a href="./config/">Configuration →</a><a href="./api/">Control API →</a><a href={REPO}>GitHub ↗</a><a href={`${REPO}/blob/main/LICENSE`}>MIT License ↗</a></div><div className="footer-meta"><span>BUILT WITH RUST + TOKIO</span><span>UNDER ACTIVE DEVELOPMENT</span></div></footer>;
}

export default function App() {
  const root = useRef(null);
  const [activeSection, setActiveSection] = useState('');

  useLayoutEffect(() => {
    gsap.registerPlugin(ScrollTrigger);
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const lenis = reduceMotion ? null : new Lenis({ duration: 1.05, smoothWheel: true, anchors: { offset: -78 } });
    const tick = time => lenis?.raf(time * 1000);
    if (lenis) { lenis.on('scroll', ScrollTrigger.update); gsap.ticker.add(tick); gsap.ticker.lagSmoothing(0); }

    const context = gsap.context(() => {
      gsap.set('.scroll-progress span', { scaleX: 0, transformOrigin: 'left center' });
      gsap.to('.scroll-progress span', { scaleX: 1, ease: 'none', scrollTrigger: { start: 0, end: 'max', scrub: .15 } });

      if (!reduceMotion) {
        gsap.timeline({ defaults: { ease: 'power3.out' } })
          .from('.hero-kicker', { y: 16, opacity: 0, duration: .55 })
          .from('.hero-title', { y: 48, opacity: 0, duration: .9 }, '-=.25')
          .from('.hero-lede, .hero-actions, .trust-row', { y: 22, opacity: 0, duration: .65, stagger: .1 }, '-=.5');
        gsap.utils.toArray('.reveal').forEach(element => gsap.fromTo(element, { y: 34, opacity: 0 }, { y: 0, opacity: 1, duration: .85, ease: 'power3.out', scrollTrigger: { trigger: element, start: 'top 88%', once: true } }));
        gsap.utils.toArray('[data-parallax]').forEach(element => gsap.to(element, { y: Number(element.dataset.parallax), ease: 'none', scrollTrigger: { trigger: element, start: 'top bottom', end: 'bottom top', scrub: 1 } }));
        gsap.from('.route-stage', { y: 30, opacity: 0, stagger: .09, ease: 'power2.out', scrollTrigger: { trigger: '.route-stages', start: 'top 82%' } });
        gsap.from('.layer', { x: -42, opacity: 0, stagger: .08, ease: 'power2.out', scrollTrigger: { trigger: '.layer-stack', start: 'top 82%' } });
      }

      ['capabilities', 'runtime', 'integrate', 'control', 'start'].forEach(id => {
        ScrollTrigger.create({ trigger: `#${id}`, start: 'top 45%', end: 'bottom 45%', onToggle: self => self.isActive && setActiveSection(id) });
      });
    }, root);

    return () => { context.revert(); if (lenis) { gsap.ticker.remove(tick); lenis.destroy(); } };
  }, []);

  return (
    <div ref={root}>
      <a className="skip-link" href="#main">Skip to content</a><div className="noise" aria-hidden="true" /><div className="scroll-progress" aria-hidden="true"><span /></div>
      <Header activeSection={activeSection} />
      <main id="main"><Hero /><Capabilities /><RouteLab /><IntegrationPanel /><ControlSection /><Architecture /><StartSection /></main>
      <Footer />
    </div>
  );
}
