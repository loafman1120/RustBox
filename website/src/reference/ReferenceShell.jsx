import { useState } from 'react';

const REPO = 'https://github.com/loafman1120/RustBox';

function Brand({ footer = false }) {
  return (
    <a className="brand" href="../" aria-label="RustBox home">
      <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
      <span>RUSTBOX</span>
      {!footer && <small>NETWORK ENGINE</small>}
    </a>
  );
}

function ReferenceHeader({ active }) {
  const [open, setOpen] = useState(false);
  const links = [
    ['home', '../', 'Overview'],
    ['config', '../config/', 'Config reference'],
    ['api', '../api/', 'API reference'],
  ];

  return (
    <header className="site-header reference-site-header">
      <Brand />
      <nav className={open ? 'is-open' : ''} aria-label="Reference navigation">
        {links.map(([id, href, label]) => (
          <a
            key={id}
            className={active === id ? 'is-active' : ''}
            href={href}
            onClick={() => setOpen(false)}
          >
            {label}
          </a>
        ))}
      </nav>
      <div className="header-actions">
        <span className="reference-state"><i /> GENERATED FROM SOURCE</span>
        <a className="source-link" href={REPO}>GitHub <span>↗</span></a>
        <button
          className={`menu-toggle ${open ? 'is-open' : ''}`}
          type="button"
          aria-label={`${open ? 'Close' : 'Open'} navigation`}
          aria-expanded={open}
          onClick={() => setOpen(value => !value)}
        >
          <i /><i />
        </button>
      </div>
    </header>
  );
}

function ReferenceFooter() {
  return (
    <footer>
      <div>
        <Brand footer />
        <p>Reference documentation generated from the RustBox source contracts.</p>
      </div>
      <div className="footer-links">
        <a href="../config/">Configuration ↗</a>
        <a href="../api/">Control API ↗</a>
        <a href={REPO}>GitHub ↗</a>
      </div>
      <div className="footer-meta">
        <span>RUSTBOX REFERENCE</span>
        <span>SCHEMA VERSION 1</span>
      </div>
    </footer>
  );
}

export default function ReferenceShell({ active, children }) {
  return (
    <div className="reference-page">
      <a className="skip-link" href="#reference-main">Skip to reference</a>
      <div className="noise" aria-hidden="true" />
      <ReferenceHeader active={active} />
      <main id="reference-main">{children}</main>
      <ReferenceFooter />
    </div>
  );
}
