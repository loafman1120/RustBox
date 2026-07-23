import { ApiReferenceReact } from '@scalar/api-reference-react';
import '@scalar/api-reference-react/style.css';
import openapi from '../data/rustbox-openapi.json';
import ReferenceShell from './ReferenceShell.jsx';

const endpointCount = Object.values(openapi.paths || {})
  .reduce((count, path) => count + Object.keys(path)
    .filter(method => ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(method))
    .length, 0);

export default function ApiReference() {
  return (
    <ReferenceShell active="api">
      <section className="reference-hero api-reference-hero">
        <div className="section-shell reference-hero-grid">
          <div>
            <p className="eyebrow"><span>02</span> LOCAL CONTROL PLANE</p>
            <h1>Control API.<br /><em>Fully mapped.</em></h1>
            <p className="reference-lede">
              A searchable reference for the Clash/Mihomo-compatible HTTP API.
              Inspect requests, responses, authentication, and streaming endpoints.
            </p>
          </div>
          <div className="reference-status-panel">
            <div><span>OPENAPI</span><strong>{openapi.openapi}</strong></div>
            <div><span>OPERATIONS</span><strong>{endpointCount}</strong></div>
            <p><i /> Generated from Rust handlers and shared control types</p>
          </div>
        </div>
      </section>
      <section className="scalar-reference-wrap" aria-label="RustBox OpenAPI reference">
        <ApiReferenceReact
          configuration={{
            content: openapi,
            theme: 'none',
            layout: 'modern',
            hideClientButton: true,
            showDeveloperTools: 'never',
            operationTitleSource: 'summary',
            telemetry: false,
            withDefaultFonts: false,
            modelsSectionLabel: 'Schemas',
          }}
        />
      </section>
    </ReferenceShell>
  );
}
