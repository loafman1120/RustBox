import { useMemo, useState } from 'react';
import configSchema from '../../../crates/rustbox-config-file/schema/rustbox-config-v1.schema.json';
import ReferenceShell from './ReferenceShell.jsx';
import { buildSchemaReference, formatValue, schemaStats } from './schema-model.js';

function FieldMeta({ field }) {
  return (
    <div className="field-meta">
      <span className="type-chip">{field.type}</span>
      {field.required && <span className="required-chip">required</span>}
      {field.nullable && <span>nullable</span>}
      {field.defaultValue !== undefined && <span>default {formatValue(field.defaultValue)}</span>}
      {field.constant !== undefined && <span>constant {formatValue(field.constant)}</span>}
    </div>
  );
}

function FieldCard({ field, copied, onCopy }) {
  return (
    <article className="field-card" id={`field-${field.id.replace(/[^a-zA-Z0-9_-]/g, '-')}`}>
      <div className="field-heading">
        <div>
          <code>{field.path}</code>
          <FieldMeta field={field} />
        </div>
        <button type="button" onClick={() => onCopy(field.path)}>
          {copied === field.path ? 'Copied' : 'Copy path'}
        </button>
      </div>
      <p>{field.description}</p>
      {(field.choices || field.minimum !== undefined || field.maximum !== undefined) && (
        <div className="field-constraints">
          {field.choices && (
            <div>
              <span>Accepted values</span>
              <div>{field.choices.map(choice => <code key={String(choice)}>{formatValue(choice)}</code>)}</div>
            </div>
          )}
          {(field.minimum !== undefined || field.maximum !== undefined) && (
            <div>
              <span>Range</span>
              <p>
                {field.minimum !== undefined ? `≥ ${field.minimum}` : ''}
                {field.minimum !== undefined && field.maximum !== undefined ? ' · ' : ''}
                {field.maximum !== undefined ? `≤ ${field.maximum}` : ''}
              </p>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function Section({ section, query, copied, onCopy }) {
  const normalizedQuery = query.trim().toLowerCase();
  const visibleFields = normalizedQuery
    ? section.fields.filter(field => (
      field.path.toLowerCase().includes(normalizedQuery)
      || field.description.toLowerCase().includes(normalizedQuery)
      || field.variant.toLowerCase().includes(normalizedQuery)
      || field.choices?.some(choice => String(choice).toLowerCase().includes(normalizedQuery))
    ))
    : section.fields;

  if (normalizedQuery && visibleFields.length === 0) return null;

  const groups = new Map();
  visibleFields.forEach(field => {
    const group = field.variant || 'Shared fields';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(field);
  });

  return (
    <section className="reference-section" id={section.id}>
      <header className="reference-section-heading">
        <span>{section.index}</span>
        <div>
          <p>{section.rootType} · {visibleFields.length} fields</p>
          <h2>{section.label}</h2>
          <div>{section.description}</div>
        </div>
      </header>

      {Array.from(groups.entries()).map(([group, fields]) => (
        <details
          className="field-group"
          key={group}
          open={Boolean(query.trim()) || group === 'Shared fields'}
        >
          <summary className="field-group-heading">
            <div>
              <span>{group === 'Shared fields' ? 'Common' : 'Variant'}</span>
              <h3>{group}</h3>
              <small>{fields.length} fields</small>
            </div>
            <i aria-hidden="true" />
          </summary>
          <div className="field-list">
            {fields.map(field => (
              <FieldCard
                key={field.id}
                field={field}
                copied={copied}
                onCopy={onCopy}
              />
            ))}
          </div>
        </details>
      ))}
    </section>
  );
}

export default function ConfigReference() {
  const sections = useMemo(() => buildSchemaReference(configSchema), []);
  const stats = useMemo(() => schemaStats(configSchema, sections), [sections]);
  const [query, setQuery] = useState('');
  const [copied, setCopied] = useState('');

  const matchingSections = sections.filter(section => {
    if (!query.trim()) return true;
    const normalizedQuery = query.trim().toLowerCase();
    return section.fields.some(field => (
      field.path.toLowerCase().includes(normalizedQuery)
      || field.description.toLowerCase().includes(normalizedQuery)
      || field.variant.toLowerCase().includes(normalizedQuery)
      || field.choices?.some(choice => String(choice).toLowerCase().includes(normalizedQuery))
    ));
  });

  const copyPath = async path => {
    await navigator.clipboard.writeText(path);
    setCopied(path);
    window.setTimeout(() => setCopied(''), 1300);
  };

  return (
    <ReferenceShell active="config">
      <section className="reference-hero config-reference-hero">
        <div className="section-shell reference-hero-grid">
          <div>
            <p className="eyebrow"><span>01</span> NATIVE CONFIGURATION</p>
            <h1>Every field.<br /><em>In plain sight.</em></h1>
            <p className="reference-lede">
              A concise reference for RustBox TOML and JSON configuration.
              Search by field name, protocol, or behavior.
            </p>
          </div>
          <div className="reference-status-panel">
            <div><span>SCHEMA</span><strong>VERSION 1</strong></div>
            <div><span>SECTIONS</span><strong>{stats.sections}</strong></div>
            <div><span>FIELDS</span><strong>{stats.fields}</strong></div>
            <div><span>MODELS</span><strong>{stats.definitions}</strong></div>
            <p><i /> Generated from the native Rust configuration contract</p>
          </div>
        </div>
      </section>

      <div className="reference-toolbar">
        <div className="section-shell reference-toolbar-inner">
          <label>
            <span>SEARCH CONFIGURATION</span>
            <input
              type="search"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="dns, listen, outbound, wireguard…"
            />
          </label>
          <div>
            <span>{query ? `${matchingSections.length} matching sections` : 'TOML + JSON'}</span>
            <a href="../schema/rustbox-config-v1.schema.json">Raw schema ↓</a>
          </div>
        </div>
      </div>

      <div className="reference-content">
        <div className="section-shell reference-layout">
          <aside className="reference-sidebar">
            <p>CONFIGURATION</p>
            <nav aria-label="Configuration sections">
              {sections.map(section => (
                <a
                  key={section.id}
                  className={matchingSections.includes(section) ? '' : 'is-muted'}
                  href={`#${section.id}`}
                >
                  <span>{section.index}</span>
                  <strong>{section.label}</strong>
                  <small>{section.fields.length}</small>
                </a>
              ))}
            </nav>
            <div>
              <span>CONTRACT</span>
              <p>Descriptions and defaults are kept in sync with the versioned source schema.</p>
            </div>
          </aside>

          <div className="reference-sections">
            {matchingSections.length > 0 ? sections.map(section => (
              <Section
                key={section.id}
                section={section}
                query={query}
                copied={copied}
                onCopy={copyPath}
              />
            )) : (
              <div className="empty-reference">
                <span>NO MATCH</span>
                <h2>Nothing found for “{query}”.</h2>
                <button type="button" onClick={() => setQuery('')}>Clear search</button>
              </div>
            )}
          </div>
        </div>
      </div>
    </ReferenceShell>
  );
}
