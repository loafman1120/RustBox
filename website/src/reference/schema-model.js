const SECTION_LABELS = {
  schema_version: 'General',
  observability: 'Observability',
  inbounds: 'Inbounds',
  outbounds: 'Outbounds',
  endpoints: 'Endpoints',
  dns: 'DNS',
  rule_sets: 'Rule sets',
  routes: 'Routes',
};

const SECTION_ORDER = Object.keys(SECTION_LABELS);

function titleCase(value) {
  return value
    .replace(/^Toml/, '')
    .replace(/Config$/, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
}

function resolveRef(schema, ref) {
  if (!ref?.startsWith('#/')) return null;
  return ref
    .slice(2)
    .split('/')
    .map(segment => segment.replace(/~1/g, '/').replace(/~0/g, '~'))
    .reduce((value, segment) => value?.[segment], schema);
}

function dereference(schema, node) {
  if (!node?.$ref) return node || {};
  const resolved = resolveRef(schema, node.$ref);
  return resolved ? { ...resolved, ...node, $ref: undefined } : node;
}

function nonNullBranches(node) {
  return node?.anyOf?.filter(branch => branch.type !== 'null') || [];
}

function normalizedNode(schema, input) {
  let node = dereference(schema, input);
  const branches = nonNullBranches(node);
  if (branches.length === 1) {
    node = { ...dereference(schema, branches[0]), ...node };
    delete node.anyOf;
  }
  return node;
}

function variantName(schema, input, index) {
  const node = normalizedNode(schema, input);
  const discriminator = node.properties?.type;
  if (discriminator?.const !== undefined) return String(discriminator.const);
  if (node.title) return node.title;
  if (input?.$ref) return titleCase(input.$ref.split('/').at(-1));
  return `Variant ${index + 1}`;
}

function valueType(schema, input) {
  const node = normalizedNode(schema, input);
  if (node.const !== undefined) return typeof node.const;
  if (node.type === 'array') return `${valueType(schema, node.items)}[]`;
  if (Array.isArray(node.type)) return node.type.join(' | ');
  if (node.type) return node.type;
  if (node.properties) return 'object';
  if (node.oneOf || nonNullBranches(node).length > 1) return 'variant';
  if (node.enum?.length) return typeof node.enum[0];
  return 'value';
}

function fieldValue(node, key) {
  if (node[key] === undefined) return undefined;
  return node[key];
}

function walkNode(schema, input, path, state, context = {}) {
  const depth = context.depth || 0;
  if (depth > 7) return;
  const node = normalizedNode(schema, input);
  const branches = node.oneOf || (nonNullBranches(node).length > 1 ? nonNullBranches(node) : null);

  if (branches) {
    branches.forEach((branch, index) => {
      const name = variantName(schema, branch, index);
      walkNode(schema, branch, path, state, {
        ...context,
        depth: depth + 1,
        variant: context.variant ? `${context.variant} · ${name}` : name,
      });
    });
    return;
  }

  if (node.type === 'array' || node.items) {
    walkNode(schema, node.items, `${path}[]`, state, { ...context, depth: depth + 1 });
    return;
  }

  const properties = node.properties;
  if (!properties) return;
  const required = new Set(node.required || []);

  Object.entries(properties).forEach(([name, source]) => {
    const property = normalizedNode(schema, source);
    const propertyPath = path ? `${path}.${name}` : name;
    const nullable = source?.anyOf?.some(branch => branch.type === 'null') || false;
    const record = {
      id: `${propertyPath}:${context.variant || 'base'}`,
      path: propertyPath,
      name,
      description: property.description || 'No description is available for this field yet.',
      type: valueType(schema, source),
      required: required.has(name),
      nullable,
      defaultValue: fieldValue(property, 'default'),
      constant: fieldValue(property, 'const'),
      choices: property.enum || null,
      minimum: fieldValue(property, 'minimum'),
      maximum: fieldValue(property, 'maximum'),
      variant: context.variant || '',
    };

    state.push(record);
    walkNode(schema, source, propertyPath, state, { ...context, depth: depth + 1 });
  });
}

export function buildSchemaReference(schema) {
  const rootRequired = new Set(schema.required || []);
  return SECTION_ORDER
    .filter(key => schema.properties?.[key])
    .map((key, index) => {
      const source = schema.properties[key];
      const node = normalizedNode(schema, source);
      const fields = [];
      walkNode(schema, source, key, fields);
      const rootField = {
        id: `${key}:base`,
        path: key,
        name: key,
        description: node.description || source.description || 'Configuration section.',
        type: valueType(schema, source),
        required: rootRequired.has(key),
        nullable: source?.anyOf?.some(branch => branch.type === 'null') || false,
        defaultValue: fieldValue(node, 'default'),
        constant: fieldValue(node, 'const'),
        choices: node.enum || null,
        minimum: fieldValue(node, 'minimum'),
        maximum: fieldValue(node, 'maximum'),
        variant: '',
      };

      const uniqueFields = Array.from(
        new Map([rootField, ...fields].map(field => [field.id, field])).values(),
      );
      const variants = Array.from(
        new Set(uniqueFields.map(field => field.variant).filter(Boolean)),
      );

      return {
        id: key,
        index: String(index + 1).padStart(2, '0'),
        label: SECTION_LABELS[key] || titleCase(key),
        description: node.description || source.description || '',
        rootType: valueType(schema, source),
        fields: uniqueFields,
        variants,
      };
    });
}

export function schemaStats(schema, sections) {
  return {
    sections: sections.length,
    fields: new Set(sections.flatMap(section => section.fields.map(field => field.path))).size,
    definitions: Object.keys(schema.$defs || {}).length,
  };
}

export function formatValue(value) {
  if (typeof value === 'string') return `"${value}"`;
  return JSON.stringify(value);
}
