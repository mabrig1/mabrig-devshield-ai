import fs from 'node:fs';
import path from 'node:path';

const METHODS = ['get','post','put','patch','delete','options','head'];

function slug(value) {
  return String(value || 'route')
    .replace(/\{([^}]+)\}/g, '$1')
    .replace(/[^A-Za-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .slice(0, 100) || 'route';
}

function dereferenceLocal(spec, value, seen = new Set()) {
  if (!value || typeof value !== 'object' || !value.$ref) return value;
  const ref = String(value.$ref);
  if (!ref.startsWith('#/')) return value;
  if (seen.has(ref)) return value;
  seen.add(ref);

  const parts = ref.slice(2).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  let current = spec;
  for (const part of parts) {
    if (!current || typeof current !== 'object' || !(part in current)) return value;
    current = current[part];
  }
  return dereferenceLocal(spec, current, seen);
}

function schemaField(spec, raw) {
  const schema = dereferenceLocal(spec, raw) || {};
  const out = {};

  if (['string','number','integer','boolean','array','object'].includes(schema.type)) out.type = schema.type;
  if (Number.isFinite(Number(schema.maxLength))) out.maxLength = Number(schema.maxLength);
  if (Number.isFinite(Number(schema.minimum))) out.min = Number(schema.minimum);
  if (Number.isFinite(Number(schema.maximum))) out.max = Number(schema.maximum);
  if (Array.isArray(schema.enum)) out.enum = schema.enum.slice(0, 100);

  return out;
}

function requestSchema(spec, operation) {
  const requestBody = dereferenceLocal(spec, operation?.requestBody);
  const json = requestBody?.content?.['application/json'];
  if (!json?.schema) return null;

  const schema = dereferenceLocal(spec, json.schema) || {};
  if (schema.type && schema.type !== 'object') return null;

  const properties = schema.properties && typeof schema.properties === 'object'
    ? schema.properties
    : {};
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  const fields = {};

  for (const [name, raw] of Object.entries(properties)) {
    fields[name] = {
      ...schemaField(spec, raw),
      required: required.has(name)
    };
  }

  return {
    requiredFields: [...required],
    allowedFields: Object.keys(properties),
    rejectUnknownFields: schema.additionalProperties === false,
    maxFields: Math.max(1, Object.keys(properties).length || 100),
    fields
  };
}

function requiredHeaders(spec, pathItem, operation) {
  const params = [
    ...(Array.isArray(pathItem?.parameters) ? pathItem.parameters : []),
    ...(Array.isArray(operation?.parameters) ? operation.parameters : [])
  ];

  return params
    .map(param => dereferenceLocal(spec, param))
    .filter(param => param?.in === 'header' && param.required === true && param.name)
    .map(param => String(param.name).toLowerCase());
}

function contentTypes(operation) {
  const body = operation?.requestBody;
  if (!body?.content || typeof body.content !== 'object') return [];
  return Object.keys(body.content).map(value => String(value).toLowerCase());
}

function operationRequiresAuth(rootSecurity, operation) {
  if (Array.isArray(operation?.security)) return operation.security.length > 0;
  return Array.isArray(rootSecurity) && rootSecurity.length > 0;
}

function extensionObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export function openApiToWaapRoutes(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('OpenAPI document must be an object');
  if (!String(spec.openapi || '').startsWith('3.')) {
    throw new Error('Only OpenAPI 3.x JSON documents are supported');
  }
  if (!spec.paths || typeof spec.paths !== 'object') {
    throw new Error('OpenAPI document has no paths object');
  }

  const routes = [];

  for (const [pathTemplate, rawPathItem] of Object.entries(spec.paths)) {
    const pathItem = dereferenceLocal(spec, rawPathItem) || {};

    for (const method of METHODS) {
      const operation = pathItem[method];
      if (!operation || typeof operation !== 'object') continue;

      const operationId = operation.operationId || method + '-' + pathTemplate;
      const schema = requestSchema(spec, operation);
      const headers = requiredHeaders(spec, pathItem, operation);
      const route = {
        id: slug(operationId),
        pathPrefix: pathTemplate.includes('{')
          ? pathTemplate.slice(0, pathTemplate.indexOf('{')).replace(/\/+$/,'') || '/'
          : pathTemplate,
        pathTemplate,
        methods: [method.toUpperCase()],
        requireAuth: operationRequiresAuth(spec.security, operation)
      };

      const types = contentTypes(operation);
      if (types.length) route.requestContentTypes = types;
      if (headers.length) route.requiredHeaders = headers;
      if (headers.includes('x-api-version')) route.apiVersionRequired = true;
      if (schema) route.requestSchema = schema;

      const bodyLimit = Number(operation['x-devshield-max-body-bytes']);
      if (Number.isFinite(bodyLimit) && bodyLimit >= 0) route.maxBodyBytes = bodyLimit;

      const rate = extensionObject(operation['x-devshield-rate-limit']);
      if (rate) route.rateLimit = rate;

      const authAbuse = extensionObject(operation['x-devshield-auth-abuse']);
      if (authAbuse) route.authAbuse = authAbuse;

      const responseInspection = extensionObject(operation['x-devshield-response-inspection']);
      if (responseInspection) route.responseInspection = responseInspection;

      routes.push(route);
    }
  }

  routes.sort((a, b) => {
    const pathCmp = String(a.pathTemplate).localeCompare(String(b.pathTemplate));
    if (pathCmp !== 0) return pathCmp;
    return a.methods[0].localeCompare(b.methods[0]);
  });

  return routes;
}

export function openApiToWaapPolicy(spec, base = {}) {
  const basePolicy = base && typeof base === 'object' ? structuredClone(base) : {};
  const routes = openApiToWaapRoutes(spec);

  return {
    mode: basePolicy.mode || 'observe',
    blockScore: basePolicy.blockScore ?? 70,
    inspectBodyBytes: basePolicy.inspectBodyBytes ?? 65536,
    maxBodyBytes: basePolicy.maxBodyBytes ?? 1048576,
    allowedOrigins: Array.isArray(basePolicy.allowedOrigins) ? basePolicy.allowedOrigins : [],
    trustedBots: Array.isArray(basePolicy.trustedBots) ? basePolicy.trustedBots : [],
    blockedCountries: Array.isArray(basePolicy.blockedCountries) ? basePolicy.blockedCountries : [],
    rateLimit: basePolicy.rateLimit || {
      enabled: true,
      requests: 120,
      windowSeconds: 60,
      key: 'ip'
    },
    waap: basePolicy.waap || {
      apiDiscovery: {
        enabled: true,
        apiPrefixes: ['/api/','/graphql'],
        unknownAction: 'observe',
        excludePrefixes: []
      },
      parameterPollution: {
        enabled: true,
        action: 'observe',
        allowDuplicateKeys: []
      }
    },
    routes
  };
}

export function readOpenApiJson(file) {
  const abs = path.resolve(file);
  const text = fs.readFileSync(abs, 'utf8');
  let spec;
  try {
    spec = JSON.parse(text);
  } catch {
    throw new Error('OpenAPI input must be valid JSON');
  }
  return spec;
}
