export interface RouteTarget {
  baseUrl: string;
  forwardPath: string;
}

const SERVICE_SLUGS = [
  'access-control',
  'user-management',
  'expense-management',
  'payroll',
  'reporting',
  'workflow',
  'notification',
  'invoice-management',
] as const;

function envVarFor(slug: string): string {
  return `SERVICE_URL_${slug.toUpperCase().replace(/-/g, '_')}`;
}

export function resolveTarget(path: string): RouteTarget | null {
  const match = path.match(/^\/api\/([a-z-]+)(\/.*)?$/);
  if (!match) return null;
  const slug = match[1];
  if (!SERVICE_SLUGS.includes(slug as (typeof SERVICE_SLUGS)[number])) return null;
  const baseUrl = process.env[envVarFor(slug)];
  if (!baseUrl) return null;
  return { baseUrl, forwardPath: match[2] ?? '/' };
}
