import { resolveTarget } from './route-map';

describe('resolveTarget', () => {
  const originalEnv = process.env;
  beforeEach(() => {
    process.env = { ...originalEnv, SERVICE_URL_USER_MANAGEMENT: 'http://localhost:3002' };
  });
  afterEach(() => { process.env = originalEnv; });

  it('maps a known service prefix to its base url and strips the prefix', () => {
    const target = resolveTarget('/api/user-management/profiles/123');
    expect(target).toEqual({ baseUrl: 'http://localhost:3002', forwardPath: '/profiles/123' });
  });

  it('returns null for an unrecognized prefix', () => {
    expect(resolveTarget('/api/does-not-exist/foo')).toBeNull();
  });

  it('returns null when the env var for a known slug is not set', () => {
    delete process.env.SERVICE_URL_USER_MANAGEMENT;
    expect(resolveTarget('/api/user-management/profiles')).toBeNull();
  });
});
