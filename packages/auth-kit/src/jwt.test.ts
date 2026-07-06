import { signAccessToken, verifyAccessToken, InvalidTokenError } from './jwt';

describe('jwt', () => {
  const secret = 'test-secret';
  const payload = {
    sub: 'user-1',
    tenantId: 'tenant-1',
    roles: ['manager'],
    permissions: ['expense:approve'],
    orgUnitId: 'org-1',
  };

  it('signs and verifies a valid token', () => {
    const token = signAccessToken(payload, secret, 900);
    const claims = verifyAccessToken(token, secret);
    expect(claims.sub).toBe('user-1');
    expect(claims.tenantId).toBe('tenant-1');
    expect(claims.permissions).toEqual(['expense:approve']);
  });

  it('throws InvalidTokenError for an expired token', () => {
    const token = signAccessToken(payload, secret, -1);
    expect(() => verifyAccessToken(token, secret)).toThrow(InvalidTokenError);
  });

  it('throws InvalidTokenError for a token signed with a different secret', () => {
    const token = signAccessToken(payload, secret, 900);
    expect(() => verifyAccessToken(token, 'wrong-secret')).toThrow(InvalidTokenError);
  });
});
