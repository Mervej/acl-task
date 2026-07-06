import { hashPassword, verifyPassword, hashSecret } from './password';

describe('password utilities', () => {
  it('hashes and verifies a matching password', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');
    expect(await verifyPassword('correct-horse-battery-staple', hash)).toBe(true);
  });

  it('rejects a non-matching password', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');
    expect(await verifyPassword('wrong-password', hash)).toBe(false);
  });

  it('produces a deterministic sha256 hash for secrets', () => {
    expect(hashSecret('my-api-key')).toBe(hashSecret('my-api-key'));
    expect(hashSecret('my-api-key')).not.toBe(hashSecret('other-key'));
  });
});
