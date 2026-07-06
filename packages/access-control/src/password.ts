import bcrypt from 'bcrypt';
import { createHash } from 'crypto';

const SALT_ROUNDS = 10;

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

export function hashSecret(plain: string): string {
  return createHash('sha256').update(plain).digest('hex');
}
