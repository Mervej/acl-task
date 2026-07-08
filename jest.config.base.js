module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.test.ts'],
  // Several services construct a module-level AuditEventEmitter backed by a
  // real ioredis connection at import time (see auth.service.ts and
  // siblings) — unit tests never use it, but the open TCP socket keeps
  // Jest's worker process alive after tests finish. Force-exiting is the
  // standard, minimal fix rather than adding teardown to every test file.
  forceExit: true,
};
