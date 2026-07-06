import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

describe('UsersController (validation)', () => {
  let app: INestApplication;
  let baseUrl: string;
  const fakeUsersService = {
    verifyServiceApiKey: jest.fn().mockResolvedValue(true),
    createUser: jest.fn().mockResolvedValue({ id: 'user-1', email: 'alice@example.com' }),
    getUser: jest.fn(),
  };

  async function postUser(body: unknown): Promise<Response> {
    return fetch(`${baseUrl}/internal/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-service-api-key': 'some-key' },
      body: JSON.stringify(body),
    });
  }

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [{ provide: UsersService, useValue: fakeUsersService }],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
    await app.listen(0);
    const address = app.getHttpServer().address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    fakeUsersService.createUser.mockClear();
  });

  it('rejects a request with a malformed email with 400', async () => {
    const res = await postUser({
      tenantId: '123e4567-e89b-12d3-a456-426614174000',
      email: 'not-an-email',
      password: 'longenoughpw',
    });

    expect(res.status).toBe(400);
    expect(fakeUsersService.createUser).not.toHaveBeenCalled();
  });

  it('rejects a request with a password under 8 characters with 400', async () => {
    const res = await postUser({
      tenantId: '123e4567-e89b-12d3-a456-426614174000',
      email: 'alice@example.com',
      password: 'short',
    });

    expect(res.status).toBe(400);
    expect(fakeUsersService.createUser).not.toHaveBeenCalled();
  });

  it('rejects a request with a non-UUID tenantId with 400', async () => {
    const res = await postUser({
      tenantId: 'not-a-uuid',
      email: 'alice@example.com',
      password: 'longenoughpw',
    });

    expect(res.status).toBe(400);
    expect(fakeUsersService.createUser).not.toHaveBeenCalled();
  });

  it('accepts a valid request and reaches the service', async () => {
    const res = await postUser({
      tenantId: '123e4567-e89b-12d3-a456-426614174000',
      email: 'alice@example.com',
      password: 'longenoughpw',
    });

    expect(res.status).toBe(201);
    expect(fakeUsersService.createUser).toHaveBeenCalledWith(
      '123e4567-e89b-12d3-a456-426614174000',
      'alice@example.com',
      'longenoughpw',
    );
  });
});
