import { All, Controller, HttpException, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { verifyAccessToken, InvalidTokenError } from '@platform/auth-kit';
import { resolveTarget } from './route-map';

@Controller('api')
export class ProxyController {
  @All('*')
  async proxy(@Req() req: Request, @Res() res: Response) {
    const authHeader = req.headers['authorization'];
    if (!authHeader?.startsWith('Bearer ')) {
      throw new HttpException('Missing bearer token', 401);
    }
    try {
      verifyAccessToken(authHeader.slice('Bearer '.length), process.env.JWT_SECRET ?? 'dev-secret-change-me');
    } catch (err) {
      if (err instanceof InvalidTokenError) throw new HttpException(err.message, 401);
      throw err;
    }

    const target = resolveTarget(req.originalUrl);
    if (!target) throw new HttpException('Unknown route', 404);

    const upstream = await fetch(`${target.baseUrl}${target.forwardPath}`, {
      method: req.method,
      headers: { 'content-type': 'application/json', authorization: authHeader },
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body),
    });
    const body = await upstream.json().catch(() => ({}));
    res.status(upstream.status).json(body);
  }
}
