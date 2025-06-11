import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class RawBodyMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    if (req.headers['content-type']?.includes('application/json') || 
        req.headers['content-type']?.includes('application/x-www-form-urlencoded')) {
      let data = '';
      req.on('data', (chunk) => {
        data += chunk;
      });
      req.on('end', () => {
        (req as any).rawBody = Buffer.from(data);
        next();
      });
    } else {
      next();
    }
  }
}