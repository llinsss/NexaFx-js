import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
    Logger,
  } from '@nestjs/common';
  import { ConfigService } from '@nestjs/config';
  import { Request } from 'express';
  import * as crypto from 'crypto';
  
  @Injectable()
  export class SignatureGuard implements CanActivate {
    private readonly logger = new Logger(SignatureGuard.name);
  
    constructor(private configService: ConfigService) {}
  
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const request = context.switchToHttp().getRequest<Request>();
      
      const signature = this.extractSignature(request);
      const rawBody = this.getRawBody(request);
      
      if (!signature) {
        this.logger.warn('Missing signature header');
        throw new UnauthorizedException('Missing signature header');
      }
  
      if (!rawBody) {
        this.logger.warn('Missing request body');
        throw new UnauthorizedException('Missing request body');
      }
  
      const isValid = this.validateSignature(signature, rawBody);
      
      if (!isValid) {
        this.logger.warn('Invalid signature');
        throw new UnauthorizedException('Invalid signature');
      }
  
      this.logger.debug('Signature validation successful');
      return true;
    }
  
    private extractSignature(request: Request): string | null {
      const signatureHeader = 
        request.headers['x-signature'] ||
        request.headers['x-hub-signature-256'] ||
        request.headers['x-webhook-signature'];
  
      if (!signatureHeader) {
        return null;
      }
  
      const signature = Array.isArray(signatureHeader) 
        ? signatureHeader[0] 
        : signatureHeader;
  
      return signature.replace(/^sha256=/, '');
    }
  
    private getRawBody(request: Request): Buffer | null {
      return (request as any).rawBody || null;
    }
  
    private validateSignature(signature: string, body: Buffer): boolean {
      const secret = this.configService.get<string>('WEBHOOK_SECRET');
      
      if (!secret) {
        this.logger.error('WEBHOOK_SECRET not configured');
        return false;
      }
  
      try {
        const expectedSignature = crypto
          .createHmac('sha256', secret)
          .update(body)
          .digest('hex');
  
        // Use timing-safe comparison to prevent timing attacks

        return crypto.timingSafeEqual(
          Buffer.from(signature, 'hex'),
          Buffer.from(expectedSignature, 'hex')
        );
      } catch (error) {
        this.logger.error('Error validating signature:', error);
        return false;
      }
    }
  }