import { UseGuards } from '@nestjs/common';
import { SignatureGuard } from '../guards/signature.guard';

export const ValidateSignature = () => UseGuards(SignatureGuard);
