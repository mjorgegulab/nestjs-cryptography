import { Module } from '@nestjs/common';
import { ConfigurableModuleClass } from './cryptography.module-definition';
import { CryptographyService } from './cryptography.service';

@Module({
  providers: [CryptographyService],
  exports: [CryptographyService],
})
export class CryptographyModule extends ConfigurableModuleClass {}
