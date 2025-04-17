import { Argon2Type } from './interfaces';
import { MODULE_OPTIONS_TOKEN } from './cryptography.module-definition';

export const CRYPTOGRAPHY_OPTIONS = 'CRYPTOGRAPHY_OPTIONS';

export const DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS = {
  outputKeyLength: 32,
  argon2Type: Argon2Type.argon2i,
  memoryCost: 65536,
  timeCost: 3,
};

export const DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS = {
  password: {
    outputKeyLength: 64,
    argon2Type: Argon2Type.argon2id,
    memoryCost: 131072,
    timeCost: 4,
  },
};

export const NEST_CRYPTOGRAPHY_MODULE_OPTIONS = MODULE_OPTIONS_TOKEN;
