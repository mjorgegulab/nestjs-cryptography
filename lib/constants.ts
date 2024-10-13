import { Argon2Type } from './interfaces';

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
