export enum Argon2Type {
  argon2d = 0,
  argon2i = 1,
  argon2id = 2,
}

export interface CryptographyKdfOptions {
  outputKeyLength: number;
  argon2Type: Argon2Type;
  memoryCost: number;
  timeCost: number;
}

export interface CryptographyHashingOptions {
  password: {
    outputKeyLength: number;
    argon2Type: Argon2Type;
    memoryCost: number;
    timeCost: number;
  };
  hmac: {
    masterKey: string;
  };
}

export interface CryptographyEncryptionOptions {
  symmetric: {
    masterKey: string;
  };
}

export interface CryptographyOptionsInterface {
  isGlobal?: boolean;
  useDefaultValues?: boolean;
  kdf?: Partial<CryptographyKdfOptions>;
  hashing?: Partial<CryptographyHashingOptions>;
  encryption?: Partial<CryptographyEncryptionOptions>;
}
