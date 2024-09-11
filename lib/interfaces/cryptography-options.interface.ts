export enum Argon2Type {
  argon2d = 0,
  argon2i = 1,
  argon2id = 2,
}

export interface CryptographyOptionsInterface {
  kdf: {
    defaultOutputKeyLength: number;
    argon2Type: Argon2Type;
    memoryCost: number;
    timeCost: number;
  };
  hashing: {
    password: {
      outputKeyLength: number;
      argon2Type: Argon2Type;
      memoryCost: number;
      timeCost: number;
    };
    hmac: {
      masterKey: string;
    };
  };
  encryption: {
    symmetric: {
      masterKey: string;
    };
  };
}
