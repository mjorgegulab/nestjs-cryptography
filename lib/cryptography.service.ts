import * as crypto from 'node:crypto';
import * as argon2 from 'argon2';
import { Inject, Injectable } from '@nestjs/common';
import { MODULE_OPTIONS_TOKEN } from './cryptography.module-definition';
import {
  CryptographyOptionsInterface,
  GenericOptionsInterface,
} from './interfaces';
import {
  DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS,
  DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS,
} from './constants';

@Injectable()
export class CryptographyService {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN)
    private moduleOptions: CryptographyOptionsInterface,
  ) {}

  private convertInputData(
    data: string | Buffer,
    inputEncoding?: BufferEncoding,
  ) {
    if (Buffer.isBuffer(data)) {
      return data;
    } else if (typeof data === 'string') {
      return Buffer.from(data, inputEncoding ?? 'utf8');
    } else {
      throw new Error('Unsupported input type');
    }
  }

  private checkModuleOptions(
    parent: string,
    options: { [key: string]: any },
  ): void {
    for (const option in options) {
      if (typeof option === 'object') this.checkModuleOptions(parent, option);
      if (options[option] === undefined || options[option] === null) {
        throw new Error(
          `[CryptographyModule] [${parent}] Option ${option} is not defined on the configuration`,
        );
      }
    }
  }

  private extractIV(data: Buffer): Buffer {
    return data.subarray(0, 12);
  }

  private extractAuthTagFromCypheredData(data: Buffer): Buffer {
    return data.subarray(76, 92);
  }

  private extractCipheredData(data: Buffer): Buffer {
    return data.subarray(92, data.length);
  }

  private extractSalt(data: Buffer): Buffer {
    return data.subarray(12, 76);
  }

  private extractSaltFromHmac(data: Buffer): Buffer {
    return data.subarray(0, 16);
  }

  private extractCipheredDEK(data: Buffer): Buffer {
    return data.subarray(0, 124);
  }

  private extractCipheredDataWithDEK(data: Buffer): Buffer {
    return data.subarray(124, data.length);
  }

  private createHmacSecureKey(key: Buffer, salt: Buffer): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        'sha3-256',
        crypto.createSecretKey(key),
        salt,
        Buffer.alloc(0),
        64,
      ),
    );
  }

  public createSafeRandomData(length: number): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        'sha3-256',
        crypto.createSecretKey(crypto.randomBytes(64)),
        crypto.randomBytes(64),
        Buffer.alloc(0),
        length,
      ),
    );
  }

  public genUUID(secure = false): string {
    return crypto.randomUUID({
      disableEntropyCache: secure,
    });
  }

  public genRandomPassword(length: number): string {
    return crypto.randomBytes(length).toString('base64').slice(0, length);
  }

  public generateSymmetricKey(length: number = 256): crypto.KeyObject {
    return crypto.generateKeySync('hmac', { length });
  }

  public async deriveMasterKey(
    masterKey: string | Buffer,
    salt: Buffer,
    length?: number,
  ): Promise<Buffer> {
    if (!this.moduleOptions?.useDefaultValues) {
      this.checkModuleOptions('KDF', {
        ...(!length && {
          outputKeyLength: this.moduleOptions?.kdf?.outputKeyLength,
        }),
        argon2Type: this.moduleOptions?.kdf?.argon2Type,
        memoryCost: this.moduleOptions?.kdf?.memoryCost,
        timeCost: this.moduleOptions?.kdf?.timeCost,
      });
    } else {
      this.moduleOptions.kdf = {
        ...this.moduleOptions?.kdf,
      };
      this.moduleOptions.kdf.outputKeyLength =
        DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS.outputKeyLength;
      this.moduleOptions.kdf.argon2Type =
        DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS.argon2Type;
      this.moduleOptions.kdf.memoryCost =
        DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS.memoryCost;
      this.moduleOptions.kdf.timeCost =
        DEFAULT_KDF_CRYPTOGRAPHY_OPTIONS.timeCost;
    }

    console.log(this.moduleOptions.kdf);

    return await argon2.hash(masterKey, {
      hashLength: length ?? this.moduleOptions.kdf.outputKeyLength,
      salt: salt,
      type: this.moduleOptions.kdf.argon2Type,
      memoryCost: this.moduleOptions.kdf.memoryCost,
      timeCost: this.moduleOptions.kdf.timeCost,
      raw: true,
    });
  }

  public async createArgon2HashFromPassword(
    data: string | Buffer,
  ): Promise<Buffer> {
    if (!this.moduleOptions?.useDefaultValues) {
      this.checkModuleOptions('HASHING_PASSWORD', {
        outputKeyLength: this.moduleOptions?.hashing?.password?.outputKeyLength,
        argon2Type: this.moduleOptions?.hashing?.password?.argon2Type,
        memoryCost: this.moduleOptions?.hashing?.password?.memoryCost,
        timeCost: this.moduleOptions?.hashing?.password?.timeCost,
      });
    } else {
      this.moduleOptions.hashing = {
        ...this.moduleOptions?.hashing,
        password: {
          ...this.moduleOptions.hashing?.password,
        },
      };
      this.moduleOptions.hashing.password.outputKeyLength =
        DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS.password.outputKeyLength;
      this.moduleOptions.hashing.password.argon2Type =
        DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS.password.argon2Type;
      this.moduleOptions.hashing.password.memoryCost =
        DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS.password.memoryCost;
      this.moduleOptions.hashing.password.timeCost =
        DEFAULT_HASHING_CRYPTOGRAPHY_OPTIONS.password.timeCost;
    }

    const tmpData = await argon2.hash(data, {
      hashLength: this.moduleOptions.hashing.password.outputKeyLength,
      type: this.moduleOptions.hashing.password.argon2Type,
      memoryCost: this.moduleOptions.hashing.password.memoryCost,
      timeCost: this.moduleOptions.hashing.password.timeCost,
      raw: false,
    });

    return Buffer.isBuffer(tmpData) ? tmpData : Buffer.from(tmpData);
  }

  public async verifyArgon2HashFromPassword(
    hash: string,
    data: string | Buffer,
  ): Promise<boolean> {
    return await argon2.verify(hash, data);
  }

  public createCustomHash(
    algorithm: string,
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Buffer {
    const inputData = this.convertInputData(data, options?.inputDataEncoding);

    const hash = crypto.createHash(algorithm, {
      ...(options?.outputLength && { outputLength: options?.outputLength }),
    });

    hash.update(inputData);

    return hash.digest();
  }

  public verifyCustomHash(
    algorithm: string,
    data: string | Buffer,
    oldHash: string | Buffer,
    options?: GenericOptionsInterface,
  ): boolean {
    const inputOldHashData = this.convertInputData(
      oldHash,
      options?.inputDataEncoding,
    );

    const hash = this.createCustomHash(algorithm, data, options);

    return crypto.timingSafeEqual(hash, inputOldHashData);
  }

  public createSecureHash(
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Buffer {
    return this.createCustomHash('shake256', data, {
      ...options,
      outputLength: 48,
    });
  }

  public verifySecureHash(
    data: string | Buffer,
    oldHash: string | Buffer,
    options?: GenericOptionsInterface,
  ): boolean {
    return this.verifyCustomHash('shake256', data, oldHash, {
      ...options,
      outputLength: 48,
    });
  }

  public createCustomHmac(
    algorithm: string,
    key: string | Buffer,
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Buffer {
    const inputKey = this.convertInputData(key, options?.inputKeyEncoding);
    const inputData = this.convertInputData(data, options?.inputDataEncoding);

    const hmac = crypto.createHmac(algorithm, crypto.createSecretKey(inputKey));

    hmac.update(inputData);

    key = null;

    return hmac.digest();
  }

  public verifyCustomHmac(
    algorithm: string,
    key: string | Buffer,
    data: string | Buffer,
    oldHmac: string | Buffer,
    options?: GenericOptionsInterface,
  ): boolean {
    const inputOldHmacData = this.convertInputData(
      oldHmac,
      options?.inputDataEncoding,
    );

    const hmac = this.createCustomHmac(algorithm, key, data, options);

    return crypto.timingSafeEqual(hmac, inputOldHmacData);
  }

  public createSecureHmac(
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Buffer {
    this.checkModuleOptions('HMAC', {
      masterKey: this.moduleOptions?.hashing?.hmac?.masterKey,
    });

    const key = Buffer.from(this.moduleOptions.hashing.hmac.masterKey, 'hex');

    const salt = crypto.randomBytes(16);

    const secureKey = this.createHmacSecureKey(key, salt);

    const hmac = this.createCustomHmac('sha3-256', secureKey, data, options);

    return Buffer.concat([salt, hmac], salt.length + hmac.length);
  }

  public verifySecureHmac(
    data: string | Buffer,
    oldHmac: string | Buffer,
    options?: GenericOptionsInterface,
  ): boolean {
    this.checkModuleOptions('HMAC', {
      masterKey: this.moduleOptions?.hashing?.hmac?.masterKey,
    });

    const key = Buffer.from(this.moduleOptions.hashing.hmac.masterKey, 'hex');

    const buffOldHmac = this.convertInputData(
      oldHmac,
      options?.inputDataEncoding,
    );

    const saltOldHmac = this.extractSaltFromHmac(buffOldHmac);
    const hashOldHmac = buffOldHmac.subarray(16, buffOldHmac.length);

    const secureKey = this.createHmacSecureKey(key, saltOldHmac);

    const hmac = this.createCustomHmac('sha3-256', secureKey, data, options);

    return crypto.timingSafeEqual(hmac, hashOldHmac);
  }

  public async symmetricDataEncrypt(
    data: string | Buffer,
    key: string | Buffer,
    options?: GenericOptionsInterface,
  ): Promise<Buffer> {
    const inputData = this.convertInputData(data, options?.inputDataEncoding);
    const inputKey = this.convertInputData(key, options?.inputKeyEncoding);

    const iv = this.createSafeRandomData(12);
    const salt = this.createSafeRandomData(64);

    const secureEncryptionKey = await this.deriveMasterKey(inputKey, salt, 32);

    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      crypto.createSecretKey(secureEncryptionKey),
      iv,
      {
        authTagLength: 16,
      },
    );

    let cipheredData = cipher.update(inputData);

    cipheredData = Buffer.concat([cipheredData, cipher.final()]);

    return Buffer.concat([iv, salt, cipher.getAuthTag(), cipheredData]);
  }

  public async symmetricDataDecrypt(
    data: string | Buffer,
    key: string | Buffer,
    options?: GenericOptionsInterface,
  ): Promise<Buffer> {
    const inputData = this.convertInputData(data, options?.inputDataEncoding);
    const inputKey = this.convertInputData(key, options?.inputKeyEncoding);

    const iv = this.extractIV(inputData);
    const salt = this.extractSalt(inputData);
    const authTag = this.extractAuthTagFromCypheredData(inputData);
    const cipheredData = this.extractCipheredData(inputData);

    const decryptionKey = await this.deriveMasterKey(inputKey, salt, 32);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      crypto.createSecretKey(decryptionKey),
      iv,
      {
        authTagLength: 16,
      },
    );

    decipher.setAuthTag(authTag);

    let decipheredData = decipher.update(cipheredData);

    decipheredData = Buffer.concat([decipheredData, decipher.final()]);

    return decipheredData;
  }

  public async symmetricSecureDataEncrypt(
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Promise<Buffer> {
    this.checkModuleOptions('SYMMETRIC_ENCRYPTION', {
      masterKey: this.moduleOptions?.encryption?.symmetric?.masterKey,
    });

    const dek = this.createSafeRandomData(32);

    const cipheredData = await this.symmetricDataEncrypt(data, dek, options);

    const cipheredDek = await this.symmetricDataEncrypt(
      dek,
      this.moduleOptions.encryption.symmetric.masterKey,
    );

    return Buffer.concat([cipheredDek, cipheredData]);
  }

  public async symmetricSecureDataDecrypt(
    data: string | Buffer,
    options?: GenericOptionsInterface,
  ): Promise<Buffer> {
    this.checkModuleOptions('SYMMETRIC_ENCRYPTION', {
      masterKey: this.moduleOptions?.encryption?.symmetric?.masterKey,
    });

    const inputData = this.convertInputData(data, options?.inputDataEncoding);

    const cipheredDek = this.extractCipheredDEK(inputData);

    const cipheredData = this.extractCipheredDataWithDEK(inputData);

    const decipheredDek = await this.symmetricDataDecrypt(
      cipheredDek,
      this.moduleOptions.encryption.symmetric.masterKey,
    );

    return await this.symmetricDataDecrypt(cipheredData, decipheredDek);
  }
}
