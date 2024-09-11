import * as crypto from 'node:crypto';
import * as argon2 from 'argon2';
import { Inject, Injectable } from '@nestjs/common';
import { MODULE_OPTIONS_TOKEN } from './cryptography.module-definition';
import { CryptographyOptionsInterface } from './interfaces';

@Injectable()
export class CryptographyService {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) private options: CryptographyOptionsInterface,
  ) {}

  private convertDataToBuffer(data: string | Buffer) {
    return Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex');
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

  private extractCipheredDEK(data: Buffer): Buffer {
    return data.subarray(0, 124);
  }

  private extractCipheredDataWithDEK(data: Buffer): Buffer {
    return data.subarray(124, data.length);
  }

  private createSaferRandomData(length: number): Buffer {
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

  private generateKeyDEK() {
    return crypto.createSecretKey(this.createSaferRandomData(32));
  }

  public genUUID(secure = false): string {
    return crypto.randomUUID({
      disableEntropyCache: secure,
    });
  }

  public genRandomPassword(length: number, encoding: 'base64' | 'hex'): string {
    return crypto.randomBytes(length).toString(encoding).slice(0, length);
  }

  public generateSymmetricKey(length: number = 256): crypto.KeyObject {
    return crypto.generateKeySync('hmac', { length });
  }

  public async deriveMasterKey(
    masterKey: string | Buffer,
    salt: Buffer,
    length: number,
  ): Promise<Buffer> {
    return await argon2.hash(masterKey, {
      hashLength: length ? length : this.options.kdf.defaultOutputKeyLength,
      salt: salt,
      type: this.options.kdf.argon2Type,
      memoryCost: this.options.kdf.memoryCost,
      timeCost: this.options.kdf.timeCost,
      raw: true,
    });
  }

  public async createArgonHashFromPassword(
    data: string | Buffer,
  ): Promise<Buffer> {
    const tmpData = await argon2.hash(data, {
      hashLength: this.options.hashing.password.outputKeyLength,
      type: this.options.hashing.password.argon2Type,
      memoryCost: this.options.hashing.password.memoryCost,
      timeCost: this.options.hashing.password.timeCost,
      raw: false,
    });
    return Buffer.isBuffer(tmpData) ? tmpData : Buffer.from(tmpData);
  }

  public async verifyArgonHashFromPassword(
    hash: string,
    data: string | Buffer,
  ): Promise<boolean> {
    return await argon2.verify(hash, data);
  }

  public createCustomHash(
    algorithm: string,
    data: string,
    outputLength: number = 0,
  ): Buffer {
    const hash = crypto.createHash(algorithm, {
      ...(outputLength && { outputLength }),
    });
    hash.update(data);
    return hash.digest();
  }

  public verifyCustomHash(
    algorithm: string,
    data: string,
    oldHash: string | Buffer,
    outputLength: number = 0,
  ): boolean {
    const hash = this.createCustomHash(algorithm, data, outputLength);
    if (Buffer.isBuffer(oldHash)) {
      return crypto.timingSafeEqual(hash, oldHash);
    } else {
      return crypto.timingSafeEqual(Buffer.from(oldHash, 'hex'), hash);
    }
  }

  public createSecureHash(data: string): Buffer {
    return this.createCustomHash('shake256', data, 48);
  }

  public verifySecureHash(data: string, oldHash: string | Buffer): boolean {
    const hash = this.createCustomHash('shake256', data, 48);
    const buffOldHash = Buffer.isBuffer(oldHash)
      ? oldHash
      : Buffer.from(oldHash, 'hex');
    return crypto.timingSafeEqual(hash, buffOldHash);
  }

  public createCustomHmac(
    algorithm: string,
    key: Buffer,
    data: string,
  ): Buffer {
    const hmac = crypto.createHmac(algorithm, crypto.createSecretKey(key));
    hmac.update(data);
    key = null;
    return hmac.digest();
  }

  public verifyCustomHmac(
    algorithm: string,
    key: Buffer,
    data: string,
    oldHmac: string | Buffer,
  ): boolean {
    const hmac = this.createCustomHmac(algorithm, key, data);
    if (Buffer.isBuffer(oldHmac)) {
      return crypto.timingSafeEqual(hmac, oldHmac);
    } else {
      return crypto.timingSafeEqual(Buffer.from(oldHmac, 'hex'), hmac);
    }
  }

  public createSecureHmac(data: string): Buffer {
    const key = Buffer.from(this.options.hashing.hmac.masterKey, 'hex');

    const salt = crypto.randomBytes(16);
    const secureKey = Buffer.from(
      crypto.hkdfSync(
        'sha3-256',
        crypto.createSecretKey(key),
        salt,
        Buffer.alloc(0),
        64,
      ),
    );
    const hmac = this.createCustomHmac('sha3-256', secureKey, data);
    return Buffer.concat(
      [Buffer.from(salt), Buffer.from(hmac)],
      salt.length + hmac.length,
    );
  }

  public verifySecureHmac(data: string, oldHmac: Buffer | string): boolean {
    const key = Buffer.from(this.options.hashing.hmac.masterKey, 'hex');

    const buffOldHmac = Buffer.isBuffer(oldHmac)
      ? oldHmac
      : Buffer.from(oldHmac, 'hex');

    const saltOldHmac = buffOldHmac.subarray(0, 16);
    const hashOldHmac = buffOldHmac.subarray(16, buffOldHmac.length);

    const secureKey = Buffer.from(
      crypto.hkdfSync(
        'sha3-256',
        crypto.createSecretKey(key),
        saltOldHmac,
        Buffer.alloc(0),
        64,
      ),
    );

    const hmac = this.createCustomHmac('sha3-256', secureKey, data);
    return crypto.timingSafeEqual(hmac, hashOldHmac);
  }

  public createInsecureFastHash(data: string): Buffer {
    return crypto.createHash('sha1').update(data).digest();
  }

  private async symmetricDataEncrypt(
    data: string | Buffer,
    key: string | Buffer,
  ): Promise<Buffer> {
    const iv = this.createSaferRandomData(12);
    const salt = this.createSaferRandomData(64);

    const secureEncryptionKey = await this.deriveMasterKey(key, salt, 32);

    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      crypto.createSecretKey(secureEncryptionKey),
      iv,
      {
        authTagLength: 16,
      },
    );

    let cipheredData = cipher.update(data);

    cipheredData = Buffer.concat([
      Buffer.from(cipheredData),
      Buffer.from(cipher.final()),
    ]);

    return Buffer.concat([iv, salt, cipher.getAuthTag(), cipheredData]);
  }

  private async symmetricDataDecrypt(
    data: string | Buffer,
    key: string | Buffer,
  ): Promise<Buffer> {
    data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex');
    const iv = this.extractIV(data);
    const salt = this.extractSalt(data);
    const authTag = this.extractAuthTagFromCypheredData(data);
    const cipheredData = this.extractCipheredData(data);

    const decryptionKey = await this.deriveMasterKey(key, salt, 32);

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

    decipheredData = Buffer.concat([
      Buffer.from(decipheredData),
      Buffer.from(decipher.final()),
    ]);

    return decipheredData;
  }

  public async symmetricSecureDataEncrypt(
    data: string | Buffer,
  ): Promise<Buffer> {
    const dek = this.createSaferRandomData(32);

    const cipheredData = await this.symmetricDataEncrypt(data, dek);

    const cipheredDek = await this.symmetricDataEncrypt(
      dek,
      this.options.encryption.symmetric.masterKey,
    );

    return Buffer.concat([cipheredDek, cipheredData]);
  }

  public async symmetricSecureDataDecrypt(
    data: string | Buffer,
  ): Promise<Buffer> {
    data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex');

    const cipheredDek = this.extractCipheredDEK(data);

    const cipheredData = this.extractCipheredDataWithDEK(data);

    const decipheredDek = await this.symmetricDataDecrypt(
      cipheredDek,
      this.options.encryption.symmetric.masterKey,
    );

    return await this.symmetricDataDecrypt(cipheredData, decipheredDek);
  }
}
