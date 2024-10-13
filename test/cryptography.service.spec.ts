import * as argon2 from 'argon2';
import { Test, TestingModule } from '@nestjs/testing';
import { CryptographyService, CryptographyOptionsInterface } from '../lib';
import { MODULE_OPTIONS_TOKEN } from '../lib/cryptography.module-definition';

describe('CryptographyService', () => {
  let service: CryptographyService;

  const mockCryptographyOptions: CryptographyOptionsInterface = {
    kdf: {
      timeCost: 3,
      memoryCost: 65536,
      argon2Type: argon2.argon2i,
      outputKeyLength: 32,
    },
    hashing: {
      password: {
        timeCost: 3,
        memoryCost: 65536,
        argon2Type: argon2.argon2id,
        outputKeyLength: 64,
      },
      hmac: {
        masterKey:
          '210c22a80d878d96102780419cdc13e2309866adcc6cf9191828279b33b4e29f',
      },
    },
    encryption: {
      symmetric: {
        masterKey:
          'bf71d424c39f58c925d9093eea419d1f67429516a5fdc4f7abbf9e8e7fbe8d7b',
      },
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CryptographyService,
        {
          provide: MODULE_OPTIONS_TOKEN,
          useValue: mockCryptographyOptions,
        },
      ],
    }).compile();

    service = module.get<CryptographyService>(CryptographyService);
  });

  it('should return error on masterKey not defined', async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CryptographyService,
        {
          provide: MODULE_OPTIONS_TOKEN,
          useValue: {
            ...mockCryptographyOptions,
            hashing: {
              ...mockCryptographyOptions.hashing,
              hmac: {
                masterKey: undefined,
              },
            },
          },
        },
      ],
    }).compile();

    service = module.get<CryptographyService>(CryptographyService);

    expect(() =>
      service.createSecureHmac('test', {
        inputDataEncoding: 'utf-8',
      }),
    ).toThrow();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
    expect(service).toBeInstanceOf(CryptographyService);
  });

  it('should generate an UUIDv4', () => {
    const uuid = service.genUUID();

    expect(uuid).toMatch(
      /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i,
    );
  });

  it('should generate a random password', () => {
    const password = service.genRandomPassword(32);

    expect(password).toMatch(/[A-Za-z\d+\/]{32}$/i);
  });

  it('should generate a symmetric key', () => {
    const symmetricKey = service.generateSymmetricKey(192);

    expect(symmetricKey.type).toBe('secret');
  });

  it('should derive a master key', async () => {
    const masterKey = await service.deriveMasterKey(
      Buffer.alloc(8),
      Buffer.alloc(8),
      32,
    );

    expect(masterKey.length).toBe(32);
    expect(masterKey.toString('hex')).toMatch(/^[a-z\d]{64}$/);
  });

  it('should create an argon2 hash', async () => {
    const argon2Hash = await service.createArgon2HashFromPassword(
      Buffer.from('strong_password'),
    );

    expect(argon2Hash.toString()).toMatch(
      /\$argon2id\$v=19\$m=65536,t=3,p=4\$[a-zA-Z\d$\/+\\]*/,
    );
  });

  it('should verify an argon2 hash', async () => {
    const goodVerificationResult = await service.verifyArgon2HashFromPassword(
      '$argon2id$v=19$m=65536,t=3,p=4$Yq6DQNj646f5yfeHXeKdZA$K' +
        'p87Nt5KakqLUHL/GcYqDnlRTmNr6hUnrvjCB7pua52WfZyKOwyK97IV' +
        'QQEyGkYpJsiPKGIo/Fre70WccqLI0Q',
      Buffer.from('strong_password'),
    );

    expect(goodVerificationResult).toBeTruthy();
  });

  it('should create a custom hash (sha256)', () => {
    const hash = service.createCustomHash(
      'sha256',
      Buffer.from('strong_password'),
    );
    const hash2 = service.createCustomHash('sha256', 'strong_password', {
      inputDataEncoding: 'utf-8',
    });

    expect(hash).toEqual(hash2);
  });

  it('should verify a custom hash (sha256)', () => {
    const originalHash =
      'e7fca264bc39d9a39a1b89e6ed819f9e28290be64c265c361df1967441462a4e';
    const goodVerificationResult = service.verifyCustomHash(
      'sha256',
      Buffer.from('strong_password', 'utf8'),
      Buffer.from(originalHash, 'hex'),
    );

    expect(goodVerificationResult).toBeTruthy();
  });

  it('should create a secure hash (shake256)', () => {
    const hash = service.createSecureHash('strong_password', {
      inputDataEncoding: 'utf-8',
    });

    expect(hash.length).toBe(48);
    expect(hash.toString('hex')).toMatch(/^[a-z\d]{96}$/i);
  });

  it('should verify a secure hash (shake256', () => {
    const originalHash =
      'd0c2c9e01bc5af77239846bde536551646900400398c5b64' +
      'b4472f3e567eb5ecce9faa03e2e25ce6f8b2ffe9d366d8fd';
    const goodVerificationResult = service.verifySecureHash(
      Buffer.from('strong_password', 'utf8'),
      originalHash,
      { inputDataEncoding: 'hex' },
    );
    const badVerificationResult = service.verifySecureHash(
      Buffer.from('str0ng_p4ssw0rd', 'utf8'),
      originalHash,
      { inputDataEncoding: 'hex' },
    );

    expect(goodVerificationResult).toBeTruthy();
    expect(badVerificationResult).toBeFalsy();
  });

  it('should create a custom HMAC (sha3-256)', () => {
    const hmac = service.createCustomHmac('sha512', 'strong_key', 'test', {
      inputDataEncoding: 'utf-8',
      inputKeyEncoding: 'utf-8',
    });

    expect(hmac.length).toBe(64);
    expect(hmac.toString('hex')).toMatch(/^[a-z\d]{128}$/);
  });

  it('should verify a custom HMAC (sha512)', () => {
    const oldHmac =
      '61e1b9895f685b4fae5ff07b96f67e8be10a0018239fd258cdf42e8f33104a5f' +
      'd336aa5ab469d6dafae6b925fe46332336bf85bc32c39c9294c40bf174e30d3d';
    const goodVerificationResult = service.verifyCustomHmac(
      'sha512',
      'strong_key',
      'test',
      Buffer.from(oldHmac, 'hex'),
      {
        inputDataEncoding: 'utf-8',
        inputKeyEncoding: 'utf-8',
      },
    );
    const badVerificationResult = service.verifyCustomHmac(
      'sha512',
      'str0ng_k3y',
      'test',
      Buffer.from(oldHmac, 'hex'),
      {
        inputDataEncoding: 'utf-8',
        inputKeyEncoding: 'utf-8',
      },
    );
    expect(goodVerificationResult).toBeTruthy();
    expect(badVerificationResult).toBeFalsy();
  });

  it('should create a secure HMAC (sha3-256)', () => {
    const hmac = service.createSecureHmac('test', {
      inputDataEncoding: 'utf-8',
    });

    expect(hmac.length).toBe(48);
    expect(hmac.toString('hex')).toMatch(/^[a-z\d]{96}$/i);
  });

  it('should verify a secure HMAC (sha3-256)', () => {
    const oldHmac =
      '620c237e3dcdfff73ca589642ec381b8fd98e1ce45b4b61a' +
      '5f1f05f69561acf0f45a62cc35b64cfcec74c22c7a10845b';
    const goodVerificationResult = service.verifySecureHmac(
      Buffer.from('test', 'utf-8'),
      Buffer.from(oldHmac, 'hex'),
    );
    const badVerificationResult = service.verifySecureHmac(
      Buffer.from('t3st', 'utf-8'),
      Buffer.from(oldHmac, 'hex'),
    );

    expect(goodVerificationResult).toBeTruthy();
    expect(badVerificationResult).toBeFalsy();
  });

  it('should encrypt data using AES-256-GCM (simple)', async () => {
    const cypheredData = await service.symmetricDataEncrypt(
      'test',
      'str0ng_k3y',
      { inputDataEncoding: 'utf-8', inputKeyEncoding: 'utf-8' },
    );

    expect(cypheredData.length).toBe(96);
    expect(cypheredData.toString('hex')).toMatch(/^[a-z\d]{192}$/i);
  });

  it('should decrypt data using AES-256-GCM (simple)', async () => {
    const cypheredData =
      'c06ac7d58ae497191937ee6159677c364d' +
      '9de891cdd8d70508832b4fe01019a522f8' +
      '30bf269fd0927da9b70ba407ab2c8fabf3' +
      '47214924bb9b286e4f55c223d2965d65f5' +
      '7e0ed10e1fde330ea68612be4b3b83e004' +
      '7176d7e44bb5c6b47e36e6';

    const goodDecryption = await service.symmetricDataDecrypt(
      cypheredData,
      'str0ng_k3y',
      {
        inputDataEncoding: 'hex',
        inputKeyEncoding: 'utf-8',
      },
    );

    const throwDecryptionError = async () => {
      await service.symmetricDataDecrypt(cypheredData, '0th3r_str0ng_k3y', {
        inputDataEncoding: 'hex',
        inputKeyEncoding: 'utf-8',
      });
    };

    expect(goodDecryption.toString()).toBe('test');
    await expect(throwDecryptionError()).rejects.toThrow();
  });

  it('should encrypt data using AES-256-GCM (advance)', async () => {
    const cypheredData = await service.symmetricSecureDataEncrypt('test', {
      inputDataEncoding: 'utf-8',
    });

    expect(cypheredData.length).toBe(220);
    expect(cypheredData.toString('hex')).toMatch(/^[a-z\d]{440}$/i);
  });

  it('should decrypt data using AES-256-GCM (advance)', async () => {
    const cypheredData =
      '845e091d036dd9ab1334ae1616219ed06db734fdbcb8b6aa89d6822' +
      '258c031838c66f9339e55e586ac0b307b5f81838865df185bb4d855' +
      '328140939ce7dfcf33adf0d5af5e7ca17cd217b0345ff40eaa17b7e' +
      '954025cec94531266870af613afa06a07a4be2caea5a067f81f7df0' +
      '489df00b4a42eff53cb7868320e9a6d3507ecafeebedc86233ba155' +
      'd4f60c416eff35dedd9af9908482fc85aff686cd93ba4b27c35bbf1' +
      '15ccd81e439f1feedc8d31d8ceef0449c9acea94ca79cf8cd240161' +
      'd766b6712cbede9e05f78ef26315103594d6630c673fe39c5944a35';

    const goodDecryption = await service.symmetricSecureDataDecrypt(
      cypheredData,
      {
        inputDataEncoding: 'hex',
      },
    );

    const throwDecryptionError = async () => {
      await service.symmetricSecureDataDecrypt(cypheredData + 'ff', {
        inputDataEncoding: 'hex',
      });
    };

    expect(goodDecryption.toString()).toBe('test');
    await expect(throwDecryptionError()).rejects.toThrow();
  });
});
