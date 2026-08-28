import { TestBed } from '@angular/core/testing';
import {
  ConversationSessionKey,
  EncryptedMessagePayload,
  KojinxCryptoProvider
} from '../models/crypto.models';
import { KOJINX_CRYPTO_PROVIDER } from '../tokens';
import { SafetyNumberUtils } from '../utils/safety-number.utils';
import { E2EChatCryptoService } from './e2e-chat-crypto.service';

describe('E2EChatCryptoService & SafetyNumberUtils', () => {
  let service: E2EChatCryptoService;
  let mockCryptoProvider: jasmine.SpyObj<KojinxCryptoProvider>;

  beforeEach(() => {
    mockCryptoProvider = jasmine.createSpyObj<KojinxCryptoProvider>(
      'KojinxCryptoProvider',
      ['getPublicKey', 'encrypt', 'decrypt']
    );

    // Simulated symmetric reverse for testing RSA wrapper
    mockCryptoProvider.encrypt.and.callFake((_pk, plaintext) =>
      Promise.resolve(`MOCK_ENC_${btoa(plaintext)}`)
    );
    mockCryptoProvider.decrypt.and.callFake(ciphertext => {
      const b64 = ciphertext.replace('MOCK_ENC_', '');
      return Promise.resolve(atob(b64));
    });

    TestBed.configureTestingModule({
      providers: [
        E2EChatCryptoService,
        { provide: KOJINX_CRYPTO_PROVIDER, useValue: mockCryptoProvider }
      ]
    });

    service = TestBed.inject(E2EChatCryptoService);
  });

  describe('AES-256-GCM Encryption and Decryption', () => {
    let testSessionKey: ConversationSessionKey;

    beforeEach(async () => {
      const rawKey = await service.generateAesKey();
      testSessionKey = {
        id: 'sk_test_12345',
        type: 'dm',
        conversationId: 'userA_userB',
        rawKey,
        generation: 1,
        createdAt: Date.now()
      };
    });

    it('should encrypt and decrypt a standard message successfully', async () => {
      const message = 'Hello Bob, this is a top secret Kojinx message!';
      const payload: EncryptedMessagePayload = await service.encryptMessage(
        testSessionKey,
        message
      );

      expect(payload.ciphertext).toBeDefined();
      expect(payload.nonce).toBeDefined();
      expect(payload.sessionKeyId).toBe('sk_test_12345');
      expect(payload.generation).toBe(1);
      expect(payload.ciphertext).not.toEqual(message);

      const decrypted = await service.decryptMessage(testSessionKey, payload);
      expect(decrypted).toEqual(message);
    });

    it('should correctly handle emojis, Unicode and multiline characters', async () => {
      const message = '🚀 Kojinx E2EE Security Test \n🔥 日本語 / Português / Русский \n✨ 100% Confidential';
      const payload = await service.encryptMessage(testSessionKey, message);
      const decrypted = await service.decryptMessage(testSessionKey, payload);

      expect(decrypted).toEqual(message);
    });

    it('should generate a fresh unique nonce and different ciphertext for identical messages', async () => {
      const message = 'Repeated message payload';
      const payload1 = await service.encryptMessage(testSessionKey, message);
      const payload2 = await service.encryptMessage(testSessionKey, message);

      expect(payload1.nonce).not.toEqual(payload2.nonce);
      expect(payload1.ciphertext).not.toEqual(payload2.ciphertext);

      expect(await service.decryptMessage(testSessionKey, payload1)).toEqual(message);
      expect(await service.decryptMessage(testSessionKey, payload2)).toEqual(message);
    });

    it('should throw an error if ciphertext has been tampered with (GCM auth tag failure)', async () => {
      const message = 'Authentic payload';
      const payload = await service.encryptMessage(testSessionKey, message);

      // Corrupt 1 byte in the base64 ciphertext
      const rawBytes = new Uint8Array(service.base64ToArrayBuffer(payload.ciphertext));
      rawBytes[0] = rawBytes[0] ^ 0xff; // flip bits
      const corruptedCiphertext = service.arrayBufferToBase64(rawBytes);

      const tamperedPayload: EncryptedMessagePayload = {
        ...payload,
        ciphertext: corruptedCiphertext
      };

      try {
        await service.decryptMessage(testSessionKey, tamperedPayload);
        fail('Should have thrown an authentication verification error');
      } catch (err) {
        expect(err).toBeDefined();
      }
    });
  });

  describe('Key Export, Import, and Wrapping', () => {
    it('should export raw AES key and import it back losslessly', async () => {
      const originalKey = await service.generateAesKey();
      const base64 = await service.exportRawKeyBase64(originalKey);
      const importedKey = await service.importRawKeyBase64(base64);

      const sessionKey1: ConversationSessionKey = {
        id: '1',
        type: 'dm',
        conversationId: 'test',
        rawKey: originalKey,
        generation: 1,
        createdAt: Date.now()
      };

      const sessionKey2: ConversationSessionKey = {
        id: '1',
        type: 'dm',
        conversationId: 'test',
        rawKey: importedKey,
        generation: 1,
        createdAt: Date.now()
      };

      const payload = await service.encryptMessage(sessionKey1, 'Cross-key test');
      const decrypted = await service.decryptMessage(sessionKey2, payload);
      expect(decrypted).toEqual('Cross-key test');
    });

    it('should wrap and unwrap session key via host RSA provider', async () => {
      const originalKey = await service.generateAesKey();
      const wrapped = await service.wrapSessionKey(originalKey, 'MOCK_PUBLIC_KEY');

      expect(mockCryptoProvider.encrypt).toHaveBeenCalled();

      const unwrappedKey = await service.unwrapSessionKey(wrapped);
      expect(mockCryptoProvider.decrypt).toHaveBeenCalled();
      expect(unwrappedKey).toBeDefined();
      expect(unwrappedKey.type).toBe('secret');
    });
  });

  describe('SafetyNumberUtils', () => {
    const keyAlice = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123AlicePublicKey';
    const keyBob = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4567BobPublicKey';

    it('should generate a 30-digit formatted safety number in 6 blocks of 5 digits', async () => {
      const safetyNumber = await SafetyNumberUtils.generate(keyAlice, keyBob);

      expect(safetyNumber.formatted).toMatch(/^\d{5} \d{5} \d{5} \d{5} \d{5} \d{5}$/);
      expect(safetyNumber.localFingerprint).toBeDefined();
      expect(safetyNumber.remoteFingerprint).toBeDefined();
    });

    it('should be order-independent (Alice->Bob matches Bob->Alice)', async () => {
      const num1 = await SafetyNumberUtils.generate(keyAlice, keyBob);
      const num2 = await SafetyNumberUtils.generate(keyBob, keyAlice);

      expect(num1.formatted).toEqual(num2.formatted);
      expect(num1.raw).toEqual(num2.raw);
    });

    it('should produce different safety numbers for different keys', async () => {
      const keyEve = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8999EvePublicKey';
      const numAliceBob = await SafetyNumberUtils.generate(keyAlice, keyBob);
      const numAliceEve = await SafetyNumberUtils.generate(keyAlice, keyEve);

      expect(numAliceBob.formatted).not.toEqual(numAliceEve.formatted);
    });
  });
});
