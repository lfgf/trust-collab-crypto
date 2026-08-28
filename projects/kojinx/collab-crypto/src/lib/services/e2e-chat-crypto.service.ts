import { Injectable, inject } from '@angular/core';
import {
  ConversationSessionKey,
  EncryptedMessagePayload,
  KojinxCryptoProvider
} from '../models/crypto.models';
import { KOJINX_CRYPTO_PROVIDER } from '../tokens';

/**
 * Pure End-to-End Encryption cryptographic service.
 * Handles AES-256-GCM message encryption/decryption and RSA key wrapping/unwrapping.
 */
@Injectable({
  providedIn: 'root'
})
export class E2EChatCryptoService {
  private cryptoProvider = inject<KojinxCryptoProvider>(KOJINX_CRYPTO_PROVIDER, {
    optional: true
  });

  /**
   * Generates a new cryptographically secure 256-bit AES-GCM session key.
   */
  async generateAesKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true, // extractable for RSA wrapping & secure export
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts plaintext string using AES-256-GCM with a fresh 12-byte (96-bit) nonce.
   *
   * @param sessionKey In-memory active session key
   * @param plaintext Plaintext message content
   */
  async encryptMessage(
    sessionKey: ConversationSessionKey,
    plaintext: string
  ): Promise<EncryptedMessagePayload> {
    if (!sessionKey || !sessionKey.rawKey) {
      throw new Error('Invalid session key provided for encryption.');
    }

    // Standard 12-byte initialization vector for AES-GCM
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedPlaintext = encoder.encode(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce
      },
      sessionKey.rawKey,
      encodedPlaintext
    );

    return {
      ciphertext: this.arrayBufferToBase64(ciphertextBuffer),
      nonce: this.arrayBufferToBase64(nonce.buffer),
      sessionKeyId: sessionKey.id,
      generation: sessionKey.generation
    };
  }

  /**
   * Decrypts an EncryptedMessagePayload using AES-256-GCM.
   *
   * @param sessionKey In-memory session key corresponding to payload.sessionKeyId
   * @param payload Encrypted payload containing ciphertext and nonce
   */
  async decryptMessage(
    sessionKey: ConversationSessionKey,
    payload: EncryptedMessagePayload
  ): Promise<string> {
    if (!sessionKey || !sessionKey.rawKey) {
      throw new Error('Invalid session key provided for decryption.');
    }

    const ciphertext = this.base64ToArrayBuffer(payload.ciphertext);
    const nonce = this.base64ToArrayBuffer(payload.nonce);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(nonce)
      },
      sessionKey.rawKey,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }

  /**
   * Exports an AES-GCM key and wraps (encrypts) it with a recipient's RSA public key.
   *
   * @param aesKey AES CryptoKey to wrap
   * @param recipientPublicKey Base64-encoded recipient RSA public key
   */
  async wrapSessionKey(
    aesKey: CryptoKey,
    recipientPublicKey: string
  ): Promise<string> {
    if (!this.cryptoProvider) {
      throw new Error(
        'KOJINX_CRYPTO_PROVIDER is not provided. Cannot wrap session keys.'
      );
    }

    const rawKeyBytes = await crypto.subtle.exportKey('raw', aesKey);
    const rawKeyBase64 = this.arrayBufferToBase64(rawKeyBytes);

    // Asymmetrically encrypt using host RSA provider
    return this.cryptoProvider.encrypt(recipientPublicKey, rawKeyBase64);
  }

  /**
   * Unwraps (decrypts) an RSA-encrypted AES raw key and imports it back into a W3C CryptoKey.
   *
   * @param encryptedAesKeyBase64 RSA-encrypted AES raw key in base64 format
   */
  async unwrapSessionKey(encryptedAesKeyBase64: string): Promise<CryptoKey> {
    if (!this.cryptoProvider) {
      throw new Error(
        'KOJINX_CRYPTO_PROVIDER is not provided. Cannot unwrap session keys.'
      );
    }

    // Asymmetrically decrypt using local private key
    const rawKeyBase64 = await this.cryptoProvider.decrypt(
      encryptedAesKeyBase64
    );
    const rawKeyBuffer = this.base64ToArrayBuffer(rawKeyBase64);

    return crypto.subtle.importKey(
      'raw',
      rawKeyBuffer,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Exports a CryptoKey to base64 raw bytes.
   */
  async exportRawKeyBase64(key: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey('raw', key);
    return this.arrayBufferToBase64(raw);
  }

  /**
   * Imports a base64 raw key string into a CryptoKey.
   */
  async importRawKeyBase64(base64: string): Promise<CryptoKey> {
    const buffer = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      'raw',
      buffer,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encodes ArrayBuffer to Base64 string.
   */
  arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Decodes Base64 string to ArrayBuffer.
   */
  base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
