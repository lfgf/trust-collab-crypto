/**
 * Encrypted message payload format transmitted over HTTP/SSE and stored in database.
 */
export interface EncryptedMessagePayload {
  /** Base64-encoded AES-256-GCM ciphertext */
  ciphertext: string;
  /** Base64-encoded 12-byte (96-bit) Initialization Vector (Nonce) */
  nonce: string;
  /** UUID of the Session Key used to encrypt this message */
  sessionKeyId: string;
  /** Generation number of the Session Key (incremented during key rotation) */
  generation: number;
}

/**
 * In-memory active Session Key holding standard W3C CryptoKey.
 */
export interface ConversationSessionKey {
  /** Unique UUID identifier for this session key */
  id: string;
  /** Conversation scope */
  type: 'dm' | 'channel' | 'group';
  /** Target conversation ID (recipientId for 1:1 DM, channelId for channels, groupId for groups) */
  conversationId: string;
  /** W3C SubtleCrypto AES-GCM 256-bit Key */
  rawKey: CryptoKey;
  /** Generation index (starts at 1, incremented upon rotation) */
  generation: number;
  /** Creation epoch timestamp in milliseconds */
  createdAt: number;
}

/**
 * Wire-format for storing and synchronizing encrypted session keys across members.
 */
export interface SessionKeyExchangePayload {
  sessionKeyId: string;
  conversationType: 'dm' | 'channel' | 'group';
  conversationId: string;
  generation: number;
  /** Map of UserId -> RSA-OAEP Base64 Encrypted AES Raw Key */
  memberPayloads: Record<string, string>;
  createdAt?: string;
  createdBy?: string;
}

/**
 * Member public key entry returned by public key directory.
 */
export interface MemberPublicKey {
  userId: string;
  publicKey: string;
}

/**
 * Safety Number verification model (Signal-style).
 */
export interface SafetyNumber {
  /** Raw 60-character hexadecimal digest */
  raw: string;
  /** Standardized formatted display in 6 blocks of 5 decimal digits */
  formatted: string;
  /** Fingerprint component for the local user */
  localFingerprint: string;
  /** Fingerprint component for the remote user */
  remoteFingerprint: string;
}

/**
 * Cryptography provider abstraction interface (RSA-2048 OAEP).
 */
export interface KojinxCryptoProvider {
  /** Returns the base64-encoded RSA public key */
  getPublicKey(): Promise<string>;
  /** Asymmetrically encrypts plaintext using target base64 RSA public key */
  encrypt(publicKeyBase64: string, plaintext: string): Promise<string>;
  /** Asymmetrically decrypts ciphertext using local private key */
  decrypt(ciphertextBase64: string): Promise<string>;
}

/**
 * Client-agnostic fetch options.
 */
export interface KojinxFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Client-agnostic fetch response.
 */
export interface KojinxFetchResponse<T = any> {
  status: number;
  data: T;
  headers?: Record<string, string>;
}

export type KojinxFetchFunction = <T = any>(
  url: string,
  options?: KojinxFetchOptions
) => Promise<KojinxFetchResponse<T>>;

/**
 * Local storage interface for session key caching.
 */
export interface KojinxStorageProvider {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
