import { Injectable, inject } from '@angular/core';
import {
  ConversationSessionKey,
  KojinxFetchFunction,
  KojinxStorageProvider,
  MemberPublicKey,
  SessionKeyExchangePayload
} from '../models/crypto.models';
import {
  KOJINX_API_BASE_URL,
  KOJINX_AUTH_TOKEN,
  KOJINX_CRYPTO_STORAGE,
  KOJINX_HTTP_FETCH
} from '../tokens';
import { E2EChatCryptoService } from './e2e-chat-crypto.service';

/** 30 days in milliseconds for maximum session key lifetime */
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Manages the lifecycle, caching, negotiation, and rotation of conversation session keys.
 */
@Injectable({
  providedIn: 'root'
})
export class SessionKeyManagerService {
  private cryptoService = inject(E2EChatCryptoService);
  private httpFetch = inject<KojinxFetchFunction>(KOJINX_HTTP_FETCH, {
    optional: true
  });
  private getApiUrl = inject<() => string>(KOJINX_API_BASE_URL, {
    optional: true
  });
  private getAuthToken = inject<() => Promise<string | null>>(
    KOJINX_AUTH_TOKEN,
    { optional: true }
  );
  private storage = inject<KojinxStorageProvider>(KOJINX_CRYPTO_STORAGE, {
    optional: true
  });

  /** Storage provider falling back to browser localStorage if not explicitly injected */
  private get storageProvider(): KojinxStorageProvider | null {
    if (this.storage) return this.storage;
    if (typeof localStorage !== 'undefined') {
      return {
        getItem: (k: string) => Promise.resolve(localStorage.getItem(k)),
        setItem: (k: string, v: string) => Promise.resolve(localStorage.setItem(k, v)),
        removeItem: (k: string) => Promise.resolve(localStorage.removeItem(k))
      };
    }
    return null;
  }

  /** Fast in-memory cache mapped by conversationId */
  private activeKeysByConversation = new Map<string, ConversationSessionKey>();
  /** Fast in-memory cache mapped by sessionKeyId (for historic messages) */
  private keysById = new Map<string, ConversationSessionKey>();
  /** Deduplicates in-flight server requests for the same conversation ID */
  private inFlightFetches = new Map<string, Promise<ConversationSessionKey | null>>();

  /**
   * Retrieves or creates an active session key for a 1:1 Direct Message conversation.
   *
   * @param localUserId Current user's ID
   * @param remoteUserId Remote contact's ID
   * @param remotePublicKey Base64 RSA public key of remote contact
   * @param localPublicKey Base64 RSA public key of local user
   */
  async getOrCreateDmSessionKey(
    localUserId: string,
    remoteUserId: string,
    remotePublicKey: string,
    localPublicKey: string
  ): Promise<ConversationSessionKey> {
    const conversationId = this.buildDmConversationId(
      localUserId,
      remoteUserId
    );

    // 1. Check in-memory cache
    const cached = this.activeKeysByConversation.get(conversationId);
    if (cached && !this.isKeyExpired(cached)) {
      return cached;
    }

    // 2. Attempt fetching from server if HTTP fetch is provided
    if (this.httpFetch && this.getApiUrl && this.getAuthToken) {
      const serverKey = await this.fetchSessionKeyFromServer(
        conversationId,
        'dm'
      );
      if (serverKey) {
        this.cacheKey(serverKey);
        return serverKey;
      }
    }

    // 3. Create fresh session key and distribute
    return this.createAndDistributeSessionKey({
      type: 'dm',
      conversationId,
      generation: cached ? cached.generation + 1 : 1,
      members: [
        { userId: localUserId, publicKey: localPublicKey },
        { userId: remoteUserId, publicKey: remotePublicKey }
      ]
    });
  }

  /**
   * Retrieves or creates an active session key for a Native Channel or Group.
   *
   * @param channelId Unique channel ID
   * @param members List of all workspace/channel members with their public keys
   */
  async getOrCreateChannelSessionKey(
    channelId: string,
    members: MemberPublicKey[]
  ): Promise<ConversationSessionKey> {
    const cached = this.activeKeysByConversation.get(channelId);
    if (cached && !this.isKeyExpired(cached)) {
      return cached;
    }

    if (this.httpFetch && this.getApiUrl && this.getAuthToken) {
      const serverKey = await this.fetchSessionKeyFromServer(
        channelId,
        'channel'
      );
      if (serverKey) {
        this.cacheKey(serverKey);
        return serverKey;
      }
    }

    return this.createAndDistributeSessionKey({
      type: 'channel',
      conversationId: channelId,
      generation: cached ? cached.generation + 1 : 1,
      members
    });
  }

  /**
   * Retrieves a session key by its specific sessionKeyId (used for decrypting historic messages).
   */
  async getSessionKeyById(
    sessionKeyId: string
  ): Promise<ConversationSessionKey | null> {
    const cached = this.keysById.get(sessionKeyId);
    if (cached) return cached;

    // Check local storage
    const sp = this.storageProvider;
    if (sp) {
      const stored = await sp.getItem(
        `kojinx_sk_${sessionKeyId}`
      );
      if (stored) {
        try {
          const parsed = JSON.parse(stored);
          const rawKey = await this.cryptoService.importRawKeyBase64(
            parsed.rawKeyBase64
          );
          const key: ConversationSessionKey = {
            id: parsed.id,
            type: parsed.type,
            conversationId: parsed.conversationId,
            rawKey,
            generation: parsed.generation,
            createdAt: parsed.createdAt
          };
          this.cacheKey(key);
          return key;
        } catch {
          // ignore corrupted local key
        }
      }
    }

    return null;
  }

  /**
   * Generates a new AES session key, wraps it for all members, and uploads to the server.
   */
  async createAndDistributeSessionKey(params: {
    type: 'dm' | 'channel' | 'group';
    conversationId: string;
    generation: number;
    members: MemberPublicKey[];
  }): Promise<ConversationSessionKey> {
    const rawAesKey = await this.cryptoService.generateAesKey();
    const sessionKeyId = this.generateUuid();

    const memberPayloads: Record<string, string> = {};
    for (const member of params.members) {
      if (member.publicKey) {
        memberPayloads[member.userId] =
          await this.cryptoService.wrapSessionKey(
            rawAesKey,
            member.publicKey
          );
      }
    }

    const sessionKey: ConversationSessionKey = {
      id: sessionKeyId,
      type: params.type,
      conversationId: params.conversationId,
      rawKey: rawAesKey,
      generation: params.generation,
      createdAt: Date.now()
    };

    // Store in memory
    this.cacheKey(sessionKey);
    await this.persistKeyLocally(sessionKey);

    // Upload to server if online
    if (this.httpFetch && this.getApiUrl && this.getAuthToken) {
      const token = await this.getAuthToken();
      const apiUrl = this.getApiUrl();
      const payload: SessionKeyExchangePayload = {
        sessionKeyId,
        conversationType: params.type,
        conversationId: params.conversationId,
        generation: params.generation,
        memberPayloads
      };

      try {
        await this.httpFetch(`${apiUrl}/api/e2e/session-keys`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
      } catch (err) {
        console.warn(
          '[SessionKeyManager] Failed to sync session key to server:',
          err
        );
      }
    }

    return sessionKey;
  }

  /**
   * Helper to check if a key has exceeded the 30-day rotation threshold.
   */
  isKeyExpired(key: ConversationSessionKey): boolean {
    return Date.now() - key.createdAt > THIRTY_DAYS_MS;
  }

  /**
   * Builds a deterministic conversation identifier for 1:1 DMs (lexicographical sort).
   */
  buildDmConversationId(userIdA: string, userIdB: string): string {
    return [userIdA, userIdB].sort().join('_');
  }

  /**
   * Caches a session key in memory.
   */
  private cacheKey(key: ConversationSessionKey): void {
    this.activeKeysByConversation.set(key.conversationId, key);
    this.keysById.set(key.id, key);
  }

  /**
   * Persists an unwrapped session key to local storage for fast startup.
   */
  private async persistKeyLocally(
    key: ConversationSessionKey
  ): Promise<void> {
    const sp = this.storageProvider;
    if (!sp) return;
    try {
      const rawKeyBase64 = await this.cryptoService.exportRawKeyBase64(
        key.rawKey
      );
      const data = JSON.stringify({
        id: key.id,
        type: key.type,
        conversationId: key.conversationId,
        rawKeyBase64,
        generation: key.generation,
        createdAt: key.createdAt
      });
      await sp.setItem(`kojinx_sk_${key.id}`, data);
    } catch {
      // ignore persistence error
    }
  }

  /**
   * Fetches latest session key from server and unwraps it locally with deduplication.
   */
  private async fetchSessionKeyFromServer(
    conversationId: string,
    type: 'dm' | 'channel' | 'group'
  ): Promise<ConversationSessionKey | null> {
    if (!this.httpFetch || !this.getApiUrl || !this.getAuthToken) return null;

    const existingPromise = this.inFlightFetches.get(conversationId);
    if (existingPromise) {
      return existingPromise;
    }

    const fetchPromise = (async () => {
      try {
        const token = await this.getAuthToken!();
        const apiUrl = this.getApiUrl!();
        const res = await this.httpFetch!<{
          sessionKeyId: string;
          generation: number;
          encryptedKey: string;
          createdAt?: string;
        }>(`${apiUrl}/api/e2e/session-keys/${conversationId}`, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${token}`
          }
        });

        if (res.status === 200 && res.data?.encryptedKey) {
          const rawKey = await this.cryptoService.unwrapSessionKey(
            res.data.encryptedKey
          );
          const key: ConversationSessionKey = {
            id: res.data.sessionKeyId,
            type,
            conversationId,
            rawKey,
            generation: res.data.generation || 1,
            createdAt: res.data.createdAt
              ? new Date(res.data.createdAt).getTime()
              : Date.now()
          };
          this.cacheKey(key);
          await this.persistKeyLocally(key);
          return key;
        }
      } catch {
        // Not found or network error
      } finally {
        this.inFlightFetches.delete(conversationId);
      }
      return null;
    })();

    this.inFlightFetches.set(conversationId, fetchPromise);
    return fetchPromise;
  }

  /**
   * Generates a random UUID (W3C standard or fallback).
   */
  private generateUuid(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}
