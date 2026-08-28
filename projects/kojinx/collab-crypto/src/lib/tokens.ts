import { InjectionToken } from '@angular/core';
import {
  KojinxCryptoProvider,
  KojinxFetchFunction,
  KojinxStorageProvider
} from './models/crypto.models';

/**
 * Injected Asymmetric Cryptography Provider (RSA-2048 OAEP).
 * On desktop: Implemented via Tauri Rust Keyring IPC.
 * On mobile: Implemented via SubtleCrypto + Capacitor SecureStorage.
 */
export const KOJINX_CRYPTO_PROVIDER = new InjectionToken<KojinxCryptoProvider>(
  'KOJINX_CRYPTO_PROVIDER'
);

/**
 * Injected Client-Agnostic HTTP Fetcher (bypass CORS on native).
 */
export const KOJINX_HTTP_FETCH = new InjectionToken<KojinxFetchFunction>(
  'KOJINX_HTTP_FETCH'
);

/**
 * Injected Storage Provider for local session key caching.
 */
export const KOJINX_CRYPTO_STORAGE = new InjectionToken<KojinxStorageProvider>(
  'KOJINX_CRYPTO_STORAGE',
  {
    factory: () => ({
      getItem: (key: string) => Promise.resolve(localStorage.getItem(key)),
      setItem: (key: string, value: string) => {
        localStorage.setItem(key, value);
        return Promise.resolve();
      },
      removeItem: (key: string) => {
        localStorage.removeItem(key);
        return Promise.resolve();
      }
    })
  }
);

/**
 * Injected API Base URL accessor function.
 */
export const KOJINX_API_BASE_URL = new InjectionToken<() => string>(
  'KOJINX_API_BASE_URL'
);

/**
 * Injected Auth Bearer Token accessor function.
 */
export const KOJINX_AUTH_TOKEN = new InjectionToken<() => Promise<string | null>>(
  'KOJINX_AUTH_TOKEN'
);
