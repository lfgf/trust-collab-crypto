import { SafetyNumber } from '../models/crypto.models';

/**
 * Computes deterministic SHA-256 safety verification numbers (Signal-style).
 * Users can compare these 30-digit numbers out-of-band to verify end-to-end identity.
 */
export class SafetyNumberUtils {
  /**
   * Generates a Safety Number between two identity public keys.
   *
   * @param localPublicKey Base64-encoded local RSA public key
   * @param remotePublicKey Base64-encoded remote RSA public key
   */
  static async generate(
    localPublicKey: string,
    remotePublicKey: string
  ): Promise<SafetyNumber> {
    if (!localPublicKey || !remotePublicKey) {
      throw new Error('Both public keys are required to generate safety numbers.');
    }

    const localFingerprint = await this.hashPublicKey(localPublicKey);
    const remoteFingerprint = await this.hashPublicKey(remotePublicKey);

    // Sort lexicographically to ensure order-independent verification
    const sorted = [localFingerprint, remoteFingerprint].sort();
    const combinedDigest = await this.sha256(sorted.join(''));

    // Convert hex digest to a 30-digit decimal representation
    const digits = this.hexTo30Digits(combinedDigest);
    const formatted = this.formatBlocks(digits);

    return {
      raw: combinedDigest,
      formatted,
      localFingerprint: localFingerprint.substring(0, 16),
      remoteFingerprint: remoteFingerprint.substring(0, 16)
    };
  }

  /**
   * Hashes a single public key using SHA-256.
   */
  static async hashPublicKey(publicKeyBase64: string): Promise<string> {
    const cleanKey = publicKeyBase64.replace(/\s+/g, '');
    return this.sha256(cleanKey);
  }

  /**
   * Computes SHA-256 hex string using W3C Web Crypto API.
   */
  private static async sha256(input: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Converts a hexadecimal string into a deterministic 30-digit decimal string.
   */
  private static hexTo30Digits(hex: string): string {
    let result = '';
    // Take chunks of 8 hex characters (32-bit integers) to produce 5-digit decimal blocks
    for (let i = 0; i < 6; i++) {
      const chunk = hex.substring(i * 8, (i + 1) * 8);
      const num = parseInt(chunk, 16) % 100000;
      result += num.toString().padStart(5, '0');
    }
    return result;
  }

  /**
   * Formats a 30-digit string into 6 blocks of 5 digits separated by spaces.
   */
  private static formatBlocks(digits: string): string {
    const blocks: string[] = [];
    for (let i = 0; i < digits.length; i += 5) {
      blocks.push(digits.substring(i, i + 5));
    }
    return blocks.join(' ');
  }
}
