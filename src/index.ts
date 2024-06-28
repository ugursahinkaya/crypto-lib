export type EncryptionTuple = [ciphertext: ArrayBuffer, iv: Uint8Array];
export type Consumer = "server" | string;
import { webcrypto } from "crypto";

export class CryptoLib {
  keyMap = new Map<string, CryptoKey>();
  protected crypto: Crypto = webcrypto as unknown as Crypto;

  protected storeKeys(consumer: Consumer, keys: CryptoKeyPair) {
    this.keyMap.set(`${consumer}PRV`, keys.privateKey);
    this.keyMap.set(`${consumer}PBL`, keys.publicKey);
  }

  encodeMessage(message: string) {
    const encoder = new TextEncoder();
    return encoder.encode(message);
  }

  mergeBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
    const result = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    result.set(new Uint8Array(buffer1), 0);
    result.set(new Uint8Array(buffer2), buffer1.byteLength);
    return result.buffer;
  }

  prepareBuffer(buffer: ArrayBufferLike) {
    const length = buffer.byteLength;
    const data = new Uint8Array(buffer.slice(12, length));
    const tag = new Uint8Array(buffer.slice(length - 16, length));
    const nonce = new Uint8Array(buffer.slice(0, 12));
    return [data, tag, nonce] as const;
  }

  randomBytes(length: number) {
    return this.crypto.getRandomValues(new Uint8Array(length));
  }

  async sha256(message: string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await this.crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((byte) => byte.toString(16).padStart(2, "0")).join("");
    return hashHex;
  }

  hasSecret(consumer: string) {
    return this.keyMap.get(`${consumer}SCR`) ? true : false;
  }

  base64ToArrayBuffer(base64: string) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  arrayBufferToBase64(buffer: ArrayBuffer) {
    let binaryString = "";
    const bytes = new Uint8Array(buffer);
    for (const byte of bytes) {
      binaryString += String.fromCharCode(byte);
    }
    return btoa(binaryString);
  }

  async setSecretSalt(consumer: string, salt: ArrayBufferLike) {
    const secret = this.keyMap.get(`${consumer}SCR`);
    if (!secret) {
      return;
    }
    const oldKey = await this.crypto.subtle.exportKey("raw", secret);
    const bufferSource = new Uint8Array(oldKey);
    const keyMaterial = await this.crypto.subtle.importKey(
      "raw",
      bufferSource,
      { name: "HKDF" },
      false,
      ["deriveKey"]
    );

    const newSecret = await this.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: { name: "SHA-256" },
        salt: salt,
        info: salt
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    this.keyMap.set(`${consumer}SCR`, newSecret);

    return newSecret;
  }

  async generateKey(consumer: Consumer) {
    const keys = await this.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      ["deriveKey"]
    );
    this.storeKeys(consumer, keys);
  }

  async exportKey(consumer: Consumer) {
    const publicKey = this.keyMap.get(`${consumer}PBL`);
    if (!publicKey) {
      throw new Error("KeyOwner has not public key");
    }
    return await this.crypto.subtle.exportKey("spki", publicKey);
  }

  async importPublicKey(publicKeyData: BufferSource, consumer: Consumer) {
    const consumerPublicKey = this.keyMap.get(`${consumer}PBL`);
    if (!consumerPublicKey) {
      throw new Error("public key not found");
    }

    const consumerPrivateKey = this.keyMap.get(`${consumer}PRV`);
    if (!consumerPrivateKey) {
      throw new Error("private key not found");
    }

    const publicKey = await this.crypto.subtle.importKey(
      "spki",
      publicKeyData,
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      false,
      []
    );

    const derivedKey = await this.crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey
      },
      consumerPrivateKey,
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );

    this.keyMap.set(`${consumer}SCR`, derivedKey);

    return derivedKey;
  }

  async encrypt(data: string, consumer: Consumer, b64: true): Promise<string>;
  async encrypt(data: string, consumer?: Consumer, b64?: false): Promise<EncryptionTuple>;
  async encrypt(
    data: string,
    consumer: Consumer = "server",
    b64?: boolean
  ): Promise<string | EncryptionTuple> {
    const secret = this.keyMap.get(`${consumer}SCR`);
    if (!secret) {
      throw new Error("secret key not found");
    }

    const encoded = this.encodeMessage(data);
    const iv = this.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await this.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      secret,
      encoded
    );

    if (b64) {
      return this.arrayBufferToBase64(this.mergeBuffers(iv, ciphertext));
    }

    return [ciphertext, iv];
  }

  async decryptBuffer(
    buffer: ArrayBuffer,
    jsonParse?: boolean,
    sender?: string
  ): Promise<Record<string, unknown> | string> {
    const [data, tag, nonce] = this.prepareBuffer(buffer);
    const rawPayload = await this.decrypt(data, tag, nonce, sender ?? "server");
    if (jsonParse) {
      return JSON.parse(rawPayload) as Record<string, unknown>;
    }
    return rawPayload;
  }

  async decrypt(data: BufferSource, _tag: BufferSource, nonce: BufferSource, consumer: Consumer) {
    const secret = this.keyMap.get(`${consumer}SCR`);
    if (!secret) {
      throw new Error("secret key not found");
    }
    const decrypted = (await this.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      secret,
      data
    )) as BufferSource;
    const decoder = new TextDecoder();
    const result = decoder.decode(decrypted);
    return result;
  }
}
