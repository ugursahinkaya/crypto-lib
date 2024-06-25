export type CryptoKeyPair = CryptoKeyPair & {
  secret?: CryptoKey;
  jwk?: string;
};
export type LiteralUnion<T extends U, U = string> = T | (U & Record<never, never>);
export type KeyOwner = LiteralUnion<'server', string>;
export type EncryptionTuple = [ciphertext: ArrayBuffer, iv: Uint8Array];
export class CryptoLib {
  keys: { [key in KeyOwner]?: CryptoKeyPair } = {};

  protected crypto: Crypto;
  protected encodeMessage(message: string) {
    const encoder = new TextEncoder();
    return encoder.encode(message);
  }

  protected mergeBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
    const result = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    result.set(new Uint8Array(buffer1), 0);
    result.set(new Uint8Array(buffer2), buffer1.byteLength);
    return result.buffer;
  }

  protected prepareBuffer(buffer: ArrayBufferLike) {
    const length = buffer.byteLength;
    const data = new Uint8Array(buffer.slice(12, length));
    const tag = new Uint8Array(buffer.slice(length - 16, length));
    const nonce = new Uint8Array(buffer.slice(0, 12));
    return [data, tag, nonce] as const;
  }
  constructor(crypto?: Crypto) {
    if (!crypto) {
      throw new Error('Provide a Web Crypto API implementation');
    }
    this.crypto = crypto;
  }

  randomString() {
    return Math.random().toString(36).substring(2, 15);
  }
  randomBytes(length: number) {
    return this.crypto.getRandomValues(new Uint8Array(length));
  }

  async sha256(message: string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await this.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((byte) => byte.toString(16).padStart(2, '0')).join('');
    return hashHex;
  }

  hasSecret(receiver: string) {
    return this.keys[receiver] && this.keys[receiver]?.secret;
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
    let binaryString = '';
    const bytes = new Uint8Array(buffer);
    for (const byte of bytes) {
      binaryString += String.fromCharCode(byte);
    }
    return btoa(binaryString);
  }

  async setSecretSalt(receiver: string, salt: ArrayBufferLike) {
    const keys = this.keys[receiver];
    if (!keys || !keys.secret) {
      return;
    }
    const oldKey = await this.crypto.subtle.exportKey('raw', keys.secret);
    const bufferSource = new Uint8Array(oldKey);
    const keyMaterial = await this.crypto.subtle.importKey(
      'raw',
      bufferSource,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    keys.secret = await this.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: { name: 'SHA-256' },
        salt: salt,
        info: salt
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    return keys.secret;
  }

  async generateKey(receiver: KeyOwner) {
    const keys = await this.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey']
    );

    this.keys[receiver] = keys;
  }

  async exportKey(receiver: KeyOwner) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return await this.crypto.subtle.exportKey('spki', this.keys[receiver]!.publicKey);
  }

  async importPublicKey(publicKeyData: BufferSource, receiver: KeyOwner) {
    const publicKey = await this.crypto.subtle.importKey(
      'spki',
      publicKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      false,
      []
    );
    const keys = this.keys[receiver];
    if (!keys) {
      throw new Error(
        'No key pair found for receiver, generate one first by calling "generateKey"'
      );
    }

    const derivedKey = await this.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: publicKey
      },
      keys.privateKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
    keys.secret = derivedKey;

    const exported: JsonWebKey = await this.crypto.subtle.exportKey('jwk', derivedKey);
    keys.jwk = JSON.stringify(exported);

    return derivedKey;
  }

  async importJwk(jwk: JsonWebKey, user: KeyOwner): Promise<boolean> {
    const secret = await this.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'AES-GCM'
      },
      false,
      ['encrypt', 'decrypt']
    );

    // ?
    if (user === 'server') {
      if (this.keys.server === undefined) {
        await this.generateKey('server');
      }

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      this.keys.server!.secret = secret;

      return true;
    }

    if (this.keys[user] === undefined) {
      this.keys[user] = {} as CryptoKeyPair;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    this.keys[user]!.secret = secret;

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    this.keys[user]!.jwk = JSON.stringify(jwk);

    return false;
  }

  async encrypt(data: string, receiver: KeyOwner, b64: true): Promise<string>;
  async encrypt(data: string, receiver?: KeyOwner, b64?: false): Promise<EncryptionTuple>;
  async encrypt(
    data: string,
    receiver: KeyOwner = 'server',
    b64?: boolean
  ): Promise<string | EncryptionTuple> {
    const { secret } = this.keys[receiver] as CryptoKeyPair;
    if (secret === undefined) {
      return data;
    }

    const encoded = this.encodeMessage(data);
    const iv = this.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await this.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
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
    const rawPayload = await this.decrypt(data, tag, nonce, sender ?? 'server');
    if (jsonParse) {
      return JSON.parse(rawPayload) as Record<string, unknown>;
    }
    return rawPayload;
  }

  async decrypt(data: BufferSource, _tag: BufferSource, nonce: BufferSource, receiver: KeyOwner) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const secret = this.keys[receiver]!.secret!;
    const decrypted = (await this.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
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
