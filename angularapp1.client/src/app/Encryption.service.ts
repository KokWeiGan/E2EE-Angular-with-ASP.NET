import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {
  private publicKey: CryptoKey | null = null;

  constructor(private http: HttpClient) {
  }

  // Fetch and import the public key, then return both PEM and imported key
  public async fetchPublicKey(): Promise<{ publicKeyPem: string, publicKey: CryptoKey | null }> {
    try {
      // Fetch public key from the server
      const response = await this.http.get<{ publicKey: string }>('https://localhost:7263/api/encryption/publickey').toPromise();

      // Check if response is not undefined and has the expected property
      if (response && response.publicKey) {
        const publicKeyPem = response.publicKey;
        this.publicKey = await this.importPublicKey(publicKeyPem);
        console.log('Public Key imported');
        return { publicKeyPem, publicKey: this.publicKey };
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Failed to fetch or import public key', error);
      return { publicKeyPem: '', publicKey: null }; // Return empty values in case of an error
    }
  }

  private async importPublicKey(pem: string): Promise<CryptoKey> {
    // Remove the header and footer from the PEM string
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.replace(new RegExp(`-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+`, 'g'), '');

    // Convert PEM to ArrayBuffer
    const binaryDerString = this.base64ToBinaryString(pemContents);
    const binaryDer = this.str2ab(binaryDerString);

    // Import the public key
    return window.crypto.subtle.importKey(
      'spki',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' },
      },
      true,
      ['encrypt']
    );
  }

  private base64ToBinaryString(base64: string): string {
    // Decode base64 to binary string
    const binaryString = window.atob(base64);
    return binaryString;
  }

  private str2ab(str: string): ArrayBuffer {
    const buf = new ArrayBuffer(str.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
      view[i] = str.charCodeAt(i);
    }
    return buf;
  }

  public async encryptData(data: string, publicKey: CryptoKey | null = null): Promise<string> {
    if (!publicKey) {
      throw new Error('Public key not loaded');
    }

    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    try {
      const encryptedData = await window.crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
        },
        publicKey,
        encodedData
      );

      return this.arrayBufferToBase64(encryptedData);
    } catch (error) {
      console.error('Encryption failed', error);
      throw error;
    }
  }
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }


  public async sendDataToServer(data: any, publicKey: CryptoKey | null): Promise<any> {
    if (!publicKey) {
      console.error('Public key is not provided');
      return;
    }

    try {
      const encryptedData = await this.encryptData(JSON.stringify(data), publicKey);
      const response = await this.http.post<any>('https://localhost:7263/api/encryption/decrypt', { data: encryptedData }).toPromise();
      console.log('Data sent to server');
      return response; // Return the server's response
    } catch (error) {
      console.error('Failed to send encrypted data', error);
      throw error; // Propagate the error
    }
  }
}

// Helper functions
function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    view[i] = str.charCodeAt(i);
  }
  return buf;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const uint8Array = new Uint8Array(buffer);
  let binary = '';
  uint8Array.forEach((byte) => binary += String.fromCharCode(byte));
  return window.btoa(binary);
}
