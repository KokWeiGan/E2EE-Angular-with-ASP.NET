import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { lastValueFrom } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {
  private publicKey: CryptoKey | null = null;

  constructor(private http: HttpClient) { }

  // Fetch and import the public key, then return both PEM and imported key
  public async fetchPublicKey(): Promise<{ publicKeyPem: string, publicKey: CryptoKey | null }> {
    try {
      // Fetch public key from the server
      const response = await lastValueFrom(this.http.get<{ publicKey: string }>('/api/encryption/publickey'));

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
    const pemContents = pem.replace(new RegExp(`${pemHeader}|${pemFooter}|\\s+`, 'g'), '');

    // Convert PEM to ArrayBuffer
    const binaryDerString = this.base64ToBinaryString(pemContents);
    const binaryDer = this.str2ab(binaryDerString);

    // Import the public key
    return window.crypto.subtle.importKey(
      'spki',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' }, // Specify SHA-256 here
      },
      true,
      ['encrypt']
    );
  }

  private base64ToBinaryString(base64: string): string {
    // Decode base64 to binary string
    return window.atob(base64);
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
    if (!publicKey && !this.publicKey) {
      throw new Error('Public key not loaded');
    }

    const keyToUse = publicKey || this.publicKey;
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    try {
      const encryptedData = await window.crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
        },
        keyToUse!,
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

  public async sendDataToServer(data: any): Promise<any> {
    if (!this.publicKey) {
      console.error('Public key is not loaded');
      return;
    }

    try {
      const encryptedData = await this.encryptData(JSON.stringify(data));
      const response = await lastValueFrom(this.http.post<any>('/api/encryption/decrypt', { data: encryptedData }));
      console.log('Data sent to server');
      return response; // Return the server's response
    } catch (error) {
      console.error('Failed to send encrypted data', error);
      throw error; // Propagate the error
    }
  }
}
