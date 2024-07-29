import { Component, OnInit } from '@angular/core';
import { EncryptionService } from './Encryption.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  password: string = ''; // Randomly generated password
  publicKeyPem: string = ''; // PEM format of the public key
  encryptedData: string = ''; // Holds the encrypted data
  publicKey: CryptoKey | null = null; // Holds the public key object
  decryptedData: string = ''; // Holds the decrypted data returned from the server
  clickCount: number = 0; // Counter for the number of button clicks
  isLoading: boolean = false; // Loading state
  errorMessage: string = ''; // Error message

  constructor(private encryptionService: EncryptionService) { }

  async ngOnInit() {
    await this.updatePublicKey();
  }

  private async updatePublicKey() {
    this.isLoading = true; // Show loading indicator
    try {
      const { publicKeyPem, publicKey } = await this.encryptionService.fetchPublicKey();
      this.publicKeyPem = publicKeyPem;
      this.publicKey = publicKey;

      // Generate a random password
      this.password = this.generateRandomPassword(12);

      // Encrypt the password using the fetched public key
      this.encryptedData = await this.encryptionService.encryptData(this.password, this.publicKey);

      console.log('Public Key PEM:', this.publicKeyPem);
      console.log('Encrypted Data:', this.encryptedData);
    } catch (error) {
      this.errorMessage = 'Failed to fetch public key or encrypt data';
      console.error(this.errorMessage, error);
    } finally {
      this.isLoading = false; // Hide loading indicator
    }
  }

  private generateRandomPassword(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }
    return password;
  }

  async sendEncryptedData() {
    this.clickCount++;
    this.isLoading = true; // Show loading indicator
    try {
      if (this.publicKey) {
        // Re-encrypt the data if necessary
        const encryptedData = await this.encryptionService.encryptData(this.password, this.publicKey);
        this.encryptedData = encryptedData; // Update the encrypted data

        const result = await this.encryptionService.sendDataToServer(this.password);
        this.decryptedData = result.decryptedData;
        console.log('Decrypted Data:', this.decryptedData);
      } else {
        this.errorMessage = 'Public key is not available for encryption';
      }
    } catch (error) {
      this.errorMessage = 'Failed to send encrypted data';
      console.error(this.errorMessage, error);
    } finally {
      this.isLoading = false; // Hide loading indicator
      this.password = this.generateRandomPassword(12);
    }
  }
}
