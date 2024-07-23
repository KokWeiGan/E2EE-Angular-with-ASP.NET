declare module 'crypto-browserify' {
  export function publicEncrypt(publicKey: string | Buffer, buffer: Buffer): Buffer;
}
