import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3'
import type { Config } from '../config.js'
import { keyFromUrl } from './keys.js'
import type { Storage } from './types.js'

/** The slice of the AWS client we use, so tests can substitute a fake. */
export interface S3Like {
  send(command: PutObjectCommand | DeleteObjectCommand): Promise<unknown>
}

export class S3Storage implements Storage {
  constructor(
    private client: S3Like,
    private bucket: string,
    /** Public base URL for objects (the bucket's website or CDN address), ending in `/`. */
    private baseUrl: string,
    private keyPrefix: string,
  ) {}

  static fromConfig(cfg: Config): S3Storage {
    const { s3 } = cfg.storage
    const client = new S3Client({
      region: s3.region,
      endpoint: s3.endpoint,
      forcePathStyle: s3.forcePathStyle,
      // With no explicit keys the SDK uses its default chain (IAM role, env, shared config): preferred on AWS.
      credentials: s3.accessKeyId && s3.secretAccessKey ? { accessKeyId: s3.accessKeyId, secretAccessKey: s3.secretAccessKey } : undefined,
    })
    return new S3Storage(client, s3.bucket as string, cfg.storage.mediaPublicUrl, s3.keyPrefix)
  }

  async put(key: string, data: Buffer, contentType: string): Promise<string> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: data,
        ContentType: contentType,
        // Keys are unique per upload, so an object never changes under its URL.
        CacheControl: 'public, max-age=31536000, immutable',
      }),
    )
    return `${this.baseUrl}${key}`
  }

  async deleteByUrl(url: string): Promise<void> {
    const key = keyFromUrl(url, this.baseUrl, this.keyPrefix)
    if (!key) return
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }))
  }
}
