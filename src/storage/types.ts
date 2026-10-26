/** Where uploaded files live. Local disk in development; S3 (or any S3-compatible bucket) in deployment. */
export interface Storage {
  /** Save and return the public URL. */
  put(key: string, data: Buffer, contentType: string): Promise<string>
  /** Remove a file by its public URL. Ignores URLs that aren't ours and files that are already gone. */
  deleteByUrl(url: string): Promise<void>
}
