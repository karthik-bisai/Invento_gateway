export interface ImageKind {
  ext: 'png' | 'jpg' | 'webp'
  contentType: 'image/png' | 'image/jpeg' | 'image/webp'
}

/**
 * Identify an image from its first bytes rather than trusting the filename or the client's content type.
 * Only PNG, JPEG and WebP are accepted: no SVG (can carry script) and no GIF.
 */
export function sniffImage(buf: Buffer): ImageKind | null {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return { ext: 'png', contentType: 'image/png' }
  }
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { ext: 'jpg', contentType: 'image/jpeg' }
  }
  if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') {
    return { ext: 'webp', contentType: 'image/webp' }
  }
  return null
}
