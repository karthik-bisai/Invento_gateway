import type { Config } from '../config.js'
import { LocalStorage } from './local.js'
import { S3Storage } from './s3.js'
import type { Storage } from './types.js'

export type { Storage } from './types.js'
export { LocalStorage } from './local.js'
export { S3Storage } from './s3.js'
export { sniffImage } from './image.js'

export function createStorage(cfg: Config): Storage {
  return cfg.storage.driver === 's3' ? S3Storage.fromConfig(cfg) : new LocalStorage(cfg.storage.mediaDir, cfg.storage.mediaPublicUrl)
}

/** Prefix every avatar key lives under, for whichever driver is active. */
export function avatarPrefix(cfg: Config): string {
  return cfg.storage.driver === 's3' ? cfg.storage.s3.keyPrefix : 'avatars/'
}
