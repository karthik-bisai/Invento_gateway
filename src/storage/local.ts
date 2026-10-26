import { mkdirSync } from 'node:fs'
import { mkdir, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { keyFromUrl } from './keys.js'
import type { Storage } from './types.js'

export class LocalStorage implements Storage {
  private root: string

  constructor(
    dir: string,
    private baseUrl: string,
    private keyPrefix = 'avatars/',
  ) {
    this.root = path.resolve(dir)
    mkdirSync(this.root, { recursive: true }) // the static file route needs the folder to exist before the first upload
  }

  get directory() {
    return this.root
  }

  private resolve(key: string) {
    const full = path.resolve(this.root, key)
    if (full !== this.root && !full.startsWith(this.root + path.sep)) throw new Error('Refusing to write outside the media directory')
    return full
  }

  async put(key: string, data: Buffer): Promise<string> {
    const file = this.resolve(key)
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, data)
    return `${this.baseUrl}${key}`
  }

  async deleteByUrl(url: string): Promise<void> {
    const key = keyFromUrl(url, this.baseUrl, this.keyPrefix)
    if (!key) return
    try {
      await unlink(this.resolve(key))
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
    }
  }
}
