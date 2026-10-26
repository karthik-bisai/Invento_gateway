/** The object key behind one of our URLs, or null if it isn't under `base`, lacks `requiredPrefix`, or tries to escape. */
export function keyFromUrl(url: string, base: string, requiredPrefix: string): string | null {
  if (!url.startsWith(base)) return null
  const key = url.slice(base.length)
  if (!key.startsWith(requiredPrefix) || key.includes('..') || key.includes('\\') || key.includes('//')) return null
  return key
}
