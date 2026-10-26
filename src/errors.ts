/** An error that maps straight onto an HTTP response in FastAPI's `{ detail }` shape, plus an optional machine code. */
export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public headers: Record<string, string> = {},
  ) {
    super(message)
  }
}
