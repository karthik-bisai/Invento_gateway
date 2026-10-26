# Invento gateway

The only service the browser talks to: sessions in an HTTP-only cookie, CSRF protection, email codes (sign-up, sign-in, password reset), rate limits, email, profile-picture uploads, and a proxy to the private FastAPI service. Node 20.12+, Fastify, TypeScript.

```
npm install
npm run dev          # http://localhost:4000 (reads .env; every value has a development default)
npm test
npm run typecheck
npm run build && npm start
npm run mail:test -- you@example.com     # prove the SMTP settings work
```

Start the whole system (with Postgres and Redis) from the `backend/` repository: `python run.py --all`. Settings are documented in [.env.example](.env.example); production environment notes are in the backend README under "Handing over for deployment".

This repository has no Dockerfile on purpose: the deployment team adds it.
