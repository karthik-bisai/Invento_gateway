import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { asUser, type Ctx, parse, relay, requireSession, uuidSchema } from '../context.js'

const approveBody = z.object({ role: z.enum(['ADMIN', 'INVENTORY_MANAGER', 'WAREHOUSE_STAFF']).optional() })
const rejectBody = z.object({ note: z.string().max(500).nullish() })

interface Decided {
  note?: string | null
  user: { email: string; full_name?: string | null }
}

/**
 * Admin decisions on access requests. The API records the decision and writes the in-app notification;
 * the gateway then emails the applicant, so the outcome reaches them even if they never reopen the app.
 */
export async function accessRoutes(app: FastifyInstance, ctx: Ctx) {
  const guard = { preHandler: requireSession(ctx) }

  for (const action of ['approve', 'reject'] as const) {
    app.post(`/access-requests/:id/${action}`, guard, async (req, reply) => {
      const { id } = parse(z.object({ id: uuidSchema }), req.params)
      const body = action === 'approve' ? parse(approveBody, req.body) : parse(rejectBody, req.body)
      const res = await asUser(ctx, req, { method: 'POST', path: `/access-requests/${id}/${action}`, body })
      if (res.status === 200) {
        const decided = res.json<Decided>()
        if (decided) void ctx.notifier.accessDecided(decided.user, action === 'approve' ? 'approved' : 'rejected', decided.note ?? null)
      }
      return relay(reply, res)
    })
  }
}
