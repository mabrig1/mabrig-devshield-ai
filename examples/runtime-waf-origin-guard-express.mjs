import crypto from 'node:crypto';

/**
 * Express middleware example for applications protected by DevShield Runtime WAF.
 *
 * Configure the same secret in:
 *   - the WAF Worker as ORIGIN_SHARED_SECRET
 *   - the origin application as DEVSHIELD_ORIGIN_SHARED_SECRET
 *
 * Put this middleware before application routes.
 */
export function requireDevShieldOrigin(req, res, next) {
  const expected = process.env.DEVSHIELD_ORIGIN_SHARED_SECRET || '';
  const supplied = String(req.get('x-devshield-origin-token') || '');

  if (!expected || !supplied || !constantTimeEqual(expected, supplied)) {
    res.status(403).json({ error: 'Direct origin access denied' });
    return;
  }

  next();
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
