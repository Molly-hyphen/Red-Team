# Security Skill: Business Logic & Workflow Vulnerabilities

## Objectives
- Test multi-step transaction integrity, quantity tampering, price parameter overriding, and race conditions.

## Testing Methodology
1. Modify pricing fields (e.g. `price: -100` or `quantity: 0`).
2. Skip sequential checkout steps (calling `/api/order/complete` without `/api/order/pay`).
3. Test concurrent coupon or redemption claims.
