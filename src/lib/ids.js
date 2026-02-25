import crypto from 'node:crypto';

export function makeId(prefix) {
  const token = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
  return `${prefix}_${token}`;
}
