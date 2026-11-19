// Manual remediation. The scanner does not rewrite the source.
import { parseObject, integerId, textOnly } from '../src/defense.mjs';
export async function profile(input, db, element) {
 const data = parseObject(input);
 const id = integerId(data.id);
 if (typeof data.name !== 'string' || data.name.length > 120) throw new TypeError('Invalid name');
 const rows = await db.query('SELECT display_name FROM users WHERE id=$1', [id]);
 textOnly(element, data.name);
 return rows;
}
