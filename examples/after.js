// Illustrative application boundary. DB driver, DOM element and request are supplied by the app.
import { parseObject, integerId, textOnly } from '../src/defense.mjs';
export async function profileView({input, requestId, db, element}) {
 const profile = parseObject(input);
 if(typeof profile.name !== 'string' || profile.name.length > 120) throw new TypeError('Invalid name');
 const id = integerId(requestId);
 const result = await db.query('SELECT display_name FROM users WHERE id = $1', [id]);
 textOnly(element, profile.name);
 return result;
}
