// Teaching fixture: source text only. Never execute this vulnerable example.
export async function profile(input, db, element) {
 const data = eval(input);
 const rows = await db.query(`SELECT display_name FROM users WHERE id=${data.id}`);
 element.innerHTML = data.name;
 return rows;
}
