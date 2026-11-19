/** Small explicit building blocks. Apply these at the correct trust boundary. */
export function textOnly(element,value) {element.textContent=String(value);}
export function parseObject(input,maxBytes=65536) {
 if(typeof input!=='string'||new TextEncoder().encode(input).length>maxBytes) throw new TypeError('Invalid JSON size');
 const value=JSON.parse(input);
 if(!value||typeof value!=='object'||Array.isArray(value)) throw new TypeError('Expected JSON object');
 for(const key of Object.keys(value)) if(['__proto__','prototype','constructor'].includes(key)) throw new TypeError('Forbidden key');
 return value;
}
export function allowedHttpsUrl(input,allowedOrigins) {
 const url=new URL(input);
 if(url.protocol!=='https:'||url.username||url.password||!allowedOrigins.includes(url.origin)) throw new TypeError('URL not allowed');
 return url.href;
}
export function integerId(value) {
 if(typeof value!=='string'||!/^\d{1,9}$/.test(value)) throw new TypeError('Expected numeric ID');
 return Number(value);
}
