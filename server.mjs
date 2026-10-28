import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb);
const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(root, 'data');
const dbPath = path.join(dataDir, 'store.sqlite');
const port = Number(process.env.PORT || 3001);
await mkdir(dataDir, { recursive: true });
const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, address_json TEXT NOT NULL DEFAULT "{}", created_at TEXT NOT NULL)');
db.exec('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL)');
db.exec('CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, items_json TEXT NOT NULL, subtotal REAL NOT NULL, shipping REAL NOT NULL, tax REAL NOT NULL, total REAL NOT NULL, payment_option TEXT NOT NULL, address_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT "placed")');

const products = [
{id:'bottle',name:'Everyday Reusable Bottle',price:28,category:'Kitchen'},
{id:'candle',name:'Slow Morning Soy Candle',price:24,category:'Home & living'},
{id:'face-oil',name:'Daily Ritual Face Oil',price:32,category:'Beauty'},
{id:'tote',name:'Market Day Cotton Tote',price:18,category:'Home & living'},
{id:'linen',name:'Soft Weekend Linen Throw',price:46,category:'Home & living'},
{id:'mug',name:'Earthware Morning Mug',price:22,category:'Kitchen'},
{id:'soap',name:'Botanical Hand & Body Soap',price:16,category:'Beauty'},
{id:'trail',name:'Trail Day Pack',price:54,category:'Outdoors'},
{id:'yoga',name:'Grounded Everyday Yoga Mat',price:42,category:'Wellness'},
{id:'planter',name:'Stoneware Leaf Planter',price:30,category:'Home & living'},
{id:'basket',name:'Woven Storage Basket',price:38,category:'Home & living'}
];
const allowedOrigins = new Set(['null', 'http://localhost:3001', 'http://127.0.0.1:3001']);
function send(res, status, data, origin='') {
  const headers = {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET, POST, OPTIONS'};
  if (allowedOrigins.has(origin)) headers['Access-Control-Allow-Origin'] = origin;
  res.writeHead(status, headers); res.end(JSON.stringify(data));
}
async function readBody(req) {
  let raw='';
  for await (const chunk of req) { raw += chunk; if (raw.length > 1_000_000) throw new Error('Request too large'); }
  return raw ? JSON.parse(raw) : {};
}
function bearer(req) { const value=req.headers.authorization||''; return value.startsWith('Bearer ')?value.slice(7):''; }
function tokenHash(token) { return createHash('sha256').update(token).digest('hex'); }
function currentUser(req) {
  const token=bearer(req); if (!token) return null;
  const row=db.prepare('SELECT u.id,u.name,u.email,u.address_json FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(tokenHash(token),new Date().toISOString());
  if (!row) return null;
  return {id:row.id,name:row.name,email:row.email,address:JSON.parse(row.address_json||'{}')};
}
async function createSession(userId) {
  const token=randomBytes(32).toString('base64url'), expires=new Date(Date.now()+30*24*60*60*1000).toISOString();
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(tokenHash(token),userId,expires);
  return {token,expiresAt:expires};
}
function safeUser(user) { return {id:user.id,name:user.name,email:user.email,address:user.address}; }
async function auth(req, res, origin) {
  const user=currentUser(req);
  if (!user) { send(res,401,{error:'Please sign in to continue.'},origin); return null; }
  return user;
}
const server=http.createServer(async(req,res)=>{
  const origin=req.headers.origin||'';
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':allowedOrigins.has(origin)?origin:'null','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET, POST, OPTIONS'});return res.end();}
  try {
    const url=new URL(req.url,'http://localhost');
    if(req.method==='GET'&&url.pathname==='/api/health')return send(res,200,{ok:true,database:'sqlite'},origin);
    if(req.method==='GET'&&url.pathname==='/api/products'){const q=(url.searchParams.get('q')||'').toLowerCase();return send(res,200,products.filter(p=>(p.name+' '+p.category).toLowerCase().includes(q)),origin);}
    if(req.method==='POST'&&url.pathname==='/api/register'){
      const {name,email,password}=await readBody(req),cleanName=String(name||'').trim(),cleanEmail=String(email||'').trim().toLowerCase();
      if(cleanName.length<1||cleanName.length>100||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)||typeof password!=='string'||password.length<8)return send(res,400,{error:'Enter a name, valid email, and password of at least 8 characters.'},origin);
      const salt=randomBytes(16).toString('hex'),hash=(await scrypt(password,salt,64)).toString('hex');
      let result;try{result=db.prepare('INSERT INTO users(name,email,password_salt,password_hash,created_at) VALUES(?,?,?,?,?)').run(cleanName,cleanEmail,salt,hash,new Date().toISOString())}catch{return send(res,409,{error:'An account with that email already exists. Sign in instead.'},origin)}
      const user={id:Number(result.lastInsertRowid),name:cleanName,email:cleanEmail,address:{}},session=await createSession(user.id);
      return send(res,201,{user:safeUser(user),...session},origin);
    }
    if(req.method==='POST'&&url.pathname==='/api/login'){
      const {email,password}=await readBody(req),cleanEmail=String(email||'').trim().toLowerCase(),row=db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);
      if(!row||typeof password!=='string')return send(res,401,{error:'Email or password is incorrect.'},origin);
      const hash=await scrypt(password,row.password_salt,64),stored=Buffer.from(row.password_hash,'hex');
      if(hash.length!==stored.length||!timingSafeEqual(hash,stored))return send(res,401,{error:'Email or password is incorrect.'},origin);
      const user={id:row.id,name:row.name,email:row.email,address:JSON.parse(row.address_json||'{}')},session=await createSession(user.id);
      return send(res,200,{user:safeUser(user),...session},origin);
    }
    if(req.method==='GET'&&url.pathname==='/api/me'){
      const user=await auth(req,res,origin);if(!user)return;
      return send(res,200,{user:safeUser(user)},origin);
    }
    if(req.method==='POST'&&url.pathname==='/api/logout'){
      const token=bearer(req);if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(token));
      return send(res,200,{ok:true},origin);
    }
    if(req.method==='POST'&&url.pathname==='/api/address'){
      const user=await auth(req,res,origin);if(!user)return;
      const a=await readBody(req),address={recipient:String(a.recipient||'').trim(),street:String(a.street||'').trim(),city:String(a.city||'').trim(),zip:String(a.zip||'').trim()};
      if(Object.values(address).some(v=>!v)||Object.values(address).some(v=>v.length>160))return send(res,400,{error:'Complete each delivery address field.'},origin);
      db.prepare('UPDATE users SET address_json=? WHERE id=?').run(JSON.stringify(address),user.id);
      return send(res,200,{address},origin);
    }
    if(req.method==='GET'&&url.pathname==='/api/orders'){
      const user=await auth(req,res,origin);if(!user)return;
      const orders=db.prepare('SELECT id,created_at AS createdAt,items_json AS items,subtotal,shipping,tax,total,payment_option AS paymentOption,address_json AS address,status FROM orders WHERE user_id=? ORDER BY created_at DESC').all(user.id);
      return send(res,200,orders.map(o=>({...o,items:JSON.parse(o.items),address:JSON.parse(o.address)})),origin);
    }
    if(req.method==='POST'&&url.pathname==='/api/checkout'){
      const user=await auth(req,res,origin);if(!user)return;
      const {items,paymentOption}=await readBody(req);
      if(!Array.isArray(items)||!items.length||items.length>100)return send(res,400,{error:'Your basket is empty or invalid.'},origin);
      if(!['card_demo','pay_on_delivery'].includes(paymentOption))return send(res,400,{error:'Choose a payment option.'},origin);
      const clean=items.map(item=>{const p=products.find(x=>x.id===item.productId),quantity=Number(item.quantity);return p&&Number.isInteger(quantity)&&quantity>0&&quantity<=99?{productId:p.id,name:p.name,unitPrice:p.price,quantity,lineTotal:p.price*quantity}:null;});
      if(clean.some(x=>!x))return send(res,400,{error:'One or more products are invalid.'},origin);
      const address=user.address;
      if(!address.recipient||!address.street||!address.city||!address.zip)return send(res,400,{error:'Add a delivery address before checkout.'},origin);
      const subtotal=clean.reduce((n,x)=>n+x.lineTotal,0),shipping=subtotal>=50?0:6,tax=Math.round(subtotal*.08*100)/100,total=subtotal+shipping+tax,id=randomUUID(),createdAt=new Date().toISOString();
      db.prepare('INSERT INTO orders(id,user_id,created_at,items_json,subtotal,shipping,tax,total,payment_option,address_json,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id,user.id,createdAt,JSON.stringify(clean),subtotal,shipping,tax,total,paymentOption,JSON.stringify(address),'placed');
      return send(res,201,{id,createdAt,items:clean,subtotal,shipping,tax,total,paymentOption,address,status:'placed'},origin);
    }
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){const html=await readFile(path.join(root,'index.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(html);}
    if(req.method==='GET'&&url.pathname==='/storefront.js'){const js=await readFile(path.join(root,'storefront.js'));res.writeHead(200,{'Content-Type':'text/javascript; charset=utf-8'});return res.end(js);}
    if(req.method==='GET'&&url.pathname==='/storefront-actions.js'){const js=await readFile(path.join(root,'storefront-actions.js'));res.writeHead(200,{'Content-Type':'text/javascript; charset=utf-8'});return res.end(js);}
    send(res,404,{error:'Not found.'},origin);
  } catch(error) { console.error(error); send(res,error instanceof SyntaxError?400:500,{error:error instanceof SyntaxError?'Invalid JSON.':'Something went wrong.'},req.headers.origin||'');}
});
server.listen(port,()=>console.log('Grove database storefront running at http://localhost:'+port+' (SQLite: '+dbPath+')'));



