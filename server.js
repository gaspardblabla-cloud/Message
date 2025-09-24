// SwiftTalk — Render PATCH: write data.json in /tmp (writable), robust logs
import fs from "fs";
import path from "path";
import http from "http";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { Server as SocketIOServer } from "socket.io";
import { v4 as uuidv4 } from "uuid";
import { fileURLToPath } from "url";

// ---------- Setup ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Render expects binding on provided PORT and 0.0.0.0
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

// Use /tmp for writable storage on Render (or DATA_DIR env to override)
const DATA_DIR = process.env.DATA_DIR || "/tmp";
const DATA_FILE = path.join(DATA_DIR, "swifttalk-data.json");

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// Ensure data dir exists
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

// ---------- Data Store JSON ----------
class DataStore {
  constructor(file) {
    this.file = file;
    this.data = { users: [], rooms: [], room_members: [], messages: [] };
    this.load();
  }
  load() {
    try {
      if (fs.existsSync(this.file)) {
        const raw = fs.readFileSync(this.file, "utf-8");
        this.data = JSON.parse(raw || "{}");
        if (!this.data.users) this.data = { users: [], rooms: [], room_members: [], messages: [] };
      } else {
        this.save();
      }
      console.log("[DataStore] Loaded from", this.file);
    } catch (e) {
      console.error("[DataStore] Load error:", e);
      this.save();
    }
  }
  save() {
    try {
      const tmp = this.file + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), "utf-8");
      fs.renameSync(tmp, this.file);
    } catch (e) {
      console.error("[DataStore] Save error:", e);
    }
  }
  // Users
  getUserByEmail(email){ return this.data.users.find(u=>u.email===email)||null; }
  getUserByUsername(username){ return this.data.users.find(u=>u.username===username)||null; }
  getUserById(id){ return this.data.users.find(u=>u.id===id)||null; }
  insertUser(u){ this.data.users.push(u); this.save(); return u; }
  searchUsers(q){
    const Q = q.toLowerCase();
    return this.data.users.filter(u=>u.username.toLowerCase().includes(Q)||u.email.toLowerCase().includes(Q))
      .slice(0,15).map(u=>({id:u.id,email:u.email,username:u.username,created_at:u.created_at}));
  }
  // Rooms
  insertRoom(r){ this.data.rooms.push(r); this.save(); return r; }
  listPublicRooms(){
    return this.data.rooms.filter(r=>!!r.is_public).sort((a,b)=>b.created_at.localeCompare(a.created_at))
      .map(r=>({...r, creator_username:this.getUserById(r.created_by)?.username||"?"}));
  }
  listRoomsForUser(uid){
    const ids = new Set(this.data.room_members.filter(m=>m.user_id===uid).map(m=>m.room_id));
    return this.data.rooms.filter(r=>ids.has(r.id)).sort((a,b)=>b.created_at.localeCompare(a.created_at))
      .map(r=>({...r, creator_username:this.getUserById(r.created_by)?.username||"?"}));
  }
  joinRoom(uid, rid){
    const exists = this.data.room_members.find(m=>m.user_id===uid && m.room_id===rid);
    if(!exists){ this.data.room_members.push({user_id:uid, room_id:rid, joined_at:new Date().toISOString()}); this.save(); }
  }
  isMember(uid, rid){ return !!this.data.room_members.find(m=>m.user_id===uid && m.room_id===rid); }
  getRoom(rid){ return this.data.rooms.find(r=>r.id===rid)||null; }
  // Messages
  insertMessage(m){ this.data.messages.push(m); this.save(); return m; }
  getRoomMessages(rid, limit=100, offset=0){
    return this.data.messages.filter(m=>m.room_id===rid).sort((a,b)=>a.created_at.localeCompare(b.created_at))
      .slice(offset, offset+limit).map(m=>({...m, from_username:this.getUserById(m.from_user_id)?.username||"?", to_username:m.to_user_id? (this.getUserById(m.to_user_id)?.username||"?"):null }));
  }
  getDMs(a,b,limit=100,offset=0){
    const arr = this.data.messages.filter(m=>(m.from_user_id===a&&m.to_user_id===b)||(m.from_user_id===b&&m.to_user_id===a))
      .sort((x,y)=>x.created_at.localeCompare(y.created_at));
    return arr.slice(offset, offset+limit).map(m=>({...m, from_username:this.getUserById(m.from_user_id)?.username||"?", to_username:this.getUserById(m.to_user_id)?.username||"?" }));
  }
}
const store = new DataStore(DATA_FILE);

// ---------- App / Server ----------
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, { cors: { origin: "*" } });

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// Health for Render
app.get("/healthz", (_req,res)=>res.status(200).send("ok"));

// ---------- Helpers ----------
const nowISO = () => new Date().toISOString();
const toUserPublic = (u) => ({ id:u.id, email:u.email, username:u.username, created_at:u.created_at });
const signToken = (u) => jwt.sign({ uid:u.id, username:u.username, email:u.email }, JWT_SECRET, { expiresIn:"30d" });
function auth(req,res,next){
  const token = req.cookies?.token;
  if(!token) return res.status(401).json({ error:"Auth required" });
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); } catch{ return res.status(401).json({ error:"Invalid token" }); }
}

// ---------- AUTH ----------
app.post("/api/auth/register", async (req,res)=>{
  try{
    const { email, username, password } = req.body||{};
    if(!email||!username||!password) return res.status(400).json({ error:"email, username, password required" });
    if(store.getUserByEmail(email.trim().toLowerCase())) return res.status(400).json({ error:"Email déjà utilisé" });
    if(store.getUserByUsername(username.trim())) return res.status(400).json({ error:"Pseudo déjà pris" });
    const id = uuidv4();
    const pass_hash = await bcrypt.hash(password, 10);
    const user = { id, email:email.trim().toLowerCase(), username:username.trim(), pass_hash, created_at:nowISO() };
    store.insertUser(user);
    const token = signToken(user);
    res.cookie("token", token, { httpOnly:true, sameSite:"lax", maxAge:1000*60*60*24*30 });
    res.json({ user: toUserPublic(user) });
  }catch(e){ console.error("[register] error", e); res.status(500).json({ error:"Register failed" }); }
});

app.post("/api/auth/login", async (req,res)=>{
  const { emailOrUsername, password } = req.body||{};
  if(!emailOrUsername||!password) return res.status(400).json({ error:"emailOrUsername and password required" });
  let user = store.getUserByEmail(emailOrUsername.trim().toLowerCase());
  if(!user) user = store.getUserByUsername(emailOrUsername.trim());
  if(!user) return res.status(401).json({ error:"Invalid credentials" });
  const ok = await bcrypt.compare(password, user.pass_hash);
  if(!ok) return res.status(401).json({ error:"Invalid credentials" });
  const token = signToken(user);
  res.cookie("token", token, { httpOnly:true, sameSite:"lax", maxAge:1000*60*60*24*30 });
  res.json({ user: toUserPublic(user) });
});

app.post("/api/auth/logout", (_req,res)=>{ res.clearCookie("token"); res.json({ ok:true }); });
app.get("/api/me", auth, (req,res)=>{ const u = store.getUserById(req.user.uid); res.json({ user: toUserPublic(u) }); });

// ---------- USERS ----------
app.get("/api/users/search", auth, (req,res)=>{
  const q=(req.query.q||"").trim(); res.json({ users: q? store.searchUsers(q): [] });
});

// ---------- ROOMS ----------
app.get("/api/rooms/public", auth, (_req,res)=> res.json({ rooms: store.listPublicRooms() }));
app.get("/api/rooms/mine", auth, (req,res)=> res.json({ rooms: store.listRoomsForUser(req.user.uid) }));
app.post("/api/rooms", auth, (req,res)=>{
  const { name, is_public=true } = req.body||{};
  if(!name) return res.status(400).json({ error:"name required" });
  const room = { id:uuidv4(), name:String(name).trim(), is_public:!!is_public, created_by:req.user.uid, created_at:nowISO() };
  store.insertRoom(room); store.joinRoom(req.user.uid, room.id);
  res.json({ room });
});
app.post("/api/rooms/join", auth, (req,res)=>{
  const { room_id } = req.body||{};
  const room = store.getRoom(room_id); if(!room) return res.status(404).json({ error:"Room not found" });
  store.joinRoom(req.user.uid, room_id); res.json({ ok:true });
});

// ---------- MESSAGES ----------
app.get("/api/messages/room", auth, (req,res)=>{
  const { room_id, limit=100, offset=0 } = req.query;
  const room = store.getRoom(room_id); if(!room) return res.status(404).json({ error:"Room not found" });
  if(!room.is_public && !store.isMember(req.user.uid, room_id)) return res.status(403).json({ error:"Not a member" });
  res.json({ messages: store.getRoomMessages(room_id, Number(limit), Number(offset)) });
});
app.get("/api/messages/dm", auth, (req,res)=>{
  const { with_user_id, limit=100, offset=0 } = req.query;
  if(!with_user_id) return res.status(400).json({ error:"with_user_id required" });
  res.json({ messages: store.getDMs(req.user.uid, with_user_id, Number(limit), Number(offset)) });
});
app.post("/api/messages/send", auth, (req,res)=>{
  const { content, room_id, to_user_id } = req.body||{};
  if(!content || (!room_id && !to_user_id)) return res.status(400).json({ error:"content and (room_id or to_user_id) required" });
  if(room_id){
    const room = store.getRoom(room_id); if(!room) return res.status(404).json({ error:"Room not found" });
    if(!room.is_public && !store.isMember(req.user.uid, room_id)) return res.status(403).json({ error:"Not a member" });
  } else {
    const toUser = store.getUserById(to_user_id); if(!toUser) return res.status(404).json({ error:"Recipient not found" });
  }
  const message = { id:uuidv4(), room_id:room_id||null, from_user_id:req.user.uid, to_user_id:to_user_id||null, content:String(content).slice(0,5000), created_at:nowISO() };
  store.insertMessage(message);
  if(room_id) io.to(`room:${room_id}`).emit("message:new", message);
  else { io.to(`user:${to_user_id}`).emit("message:new", message); io.to(`user:${req.user.uid}`).emit("message:new", message); }
  res.json({ message });
});

// ---------- Socket.IO ----------
io.use((socket,next)=>{
  try{
    const cookie = socket.request.headers.cookie||"";
    const token = cookie.split(";").map(s=>s.trim()).find(s=>s.startsWith("token="))?.split("=")[1];
    if(!token) return next(new Error("Auth required"));
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch{ next(new Error("Invalid token")); }
});
io.on("connection",(socket)=>{
  const user = socket.user;
  socket.join(`user:${user.uid}`);
  socket.on("room:join", ({room_id})=>{ if(room_id) socket.join(`room:${room_id}`); });
  socket.on("room:leave", ({room_id})=>{ if(room_id) socket.leave(`room:${room_id}`); });
  socket.on("message:send", ({content,room_id,to_user_id})=>{
    if(!content || (!room_id && !to_user_id)) return;
    if(room_id){
      const room = store.getRoom(room_id); if(!room) return;
      if(!room.is_public && !store.isMember(user.uid, room_id)) return;
    } else { if(!store.getUserById(to_user_id)) return; }
    const msg = { id:uuidv4(), room_id:room_id||null, from_user_id:user.uid, to_user_id:to_user_id||null, content:String(content).slice(0,5000), created_at:nowISO() };
    store.insertMessage(msg);
    if(room_id) io.to(`room:${room_id}`).emit("message:new", msg);
    else { io.to(`user:${to_user_id}`).emit("message:new", msg); io.to(`user:${user.uid}`).emit("message:new", msg); }
  });
});

// ---------- Front (SPA) ----------
const INDEX_HTML = `<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SwiftTalk — Messagerie</title>
<link rel="icon" href="data:,">
<style>
:root{ --bg:#0b0c10; --panel:rgba(255,255,255,0.08); --ink:#eef1f6; --muted:#a9b0c3;
 --tint:#0a84ff; --card:rgba(255,255,255,0.06); --border:rgba(255,255,255,0.12); --blur:10px; --radius:18px; --pill:999px; }
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',Helvetica,Arial,sans-serif;color:var(--ink);background:radial-gradient(1200px 600px at 80% -10%, #1b1f2a 0%, #0b0c10 60%) #0b0c10;overflow:hidden;}
.glass{background:var(--card);backdrop-filter:blur(var(--blur));border:1px solid var(--border);border-radius:var(--radius)}
header.nav{position:fixed;left:0;right:0;bottom:0;height:72px;display:flex;gap:12px;padding:10px 14px;align-items:center;justify-content:space-between;z-index:10;background:linear-gradient(180deg, rgba(11,12,16,0), rgba(11,12,16,0.85) 35%, rgba(11,12,16,0.95));backdrop-filter:blur(8px);border-top:1px solid var(--border)}
.tab{flex:1;display:flex;flex-direction:column;align-items:center;gap:6px;color:var(--muted);text-decoration:none;padding:10px 8px;border-radius:14px;transition:all .2s}
.tab.active{color:var(--ink);background:rgba(255,255,255,0.08)}
.wrap{position:absolute;inset:0;padding:16px;padding-bottom:100px;display:grid;grid-template-columns:340px 1fr;gap:16px}
@media (max-width:980px){.wrap{grid-template-columns:1fr}.side{display:none}}
.hero{grid-column:1 / -1;display:flex;gap:16px;align-items:center;justify-content:space-between}
.hero-card{flex:1;min-height:110px;padding:18px;display:flex;gap:16px;align-items:center}
.hero-card h1{margin:0;font-size:20px}.hero-card p{margin:0;color:var(--muted)}
.hero-actions{display:flex;gap:10px;flex-wrap:wrap}
.btn{appearance:none;border:none;cursor:pointer;padding:12px 16px;border-radius:var(--pill);background:linear-gradient(180deg,var(--tint),#0060df);color:#fff;font-weight:600;box-shadow:0 6px 16px rgba(10,132,255,.35);transition:transform .08s,filter .2s}
.btn.secondary{background:rgba(255,255,255,0.12);box-shadow:none;color:var(--ink);border:1px solid var(--border)}
.btn:active{transform:translateY(1px)} .btn.small{padding:8px 12px;font-size:13px}
.side{display:flex;flex-direction:column;gap:16px}
.panel{padding:14px} .section-title{margin:0 0 10px;font-size:13px;letter-spacing:.3px;color:var(--muted);text-transform:uppercase}
.list{display:flex;flex-direction:column;gap:8px;max-height:38vh;overflow:auto}
.item{display:flex;align-items:center;gap:12px;padding:10px;border-radius:12px;border:1px solid var(--border)}
.item .avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#3a3f55,#1b1f2a);display:flex;align-items:center;justify-content:center;font-weight:700}
.item .meta{display:flex;flex-direction:column}.item .meta .name{font-weight:600}.item .meta .sub{color:var(--muted);font-size:12px}
.chat{display:flex;flex-direction:column;gap:12px;min-height:46vh;max-height:60vh;overflow:auto;padding:12px;border:1px solid var(--border);border-radius:14px}
.bubble{max-width:75%;padding:10px 12px;border-radius:18px;line-height:1.35;animation:pop .12s ease}
@keyframes pop{from{transform:scale(.98);opacity:0}to{transform:scale(1);opacity:1}}
.bubble.me{margin-left:auto;background:linear-gradient(180deg,#0a84ff,#0060df);color:#fff}
.bubble.them{margin-right:auto;background:rgba(255,255,255,0.08)}
.composer{display:flex;gap:10px;padding:10px;border:1px solid var(--border);border-radius:14px}
input,select,textarea{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,0.04);color:var(--ink);outline:none}
input:focus,select:focus,textarea:focus{border-color:rgba(100,210,255,0.7);box-shadow:0 0 0 4px rgba(100,210,255,0.12)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.hidden{display:none !important}.pill{padding:6px 10px;border-radius:999px;background:rgba(255,255,255,0.08);border:1px solid var(--border);font-size:12px;color:var(--muted)}
.link{color:var(--tint);cursor:pointer}
</style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="glass hero-card">
        <div><h1>SwiftTalk</h1><p>Messagerie temps réel inspirée d’iOS 16+ — crée un compte, rejoins un salon, écris à un contact.</p></div>
        <div class="hero-actions">
          <button class="btn" id="btnOpenRegister">Créer un compte</button>
          <button class="btn secondary" id="btnOpenLogin">Se connecter</button>
          <span id="meInfo" class="pill hidden"></span>
          <button class="btn small secondary hidden" id="btnLogout">Se déconnecter</button>
        </div>
      </div>
      <div class="glass hero-card">
        <div><h1>Accès rapide</h1><p>Salons publics, salon privé, discussion directe.</p></div>
        <div class="hero-actions">
          <button class="btn" id="btnQuickJoin">Salons publics</button>
          <button class="btn secondary" id="btnQuickCreateRoom">Créer un salon</button>
          <button class="btn secondary" id="btnQuickDM">Écrire à un contact</button>
        </div>
      </div>
    </div>

    <div class="side">
      <div class="glass panel">
        <div class="section-title">Salons (mes & publics)</div>
        <div class="list" id="roomsList"></div>
        <div class="grid-2" style="margin-top:10px">
          <input id="roomName" placeholder="Nom du salon"/>
          <select id="roomVisibility"><option value="1">Public</option><option value="0">Privé</option></select>
        </div>
        <div style="margin-top:10px;display:flex;gap:10px">
          <button class="btn small" id="btnCreateRoom">Créer</button>
          <button class="btn small secondary" id="btnRefreshRooms">Rafraîchir</button>
        </div>
      </div>
      <div class="glass panel">
        <div class="section-title">Contacts</div>
        <input id="userSearch" placeholder="Rechercher un pseudo ou email…"/>
        <div class="list" id="usersList"></div>
      </div>
    </div>

    <div>
      <div class="glass panel">
        <div class="section-title">Discussion</div>
        <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px">
          <span class="pill">Cible: <span id="targetPill">Aucun</span></span>
          <span class="pill">Type: <span id="typePill">—</span></span>
          <span class="pill" id="notifPill">Notifications: —</span>
        </div>
        <div class="chat" id="chat"></div>
        <div class="composer" style="margin-top:10px">
          <input id="messageInput" placeholder="Écrire un message…"/>
          <button class="btn" id="btnSend">Envoyer</button>
        </div>
      </div>
      <div class="glass panel" style="margin-top:16px">
        <div class="section-title">Profil</div>
        <div id="profileBox"><p>Connectez-vous pour voir votre profil.</p></div>
      </div>
    </div>
  </div>

  <header class="nav">
    <a class="tab active" id="tabHome"><div>🏠</div><div class="label">Accueil</div></a>
    <a class="tab" id="tabMessages"><div>💬</div><div class="label">Messages</div></a>
    <a class="tab" id="tabRooms"><div>🗂️</div><div class="label">Salons</div></a>
    <a class="tab" id="tabProfile"><div>👤</div><div class="label">Profil</div></a>
  </header>

  <dialog id="dlgAuth" class="glass" style="border:none;padding:20px;width:420px;max-width:95%">
    <h3 id="authTitle">Créer un compte</h3>
    <div id="registerForm">
      <div class="grid-2" style="margin-top:8px">
        <input id="regEmail" placeholder="Email" type="email"/>
        <input id="regUsername" placeholder="Pseudo"/>
      </div>
      <input id="regPassword" placeholder="Mot de passe" type="password" style="margin-top:8px"/>
      <button class="btn" id="btnDoRegister" style="margin-top:12px">Créer</button>
      <p style="color:var(--muted);font-size:13px;margin-top:8px">Déjà un compte ? <span class="link" id="linkGoLogin">Se connecter</span></p>
    </div>
    <div id="loginForm" class="hidden">
      <input id="loginEmailOrUsername" placeholder="Email ou Pseudo"/>
      <input id="loginPassword" placeholder="Mot de passe" type="password" style="margin-top:8px"/>
      <button class="btn" id="btnDoLogin" style="margin-top:12px">Connexion</button>
      <p style="color:var(--muted);font-size:13px;margin-top:8px">Pas de compte ? <span class="link" id="linkGoRegister">Créer un compte</span></p>
    </div>
  </dialog>

  <script src="/socket.io/socket.io.js"></script>
  <script>
    const state = { me:null, target:{type:null,id:null,label:"Aucun"}, socket:null };
    const el = id => document.getElementById(id); const chat = el("chat");
    function setTarget(type,id,label){ state.target={type,id,label}; el("targetPill").textContent=label||"—"; el("typePill").textContent=type? (type==="room"?"Salon":"Direct"):"—"; chat.innerHTML=""; if(type==="room") loadRoomMessages(id); else if(type==="dm") loadDmMessages(id); }
    function addBubble({content,me}){ const b=document.createElement("div"); b.className="bubble "+(me?"me":"them"); b.textContent=content; chat.appendChild(b); chat.scrollTop=chat.scrollHeight; }
    function setupNotifications(){ if(!("Notification" in window)){ el("notifPill").textContent="Notifications: N/A";return;} if(Notification.permission==="granted"){el("notifPill").textContent="Notifications: ON";} else if(Notification.permission!=="denied"){ Notification.requestPermission().then(p=>{ el("notifPill").textContent="Notifications: "+(p==="granted"?"ON":"OFF"); }); } else el("notifPill").textContent="Notifications: OFF"; }
    function notify(title, body){ try{ if(Notification.permission==="granted") new Notification(title,{body}); }catch{} }

    async function fetchMe(){ const r=await fetch("/api/me"); if(r.ok){ const {user}=await r.json(); state.me=user; el("meInfo").classList.remove("hidden"); el("meInfo").textContent="Connecté: "+user.username; el("btnLogout").classList.remove("hidden"); el("profileBox").innerHTML="<p><b>Pseudo:</b> "+user.username+"<br/><b>Email:</b> "+user.email+"</p>"; connectSocket(); refreshRooms(); } }
    async function register(){ const payload={ email:el("regEmail").value.trim(), username:el("regUsername").value.trim(), password:el("regPassword").value }; const r=await fetch("/api/auth/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); const j=await r.json(); if(!r.ok) return alert(j.error||"Erreur inscription"); el("dlgAuth").close(); fetchMe(); }
    async function login(){ const payload={ emailOrUsername:el("loginEmailOrUsername").value.trim(), password:el("loginPassword").value }; const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); const j=await r.json(); if(!r.ok) return alert(j.error||"Erreur connexion"); el("dlgAuth").close(); fetchMe(); }
    async function logout(){ await fetch("/api/auth/logout",{method:"POST"}); location.reload(); }

    async function refreshRooms(){ if(!state.me) return; const [mine,pub]=await Promise.all([ fetch("/api/rooms/mine").then(r=>r.json()), fetch("/api/rooms/public").then(r=>r.json()) ]); const list=el("roomsList"); list.innerHTML=""; const seen=new Set(); (mine.rooms||[]).forEach(r=>{ seen.add(r.id); addRoomItem(r,true); }); (pub.rooms||[]).forEach(r=>{ if(!seen.has(r.id)) addRoomItem(r,false); }); }
    function addRoomItem(room,mine){ const li=document.createElement("div"); li.className="item"; li.innerHTML=`
      <div class="avatar">#</div>
      <div class="meta"><div class="name">${room.name} ${room.is_public?"":"🔒"}</div><div class="sub">${mine?"Membre":"Public"} • Créé par ${room.creator_username||"?"}</div></div>
      <div style="margin-left:auto;display:flex;gap:6px"><button class="btn small secondary">Ouvrir</button>${mine?"":'<button class="btn small">Rejoindre</button>'}</div>`;
      const [btnOpen, btnJoin] = li.querySelectorAll("button");
      btnOpen.onclick=()=>{ setTarget("room",room.id,room.name); joinSocketRoom(room.id); };
      if(btnJoin) btnJoin.onclick=async()=>{ const r=await fetch("/api/rooms/join",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({room_id:room.id})}); if(r.ok){ refreshRooms(); setTarget("room",room.id,room.name); joinSocketRoom(room.id);} else alert("Impossible de rejoindre"); };
      el("roomsList").appendChild(li);
    }
    async function createRoom(){ const name=el("roomName").value.trim(); const is_public=el("roomVisibility").value==="1"; if(!name) return alert("Nom requis"); const r=await fetch("/api/rooms",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,is_public})}); const j=await r.json(); if(!r.ok) return alert(j.error||"Erreur création"); await refreshRooms(); setTarget("room",j.room.id,name); joinSocketRoom(j.room.id); el("roomName").value=""; }
    async function loadRoomMessages(room_id){ const r=await fetch("/api/messages/room?room_id="+encodeURIComponent(room_id)); const j=await r.json(); chat.innerHTML=""; (j.messages||[]).forEach(m=>addBubble({content:m.content, me:m.from_user_id===state.me?.id})); }
    async function loadDmMessages(with_user_id){ const r=await fetch("/api/messages/dm?with_user_id="+encodeURIComponent(with_user_id)); const j=await r.json(); chat.innerHTML=""; (j.messages||[]).forEach(m=>addBubble({content:m.content, me:m.from_user_id===state.me?.id})); }
    async function sendMessage(){ const content=el("messageInput").value.trim(); if(!content) return; if(!state.target.type) return alert("Choisissez un salon ou un contact"); const payload={ content }; if(state.target.type==="room") payload.room_id=state.target.id; if(state.target.type==="dm") payload.to_user_id=state.target.id; if(state.socket?.connected) state.socket.emit("message:send",payload); else { const r=await fetch("/api/messages/send",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); if(!r.ok) alert("Envoi échoué"); } el("messageInput").value=""; }
    let searchDebounce; el("userSearch").addEventListener("input",(e)=>{ const v=e.target.value.trim(); clearTimeout(searchDebounce); if(!v){ el("usersList").innerHTML=""; return; } searchDebounce=setTimeout(async()=>{ const r=await fetch("/api/users/search?q="+encodeURIComponent(v)); const j=await r.json(); const list=el("usersList"); list.innerHTML=""; (j.users||[]).filter(u=>u.id!==state.me?.id).forEach(u=>{ const li=document.createElement("div"); li.className="item"; li.innerHTML=`
          <div class="avatar">${(u.username||"??").slice(0,2).toUpperCase()}</div>
          <div class="meta"><div class="name">${u.username}</div><div class="sub">${u.email}</div></div>
          <div style="margin-left:auto;"><button class="btn small">Discuter</button></div>`;
          li.querySelector("button").onclick=()=> setTarget("dm",u.id,"@"+u.username);
          list.appendChild(li);
        }); },250);
    });
    function connectSocket(){ if(state.socket){ try{state.socket.disconnect();}catch{} } state.socket = io("/", { withCredentials:true }); state.socket.on("connect",()=>{ if(state.target.type==="room") joinSocketRoom(state.target.id); }); state.socket.on("message:new",(m)=>{ const isRoom=(state.target.type==="room"&&m.room_id===state.target.id); const isDM=(state.target.type==="dm"&& ((m.from_user_id===state.target.id&&m.to_user_id===state.me.id)||(m.from_user_id===state.me.id&&m.to_user_id===state.target.id))); if(isRoom||isDM){ addBubble({content:m.content, me:m.from_user_id===state.me.id}); } else { notify("Nouveau message", m.content.slice(0,80)); } }); }
    function joinSocketRoom(room_id){ try{ state.socket.emit("room:join",{room_id}); }catch{} }

    const actTab=id=>{ document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active")); document.getElementById(id).classList.add("active"); };
    document.getElementById("btnQuickJoin").onclick=()=>{ actTab("tabRooms"); refreshRooms(); };
    document.getElementById("btnQuickCreateRoom").onclick=()=> document.getElementById("roomName").focus();
    document.getElementById("btnQuickDM").onclick=()=> document.getElementById("userSearch").focus();

    document.getElementById("btnOpenRegister").onclick=()=>{ document.getElementById("authTitle").textContent="Créer un compte"; document.getElementById("registerForm").classList.remove("hidden"); document.getElementById("loginForm").classList.add("hidden"); document.getElementById("dlgAuth").showModal(); };
    document.getElementById("btnOpenLogin").onclick=()=>{ document.getElementById("authTitle").textContent="Se connecter"; document.getElementById("registerForm").classList.add("hidden"); document.getElementById("loginForm").classList.remove("hidden"); document.getElementById("dlgAuth").showModal(); };
    document.getElementById("linkGoLogin").onclick=()=>{ document.getElementById("authTitle").textContent="Se connecter"; document.getElementById("registerForm").classList.add("hidden"); document.getElementById("loginForm").classList.remove("hidden"); };
    document.getElementById("linkGoRegister").onclick=()=>{ document.getElementById("authTitle").textContent="Créer un compte"; document.getElementById("registerForm").classList.remove("hidden"); document.getElementById("loginForm").classList.add("hidden"); };
    document.getElementById("btnDoRegister").onclick=register; document.getElementById("btnDoLogin").onclick=login; document.getElementById("btnLogout").onclick=logout;
    document.getElementById("btnCreateRoom").onclick=createRoom; document.getElementById("btnRefreshRooms").onclick=refreshRooms; document.getElementById("btnSend").onclick=sendMessage;
    document.getElementById("messageInput").addEventListener("keydown", e=>{ if(e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); sendMessage(); } });
    document.getElementById("tabHome").onclick=()=>actTab("tabHome"); document.getElementById("tabMessages").onclick=()=>actTab("tabMessages"); document.getElementById("tabRooms").onclick=()=>actTab("tabRooms"); document.getElementById("tabProfile").onclick=()=>actTab("tabProfile");

    setupNotifications(); fetchMe();
  </script>
</body></html>`;

app.get("/", (_req,res)=>{ res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(INDEX_HTML); });

// ---------- Start & Error handling ----------
process.on("uncaughtException", (e)=>{ console.error("[uncaughtException]", e); });
process.on("unhandledRejection", (e)=>{ console.error("[unhandledRejection]", e); });

server.listen(PORT, HOST, () => {
  console.log("SwiftTalk running on", HOST+":"+PORT);
  console.log("Working dir:", process.cwd());
  console.log("Data file:", DATA_FILE);
});
