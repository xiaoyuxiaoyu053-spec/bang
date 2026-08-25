const express=require("express"), http=require("http"), path=require("path");
const bcrypt=require("bcryptjs"), Database=require("better-sqlite3"), {Server}=require("socket.io");
const app=express(), server=http.createServer(app), io=new Server(server);
const db=new Database(process.env.DB_PATH||"starchat.db");
db.pragma("journal_mode=WAL");
db.exec(`CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL, nickname TEXT NOT NULL, avatar TEXT DEFAULT '',
 is_admin INTEGER DEFAULT 0, created_at INTEGER DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
 nickname TEXT, avatar TEXT, text TEXT, type TEXT DEFAULT 'text',
 reply_id INTEGER, reply_nickname TEXT, reply_text TEXT, created_at INTEGER DEFAULT (unixepoch()),
 FOREIGN KEY(user_id) REFERENCES users(id)
);`);
const admin=db.prepare("SELECT id FROM users WHERE username='Admin'").get();
if(!admin){
 const hash=bcrypt.hashSync("AdminStar123456",10);
 db.prepare("INSERT INTO users(username,password,nickname,is_admin) VALUES(?,?,?,1)")
   .run("Admin",hash,"Admin");
}
app.use(express.json({limit:"2mb"})); app.use(express.static(path.join(__dirname,"public")));
const sessions=new Map();
function userFromToken(t){return t&&sessions.get(t)}
app.post("/api/register",(req,res)=>{
 const {username,password}=req.body||{};
 if(!/^[A-Za-z0-9_]{3,20}$/.test(username||"") || (password||"").length<6)
   return res.status(400).json({error:"账号3-20位字母数字下划线，密码至少6位"});
 try{
  const hash=bcrypt.hashSync(password,10);
  const r=db.prepare("INSERT INTO users(username,password,nickname) VALUES(?,?,?)").run(username,hash,username);
  const u=db.prepare("SELECT id,username,nickname,avatar,is_admin FROM users WHERE id=?").get(r.lastInsertRowid);
  const token=require("crypto").randomBytes(32).toString("hex"); sessions.set(token,u);
  res.json({token,user:u});
 }catch(e){res.status(409).json({error:"账号已存在"})}
});
app.post("/api/login",(req,res)=>{
 const {username,password}=req.body||{}, u=db.prepare("SELECT * FROM users WHERE username=?").get(username);
 if(!u||!bcrypt.compareSync(password,u.password)) return res.status(401).json({error:"账号或密码错误"});
 const token=require("crypto").randomBytes(32).toString("hex");
 const safe={id:u.id,username:u.username,nickname:u.nickname,avatar:u.avatar,is_admin:u.is_admin};
 sessions.set(token,safe); res.json({token,user:safe});
});
app.get("/api/me",(req,res)=>{
 const u=userFromToken(req.headers.authorization?.replace("Bearer ","")); if(!u)return res.status(401).end(); res.json(u);
});
app.get("/api/messages",(req,res)=>{
 const rows=db.prepare("SELECT * FROM messages ORDER BY id DESC LIMIT 100").all().reverse(); res.json(rows);
});
app.get("/api/users",(req,res)=>res.json(db.prepare("SELECT id,username,nickname,avatar,is_admin FROM users ORDER BY id").all()));
app.post("/api/profile",(req,res)=>{
 const u=userFromToken(req.headers.authorization?.replace("Bearer ","")); if(!u)return res.status(401).end();
 const {nickname,avatar}=req.body||{}; const n=String(nickname||"").trim().slice(0,24), a=String(avatar||"").slice(0,300000);
 if(!n)return res.status(400).json({error:"昵称不能为空"});
 db.prepare("UPDATE users SET nickname=?,avatar=? WHERE id=?").run(n,a,u.id);
 Object.assign(u,{nickname:n,avatar:a}); res.json(u);
});
io.on("connection",socket=>{
 socket.on("auth",token=>{const u=userFromToken(token); if(u){socket.user=u; socket.join("public"); io.to("public").emit("presence",{username:u.username,nickname:u.nickname,online:true});}});
 socket.on("send",data=>{
  const u=socket.user;if(!u)return;
  const text=String(data?.text||"").slice(0,4000), type=["text","gif"].includes(data?.type)?data.type:"text";
  if(!text.trim())return;
  let reply=null;
  if(data.reply_id) reply=db.prepare("SELECT nickname,text FROM messages WHERE id=?").get(Number(data.reply_id));
  const r=db.prepare(`INSERT INTO messages(user_id,username,nickname,avatar,text,type,reply_id,reply_nickname,reply_text)
   VALUES(?,?,?,?,?,?,?,?,?)`).run(u.id,u.username,u.nickname,u.avatar||"",text,type,data.reply_id||null,reply?.nickname||null,reply?.text||null);
  const msg=db.prepare("SELECT * FROM messages WHERE id=?").get(r.lastInsertRowid); io.to("public").emit("message",msg);
 });
 socket.on("delete",id=>{
  const u=socket.user;if(!u)return; const m=db.prepare("SELECT * FROM messages WHERE id=?").get(id);
  if(m&&(m.user_id===u.id||u.is_admin)){db.prepare("DELETE FROM messages WHERE id=?").run(id);io.to("public").emit("deleted",id);}
 });
 socket.on("disconnect",()=>{if(socket.user)io.to("public").emit("presence",{username:socket.user.username,nickname:socket.user.nickname,online:false});});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public/index.html")));
const port=process.env.PORT||3000; server.listen(port,()=>console.log("StarChat listening on "+port));
