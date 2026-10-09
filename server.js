require("dotenv").config();
const express=require("express"), session=require("express-session"), cors=require("cors"), crypto=require("crypto");
const app=express(), PORT=Number(process.env.PORT||3000);
const APP_ID=process.env.META_APP_ID, APP_SECRET=process.env.META_APP_SECRET;
const API_VERSION=process.env.META_API_VERSION||"v26.0";
const BASE=(process.env.APP_BASE_URL||"").replace(/\/+$/,"");
const SESSION_SECRET=process.env.SESSION_SECRET;
const origins=(process.env.FRONTEND_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
if(!SESSION_SECRET){console.error("Missing SESSION_SECRET environment variable");process.exit(1);}
app.set("trust proxy",1);
app.use(cors({origin(o,cb){if(!o||!origins.length||origins.includes(o))return cb(null,true);cb(new Error("Origin not allowed"));},credentials:true}));
app.use(express.json({limit:"2mb"}));
app.use(session({name:"fb_scheduler_sid",secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",maxAge:8*60*60*1000}}));
function configured(res){if(!APP_ID||!APP_SECRET||!BASE){res.status(503).json({error:"META_CONFIGURATION_MISSING",message:"Set META_APP_ID, META_APP_SECRET and APP_BASE_URL in host environment."});return false;}return true;}
const callback=()=>BASE+"/auth/facebook/callback";
async function graph(path,params={}){const u=new URL(`https://graph.facebook.com/${API_VERSION}/${path}`);Object.entries(params).forEach(([k,v])=>{if(v!=null)u.searchParams.set(k,String(v));});const r=await fetch(u);const d=await r.json().catch(()=>({}));if(!r.ok||d.error){const e=new Error(d.error?.message||`Graph API HTTP ${r.status}`);e.meta=d.error;e.status=r.status;throw e;}return d;}
app.get("/health",(_q,s)=>s.json({ok:true,service:"facebook-bulk-scheduler-backend",version:"0.1.0"}));
app.get("/config/status",(_q,s)=>s.json({appIdConfigured:!!APP_ID,appSecretConfigured:!!APP_SECRET,appBaseUrlConfigured:!!BASE,callbackPath:"/auth/facebook/callback",metaApiVersion:API_VERSION}));
app.get("/auth/facebook",(q,s)=>{if(!configured(s))return;const state=crypto.randomBytes(24).toString("hex");q.session.oauthState=state;const u=new URL(`https://www.facebook.com/${API_VERSION}/dialog/oauth`);u.searchParams.set("client_id",APP_ID);u.searchParams.set("redirect_uri",callback());u.searchParams.set("state",state);u.searchParams.set("response_type","code");u.searchParams.set("scope",(process.env.META_SCOPES||"public_profile,email").split(",").map(x=>x.trim()).filter(Boolean).join(","));s.redirect(u.toString());});
app.get("/auth/facebook/callback",async(q,s)=>{if(!configured(s))return;const {code,state,error,error_description}=q.query;if(error)return s.status(400).send("Facebook Login was cancelled or rejected: "+String(error_description||error));if(!code||!state||!q.session.oauthState||state!==q.session.oauthState)return s.status(400).send("Invalid OAuth state. Start Facebook Login again.");delete q.session.oauthState;try{const t=await graph("oauth/access_token",{client_id:APP_ID,client_secret:APP_SECRET,redirect_uri:callback(),code});q.session.userAccessToken=t.access_token;const me=await graph("me",{fields:"id,name",access_token:t.access_token});q.session.facebookUser={id:me.id,name:me.name||""};if(process.env.FRONTEND_SUCCESS_URL){const u=new URL(process.env.FRONTEND_SUCCESS_URL);u.searchParams.set("connected","1");return s.redirect(u.toString());}s.send("Facebook Login succeeded. Page access still requires Page permissions to be configured and granted.");}catch(e){console.error("OAuth callback failed:",e.message);s.status(502).send("Facebook Login failed. Check Meta configuration and backend logs.");}});
app.get("/auth/status",(q,s)=>s.json({connected:!!q.session.userAccessToken,user:q.session.facebookUser||null}));
app.post("/auth/logout",(q,s)=>q.session.destroy(()=>{s.clearCookie("fb_scheduler_sid");s.json({ok:true});}));
app.get("/api/pages",async(q,s)=>{if(!q.session.userAccessToken)return s.status(401).json({error:"NOT_CONNECTED",message:"Connect with Facebook first."});try{const d=await graph("me/accounts",{fields:"id,name,access_token,tasks",access_token:q.session.userAccessToken});q.session.pages=(d.data||[]).map(p=>({id:p.id,name:p.name,tasks:p.tasks||[],accessToken:p.access_token}));s.json({pages:q.session.pages.map(({id,name,tasks})=>({id,name,tasks}))});}catch(e){s.status(502).json({error:"PAGE_FETCH_FAILED",message:e.meta?.message||e.message,hint:"Requires available and granted Meta Page permissions and user Page access."});}});
app.post("/api/posts/photo",(_q,s)=>s.status(501).json({error:"PUBLISHING_NOT_IMPLEMENTED",message:"Photo publishing is not implemented yet; do not treat this endpoint as working."}));
app.post("/api/schedule",(_q,s)=>s.status(501).json({error:"SCHEDULER_NOT_IMPLEMENTED",message:"Persistent server-side scheduling is not implemented yet; do not treat a saved time as a published post."}));
app.use((e,_q,s,_n)=>{console.error(e.message);s.status(500).json({error:"INTERNAL_ERROR",message:"Unexpected server error."});});
app.listen(PORT,()=>console.log(`Backend listening on ${PORT}`));
