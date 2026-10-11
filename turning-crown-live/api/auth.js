import crypto from 'node:crypto';
const sign=t=>crypto.createHmac('sha256',process.env.TC_SESSION_SECRET||'unset').update(t).digest('base64url');
const auth=req=>{
  const value=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('tc_dm_auth='));
  if(!value)return false;
  const [t,s]=value.slice(11).split('.');
  if(!t||!s||!/^\d{13}$/.test(t)||Date.now()-Number(t)>28800000||Number(t)>Date.now()+60000)return false;
  const expected=sign(t);
  return expected.length===s.length&&crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(s));
};
const origin=req=>{try{const u=new URL(req.headers.origin);return u.protocol==='https:'&&u.host===req.headers.host;}catch{return false;}};
export default function handler(req,res){
 res.setHeader('Cache-Control','private, no-store');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method==='GET')return res.status(200).json({authenticated:auth(req)});
 if(!['POST','DELETE'].includes(req.method))return res.status(405).json({error:'Method not allowed'});
 if(!origin(req))return res.status(403).json({error:'Origin rejected'});
 if(req.method==='DELETE'){
  res.setHeader('Set-Cookie','tc_dm_auth=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
  return res.status(200).json({authenticated:false});
 }
 const a=Buffer.from(String(req.body?.passcode||'')),b=Buffer.from(process.env.TC_DM_PASSCODE||'');
 if(!b.length||a.length!==b.length||!crypto.timingSafeEqual(a,b))
  return res.status(401).json({error:'Invalid passcode'});
 const timestamp=String(Date.now());
 res.setHeader('Set-Cookie','tc_dm_auth='+timestamp+'.'+sign(timestamp)+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800');
 return res.status(200).json({authenticated:true});
}