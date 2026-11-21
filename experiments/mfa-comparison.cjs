const {createRequire}=require('node:module');
const requireBackend=createRequire(process.cwd()+'/backend/package.json');
const {Pool}=requireBackend('pg');
const {generate}=requireBackend('otplib');
const {randomBytes}=require('node:crypto');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const db=new Pool({host:'/tmp',database:'cs2413_auth'});
const email='mfa-measure-'+randomBytes(6).toString('hex')+'@example.test';
const password='LabOnly!'+randomBytes(20).toString('hex');
const rows=[];
async function request(path,body,cookie){
 const start=performance.now();
 const r=await fetch('http://127.0.0.1:3001'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:body===undefined?undefined:JSON.stringify(body)});
 return {status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]||cookie,ms:performance.now()-start};
}
async function attempt(mode,n){
 const login=await request('/login',{email,password});
 assert.equal(login.status,200,'Login must reach password verification; rerun after rate-limit window if blocked');
 const me=await request('/me',undefined,login.cookie);
 rows.push({mode,attempt:n,login_status:login.status,mfa_required:login.body.mfaRequired===true,me_status:me.status,access_granted:me.status===200,elapsed_ms:(login.ms+me.ms).toFixed(2)});
 assert.equal(me.status,mode==='mfa_off'?200:401);
 await request('/logout',{},login.cookie);
}
(async()=>{
 try{
 assert.equal((await request('/register',{email,password})).status,201);
 for(let i=1;i<=3;i++)await attempt('mfa_off',i);
 const session=await request('/login',{email,password}); assert.equal(session.status,200);
 const enrollment=await request('/mfa/enroll',{},session.cookie);assert.equal(enrollment.status,200);
 const secret=new URL(enrollment.body.uri).searchParams.get('secret');
 const token=await generate({secret});
 assert.equal((await request('/mfa/confirm',{token},session.cookie)).status,200);
 await request('/logout',{},session.cookie);
 for(let i=1;i<=3;i++)await attempt('mfa_on_password_only',i);
 console.log('Password-only comparison passed. Waiting for a fresh TOTP interval for positive control.');
 await new Promise(r=>setTimeout(r,30000-Date.now()%30000+1500));
 const login=await request('/login',{email,password});assert.equal(login.status,200);
 assert.equal((await request('/me',undefined,login.cookie)).status,401);
 const verified=await request('/mfa/verify',{token:await generate({secret})},login.cookie);assert.equal(verified.status,200);
 const me=await request('/me',undefined,verified.cookie);assert.equal(me.status,200);
 rows.push({mode:'mfa_on_valid_code',attempt:1,login_status:login.status,mfa_required:true,me_status:me.status,access_granted:true,elapsed_ms:(login.ms+verified.ms+me.ms).toFixed(2)});
 await request('/logout',{},verified.cookie);
 fs.mkdirSync('experiments/results',{recursive:true});
 const output='experiments/results/mfa_comparison.csv';
 const keys=Object.keys(rows[0]);fs.writeFileSync(output,keys.join(',')+'\n'+rows.map(r=>keys.map(k=>r[k]).join(',')).join('\n')+'\n');
 console.table(rows);console.log('Saved '+output);
 }finally{await db.query('DELETE FROM users WHERE email=$1',[email]);await db.end();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
