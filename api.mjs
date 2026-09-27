import { getStore } from '@netlify/blobs';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

const COOKIE_USER='x67_user', COOKIE_ADMIN='x67_admin', DAY=86_400_000, SESSION_TTL=12*60*60*1000;
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'x67yz';
const SESSION_SECRET=process.env.SESSION_SECRET||ADMIN_PASSWORD;
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const hash=value=>createHash('sha256').update(value).digest('hex');
const sessionHash=value=>createHmac('sha256',SESSION_SECRET).update(value).digest('hex');
const token=()=>randomBytes(32).toString('base64url');
const cookie=(name,value,maxAge)=>`${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const clearCookie=name=>`${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
const safeEqual=(a,b)=>{const aa=Buffer.from(String(a??'')),bb=Buffer.from(String(b??''));return aa.length===bb.length&&timingSafeEqual(aa,bb)};
const bodyOf=async request=>{try{return await request.json()}catch{return {}}};
const cookieValue=(request,name)=>{const raw=request.headers.get('cookie')??'',item=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(`${name}=`));return item?decodeURIComponent(item.slice(name.length+1)):''};
const store=()=>getStore({name:'x67-security-ios',consistency:'strong'});
async function session(request,kind){
  const name=kind==='admin'?COOKIE_ADMIN:COOKIE_USER,value=cookieValue(request,name);if(!value)return null;
  const s=store(),data=await s.get(`sessions/${sessionHash(value)}`,{type:'json',consistency:'strong'});
  if(!data||data.kind!==kind||data.expiresAt<=Date.now())return null;
  if(kind==='user'){const record=await s.get(`keys/${data.keyId}`,{type:'json',consistency:'strong'});if(!record||record.revoked||(record.expiresAt&&record.expiresAt<=Date.now()))return null;}
  return {value,data};
}
async function issue(kind,extra={}){const value=token();await store().setJSON(`sessions/${sessionHash(value)}`,{kind,expiresAt:Date.now()+SESSION_TTL,...extra});return value;}
export default async request=>{
 try{
  const origin=request.headers.get('origin'),host=request.headers.get('host');
  if(origin&&host&&new URL(origin).host!==host)return json({error:'Origem não autorizada.'},403);
  const url=new URL(request.url),action=url.searchParams.get('action'),input=await bodyOf(request),s=store();
  if(request.method==='GET'&&action==='session'){const [user,admin]=await Promise.all([session(request,'user'),session(request,'admin')]);return json({authenticated:Boolean(user),admin:Boolean(admin)});}
  if(request.method==='POST'&&action==='user-login'){
   const key=String(input.key??'').trim().toUpperCase();if(!/^X67-[A-Z0-9-]{12,80}$/.test(key))return json({error:'Chave inválida.'},401);
   const keyId=hash(key),record=await s.get(`keys/${keyId}`,{type:'json',consistency:'strong'});if(!record||record.revoked||(record.expiresAt&&record.expiresAt<=Date.now()))return json({error:'Chave inválida, removida ou expirada.'},401);
   const value=await issue('user',{keyId});return json({ok:true},200,{'set-cookie':cookie(COOKIE_USER,value,SESSION_TTL/1000)});
  }
  if(request.method==='POST'&&action==='admin-login'){
   if(!safeEqual(input.password,ADMIN_PASSWORD)){await new Promise(r=>setTimeout(r,700));return json({error:'Senha administrativa incorreta.'},401);}
   const value=await issue('admin');return json({ok:true},200,{'set-cookie':cookie(COOKIE_ADMIN,value,SESSION_TTL/1000)});
  }
  if(request.method==='POST'&&action==='logout'){
   for(const kind of ['user','admin']){const current=await session(request,kind);if(current)await s.delete(`sessions/${sessionHash(current.value)}`);}
   const response=json({ok:true});response.headers.append('set-cookie',clearCookie(COOKIE_USER));response.headers.append('set-cookie',clearCookie(COOKIE_ADMIN));return response;
  }
  if(action==='create-key'&&request.method==='POST'){
   if(!(await session(request,'admin')))return json({error:'Acesso administrativo necessário.'},401);
   const days=Number(input.days);if(![0,1,3,7,15,30].includes(days))return json({error:'Duração inválida.'},400);
   let key=String(input.customKey??'').trim().toUpperCase();
   if(key){if(!/^X67-[A-Z0-9-]{12,80}$/.test(key))return json({error:'Chave personalizada precisa começar por X67- e conter ao menos 12 caracteres alfanuméricos.'},400);}
   else key=`X67-${randomBytes(15).toString('hex').toUpperCase()}`;
   const keyId=hash(key),now=Date.now(),record={id:keyId,createdAt:now,expiresAt:days?now+days*DAY:null,days,duration:days?`${days} dia${days>1?'s':''}`:'Permanente',revoked:false};
   const {modified}=await s.setJSON(`keys/${keyId}`,record,{onlyIfNew:true});if(!modified)return json({error:'Esta chave já existe. Escolha outra chave personalizada.'},409);
   return json({key,record:{...record,key:undefined}},201);
  }
  if(action==='list-keys'&&request.method==='GET'){
   if(!(await session(request,'admin')))return json({error:'Acesso administrativo necessário.'},401);
   const {blobs}=await s.list({prefix:'keys/'}),records=[];
   for(const entry of blobs){const record=await s.get(entry.key,{type:'json',consistency:'strong'});if(record&&!record.revoked)records.push(record);}
   records.sort((a,b)=>b.createdAt-a.createdAt);return json({keys:records});
  }
  if(action==='delete-key'&&request.method==='POST'){
   if(!(await session(request,'admin')))return json({error:'Acesso administrativo necessário.'},401);
   const id=String(input.id??'');if(!/^[a-f0-9]{64}$/.test(id))return json({error:'Identificador inválido.'},400);
   await s.delete(`keys/${id}`);return json({ok:true});
  }
  return json({error:'Ação não encontrada.'},404);
 }catch(error){
  console.error('X67 API error:',error);
  const safe=error.message?.includes('ADMIN_PASSWORD')?error.message:'Falha temporária no serviço. Verifique a configuração do site no Netlify.';
  return json({error:safe},500);
 }
};
