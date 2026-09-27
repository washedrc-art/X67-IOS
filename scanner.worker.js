import { Unzip, UnzipInflate, UnzipPassThrough, Gunzip } from 'fflate';
import { parse as parsePlist, parseBinary as parseBinaryPlist } from 'plist';
import { DOMParser as XmlDomParser } from '@xmldom/xmldom';

const MAX_TOTAL = 1024 ** 3;
const MAX_SELECTED_FILE = 12 * 1024 * 1024;
const ACCEPTED = /\.(?:log(?:\.\d+)?|txt|plist|json|ips|crash|panic|mobileconfig|mobileprovision|tracev3)(?:\.(?:gz|gzip))?$/i;
const FINDINGS = {
  profiles: [
    ['Perfil instalado', /\b(?:ProfileInstall(?:ed)?|ConfigurationProfileInstalled|MCProfileInstalled|Profile[\s_-]+Install(?:ed)?|Profile[\s_-]+Installed|Installed.{0,80}Profile)\b/ig],
    ['Perfil removido', /\b(?:ProfileRemoved|ProfileRemoval|ProfileUninstall(?:ed)?|ConfigurationProfileRemoved|MCProfileRemoved|Profile[\s_-]+Remov(?:e|ed|al)|Removed.{0,80}Profile|Uninstalled.{0,80}Profile)\b/ig],
  ],
  certificates: [
    ['TrollStore', /\bTrollStore\b/ig], ['AltStore', /\bAltStore\b/ig], ['SideStore', /\bSideStore\b/ig],
    ['Sideloadly', /\bSideloadly\b/ig], ['Scarlet', /\bScarlet\b/ig], ['ESign', /\bESign\b/ig],
    ['Feather', /\bFeather\b/ig], ['GBox', /\bGBox\b/ig], ['TrollHelper', /\bTrollHelper\b/ig],
    ['Skibidi Revoke', /\bSkibidi[\s_-]+Revoke\b/ig],
    ['Khoindvn', /\bKhoindvn\b/ig], ['KSign', /\bKSign\b/ig],
  ],
  pc: [
    ['Registro de pareamento criado', /\b(?:AddPairingRecord|PairingRecordAdded|PairingRecordCreated|PairingRecordSaved|PairingSucceeded|PairingSuccessful|PairingCompleted|DevicePairingSucceeded)\b/ig],
    ['Conexão USB com computador confirmada', /\busb_host_connected_block_invoke\b|\bUSBHostConnected\b/ig],
    ['Sessão lockdown confirmada com host', /\b(?:LockdownSessionStarted|HostSessionStarted|PairingSessionCompleted|DevicePairedSuccessfully)\b/ig],
  ],
  jailbreak: [
    ['Cydia', /\bCydia\b/ig], ['Sileo', /\bSileo\b/ig], ['Zebra', /\bZebra\b/ig],
    ['Substrate', /\bSubstrate\b/ig], ['Substitute', /\bSubstitute\b/ig], ['ElleKit', /\bElleKit\b/ig],
    ['libhooker', /\blibhooker\b/ig], ['TweakInject', /\bTweakInject\b/ig], ['RocketBootstrap', /\bRocketBootstrap\b/ig],
    ['Dopamine', /\bDopamine\b/ig], ['palera1n', /\bpalera1n\b/ig], ['checkra1n', /\bcheckra1n\b/ig],
    ['unc0ver', /\bunc0ver\b/ig], ['Taurine', /\bTaurine\b/ig], ['Odyssey', /\bOdyssey\b/ig],
    ['Indicador de bootstrap rootless', /(?:\/var\/jb(?:\/|\b)|\/private\/preboot\/[^\s,]*\/procursus(?:\/|\b))/ig],
    ['Frida server', /\bfrida-server\b/ig],
  ],
};
const TOOL_NAMES=['TrollStore','AltStore','SideStore','Sideloadly','Scarlet','ESign','Feather','GBox','TrollHelper','Skibidi Revoke','Khoindvn','KSign'];
const TOOL_PATTERN=/\b(?:TrollStore|AltStore|SideStore|Sideloadly|Scarlet|ESign|Feather|GBox|TrollHelper|Skibidi[\s_-]+Revoke|Khoindvn|KSign)\b/ig;
const JAILBREAK_PATTERN=/\b(?:Cydia|Sileo|Zebra|Substrate|Substitute|ElleKit|libhooker|TweakInject|RocketBootstrap|Dopamine|palera1n|checkra1n|unc0ver|Taurine|Odyssey)\b/ig;
const results = { filesSeen: 0, bytesExpanded: 0, hits: { profiles: [], certificates: [], pc: [], jailbreak: [] }, ios: [], sysIntegrity: [], sources: new Set(), warnings: [] };
if(typeof globalThis.DOMParser==='undefined')globalThis.DOMParser=XmlDomParser;
let stopped = false, lastProgress = 0, mcstateSeen = false, mcProfileEventsSeen=false, mcSettingsEventsSeen=false, entriesSeen = 0;
const seenSignals=new Set(),hitCounts=new Map(),skywalkFound=new Set(),binaryPlists=new Set();
const seenSys=new Set();
function send(type, data = {}) { self.postMessage({ type, ...data }); }
function progress(phase, value) { const now=Date.now(); if(now-lastProgress>120||value>=100){send('progress',{phase,value,expanded:results.bytesExpanded});lastProgress=now;} }
function cleanPath(name) { return String(name||'').replace(/\\/g,'/').toLowerCase(); }
function timestampNear(text,index){
  const left=text.lastIndexOf('\n',index),right=text.indexOf('\n',index),start=left<0?0:left+1,end=right<0?text.length:right;
  const line=text.slice(start,end),pattern=/(?:20\d{2}[-/]\d\d[-/]\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?|\b\d{2}\/\d{2}\/\d{2,4}\s+\d\d:\d\d:\d\d(?:[.,]\d+)?|\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)/g;
  let closest=null,distance=Infinity;for(const match of line.matchAll(pattern)){const current=Math.abs(start+match.index-index);if(current<distance){closest=match[0];distance=current;}}
  if(closest)return closest;return text.slice(Math.max(0,index-100),Math.min(text.length,index+100)).match(pattern)?.[0]||null;
}
function addSys(item){const key=`${item.label}|${item.at||''}`;if(seenSys.has(key)||results.sysIntegrity.length>=8)return;seenSys.add(key);results.sysIntegrity.push(item);}
function addHit(category,label,path,text,index,atOverride=null) {
  const at=atOverride||timestampNear(text,index),source=cleanPath(path),countKey=`${category}|${label}|${source}`;
  if(category==='pc'&&!at)return;
  let detail='';
  if(category==='profiles'){
    const area=text.slice(Math.max(0,index-240),Math.min(text.length,index+480));
    const key='(?:PayloadIdentifier|ProfileIdentifier|ProfileUUID|PayloadUUID|profileIdentifier|profileUUID|Identifier)';
    const plistValue=area.match(new RegExp(`${key}\\s*<\\/key>\\s*<string>([^<]{4,160})`,'i'));
    const tagged=area.match(new RegExp(`${key}[\\s"'=:\\[\\]]+([A-Za-z0-9._-]{4,160})`,'i'));
    const hashId=area.match(/\b(?:[a-f0-9]{40}|[a-f0-9]{32}|[a-f0-9]{64})\b/i);
    const bundle=area.match(/\b[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+){2,}\b/);
    detail=plistValue?.[1]||tagged?.[1]||hashId?.[0]||bundle?.[0]||'';
  }
  const dedupe=`${category}|${label}|${source}|${at||'sem-horario'}|${detail}`;
  if(seenSignals.has(dedupe))return;seenSignals.add(dedupe);
  const count=hitCounts.get(countKey)||0,perSourceCap=category==='profiles'?12:category==='jailbreak'?3:4;if(count>=perSourceCap||results.hits[category].length>=25)return;hitCounts.set(countKey,count+1);
  results.hits[category].push({label,at,detail,dedupe,source});
}
function flattenPlist(value,out=[],depth=0,budget={count:0}){
  if(depth>16||budget.count++>20000||budget.bytes>MAX_SELECTED_FILE)return out;
  if(typeof value==='string'){const item=value.slice(0,4096);out.push(item);budget.bytes=(budget.bytes||0)+item.length;return out;}
  if(Array.isArray(value)){for(const item of value)flattenPlist(item,out,depth+1,budget);return out;}
  if(value&&typeof value==='object'&&!(value instanceof Uint8Array)&&!(value instanceof Date)){
    for(const [key,item] of Object.entries(value)){if(/(?:PayloadIdentifier|PayloadUUID|PayloadDisplayName|ProfileIdentifier|ProfileUUID|Identifier|Name|Label)/i.test(key)){out.push(key);budget.bytes=(budget.bytes||0)+key.length;}flattenPlist(item,out,depth+1,budget);}
  }
  return out;
}
function dateValue(value){if(value instanceof Date&&!Number.isNaN(value.getTime()))return value.toISOString();if(typeof value==='string'&&value){const d=new Date(value);if(!Number.isNaN(d.getTime()))return d.toISOString();}return null;}
function profileEvent(value){let latest=null;const visit=x=>{if(Array.isArray(x)){for(const item of x)visit(item);return;}if(!x||typeof x!=='object'||x instanceof Date||x instanceof Uint8Array)return;
    if(typeof x.event==='string'&&x.timestamp){const at=dateValue(x.timestamp);if(at&&(!latest||at>latest.at))latest={event:x.event.toLowerCase(),at};}
    for(const item of Object.values(x))visit(item);
  };visit(value);return latest;}
function scanPlistSignals(obj,path){
  const inspectString=(source,field,at)=>{
    if(!source)return;
    TOOL_PATTERN.lastIndex=0;let m;while((m=TOOL_PATTERN.exec(source)))addHit('certificates',TOOL_NAMES.find(n=>new RegExp(`^${n.replace(' ','[\\s_-]+')}$`,'i').test(m[0]))||m[0],path,`${field}: ${source}`,source.indexOf(m[0]),at);
    JAILBREAK_PATTERN.lastIndex=0;while((m=JAILBREAK_PATTERN.exec(source)))addHit('jailbreak',m[0],path,`${field}: ${source}`,source.indexOf(m[0]),at);
  };
  const visit=(value,parentAt=null)=>{
    if(Array.isArray(value)){for(const item of value)visit(item,parentAt);return;}
    if(!value||typeof value!=='object'||value instanceof Date||value instanceof Uint8Array)return;
    const ownAt=dateValue(value.timestamp)||parentAt;
    if(typeof value.event==='string'&&ownAt){
      const context=Object.entries(value).filter(([k,v])=>k!=='timestamp'&&typeof v==='string').map(([k,v])=>`${k}: ${v}`).join(' ');
      inspectString(context,'Event',ownAt);
    }
    for(const [key,item] of Object.entries(value)){
      inspectString(key,'Plist key',ownAt);
      if(typeof item==='string')inspectString(item,'Plist value',ownAt);else visit(item,ownAt);
    }
  };visit(obj);
}
function inspectProfileInventory(obj,path){
  for(const groupName of ['SystemProfileRestrictions','UserProfileRestrictions']){
    const group=obj?.[groupName];if(!group||typeof group!=='object'||Array.isArray(group))continue;
    const addNestedIds=(value,parentKey='')=>{
      if(Array.isArray(value)){for(const item of value)addNestedIds(item,parentKey);return;}
      if(!value||typeof value!=='object'||value instanceof Date||value instanceof Uint8Array)return;
      for(const [key,item] of Object.entries(value)){
        if(typeof item==='string'&&/(?:profile|payload|identifier|uuid)/i.test(`${parentKey} ${key}`)&&/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(item)){
          const event=profileEvent(value),removed=/remove|uninstall|delete/i.test(event?.event||'');
          const line=`Profile identifier: ${item} | Event: ${event?.event||'inventory'} | Timestamp: ${event?.at||''}`;
          addHit('profiles',removed?'Perfil removido':'Perfil instalado',path,line,line.indexOf(item),event?.at||null);
        }else addNestedIds(item,key);
      }
    };
    addNestedIds(group);
    for(const [identifier,value] of Object.entries(group)){
      const id=String(identifier),tool=TOOL_NAMES.find(name=>new RegExp(`\\b${name.replace(' ','[\\s_-]+')}\\b`,'i').test(id));
      const hash=/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(id),profile=/\.profile$/i.test(id);
      const event=profileEvent(value),bundle=/^[a-z0-9_-]+(?:\.[a-z0-9_-]+){2,}$/i.test(id)&&!/^com\.apple\./i.test(id)&&Boolean(event);
      if(!tool&&!hash&&!profile&&!bundle)continue;
      const removed=/remove|uninstall|delete/i.test(event?.event||'')||/(?:removed|uninstalled|deleted)/i.test(id);
      const status=removed?'Perfil removido':'Perfil instalado';
      const label=tool?`${status} — ${tool}`:status;
      const line=`Identifier: ${id} | Event: ${event?.event||'inventory'} | Timestamp: ${event?.at||''}`;
      addHit('profiles',label,path,line,line.indexOf(id),event?.at||null);
      if(tool)addHit('certificates',tool,path,line,line.indexOf(id),event?.at||null);
    }
  }
}
function inspectText(raw,path,binaryBytes=null) {
  if(!raw)return; const text=raw.replaceAll('\0','').slice(0,MAX_SELECTED_FILE), pathLower=cleanPath(path);
  results.filesSeen++; results.sources.add(path||'arquivo sem nome');
  let plistText='',plistObject=null;
  if(binaryBytes?.length>=8&&String.fromCharCode(...binaryBytes.subarray(0,8))==='bplist00'){
    try{const obj=parseBinaryPlist(binaryBytes.subarray(0,MAX_SELECTED_FILE));plistObject=obj;plistText=flattenPlist(obj).join('\n');
      const id=obj?.PayloadIdentifier||obj?.PayloadUUID||obj?.UUID||'';
      const display=obj?.PayloadDisplayName||obj?.Name||'';
      const looksLikeProfile=Boolean(id||obj?.PayloadType==='Configuration');
      if(looksLikeProfile){const label=/(?:remov|uninstall|delet)/i.test(pathLower)?'Perfil removido':'Perfil instalado';addHit('profiles',label,path,`${display} ${id} ${plistText}`,0);}
    }catch{binaryPlists.add(path);}
  }
  if(!plistObject&&/\.plist$/i.test(pathLower)&&text.startsWith('<?xml'))try{plistObject=parsePlist(text);plistText=flattenPlist(plistObject).join('\n');}catch{}
  if(plistObject&&/(?:mcprofileevents|mcsettingsevents)\.plist$/i.test(pathLower)){
    scanPlistSignals(plistObject,path);inspectProfileInventory(plistObject,path);
    if(/mcprofileevents\.plist$/i.test(pathLower)){mcProfileEventsSeen=true;addSys({label:'MCState padrão: McProfileEvents.plist legível',status:'found'});}
    if(/mcsettingsevents\.plist$/i.test(pathLower)){mcSettingsEventsSeen=true;addSys({label:'MCState padrão: MCSettingsEvents.plist legível',status:'found'});}
  }
  const profileEvents=[];
  for(const [label,pattern] of FINDINGS.profiles){pattern.lastIndex=0;let m;while((m=pattern.exec(text))&&profileEvents.length<24)profileEvents.push({label,index:m.index});}
  const structuredMcState=/(?:mcprofileevents|mcsettingsevents)\.plist$/i.test(pathLower);
  for(const [category,patterns] of Object.entries(FINDINGS)){if(structuredMcState&&['certificates','jailbreak'].includes(category))continue;for(const [label,pattern] of patterns){pattern.lastIndex=0;let m,count=0;while((m=pattern.exec(text))&&count++<12)addHit(category,label,path,text,m.index);}}
  const toolNames=TOOL_NAMES;
  for(const event of profileEvents){const areaStart=Math.max(0,event.index-256),areaEnd=Math.min(text.length,event.index+512),area=text.slice(areaStart,areaEnd);for(const tool of toolNames){const match=new RegExp(`\\b${tool.replace(' ','[\\s_-]+')}\\b`,'i').exec(area);if(match)addHit('profiles',`${event.label} — ${tool}`,path,text,areaStart+match.index);}}
  if(plistText)for(const [category,patterns] of Object.entries(FINDINGS)){if(structuredMcState&&['certificates','jailbreak'].includes(category))continue;for(const [label,pattern] of patterns){pattern.lastIndex=0;let m,count=0;while((m=pattern.exec(plistText))&&count++<12)addHit(category,label,path,plistText,m.index);}}
  const versions=text.match(/\b(?:iPhone OS|iOS|ProductVersion|SystemVersion)\s*[:=]?\s*(\d{2}(?:\.\d+){1,2})\b/ig)||[];
  for(const value of versions){const m=value.match(/(\d{2}(?:\.\d+){1,2})/);if(m&&!results.ios.includes(m[1]))results.ios.push(m[1]);}
  if(/(?:^|\/)(?:sys\/logs\/skywalk|logs\/networking\/skywalk)(?:\/|\.txt|$)/i.test(pathLower))for(const target of ['freefire','freefiremax'])if(new RegExp(`\\b${target}\\b`,'i').test(text)){skywalkFound.add(target);addSys({label:`Skywalk: ${target} encontrado`,at:timestampNear(text,text.search(new RegExp(`\\b${target}\\b`,'i'))),status:'found'});}
  if(/(?:^|\/)sys\/summaries\/mcstate\.log$/i.test(pathLower)||/(?:^|\/)summaries\/mcstate\.log$/i.test(pathLower)){
    mcstateSeen=true;
    for(const [signature,name] of [['/McProfileEvents.plist,','McProfileEvents.plist'],['/McSettingsEvents.plist,','McSettingsEvents.plist']]){
      const index=text.indexOf(signature),ok=index>=0;
      addSys({label:ok?`McState: ${name} original`:`SYS MANIPULADA: ${name} ausente ou alterado`,at:ok?timestampNear(text,index):null,status:ok?'original':'suspected'});
    }
  }
  if(/\.(?:mobileprovision|plist|xml|log)$/i.test(pathLower)&&/(?:profile|provision)/i.test(pathLower)){
    const inventory=text.match(/(?:PayloadIdentifier|ProfileIdentifier|Identifier)\s*(?:<\/key>\s*<string>|["'=:\s]+)\s*([A-Za-z0-9._-]{4,160})/i);
    if(inventory)addHit('profiles','Perfil em inventário/provisionamento',path,text,text.indexOf(inventory[1]));
    for(const tool of toolNames){
      const match=new RegExp(`\\b${tool}\\b`,'i').exec(text);
      if(match)addHit('profiles',`Perfil associado a ${tool}`,path,text,match.index);
    }
  }
  if(/\.(?:plist|mobileconfig|mobileprovision)$/i.test(pathLower)&&!binaryBytes&&text.startsWith('bplist'))binaryPlists.add(path);
  if(/\.(?:plist|mobileconfig|mobileprovision)$/i.test(pathLower)&&!text.startsWith('bplist')){
    const id=text.match(/<key>(?:PayloadIdentifier|ProfileIdentifier|Identifier)<\/key>\s*<string>([^<]{4,160})/i)?.[1]||text.match(/(?:PayloadIdentifier|ProfileIdentifier)[\s"'=:\[]+([A-Za-z0-9._-]{4,160})/i)?.[1];
    const profileType=/<key>PayloadType<\/key>\s*<string>Configuration<\/string>/i.test(text);
    if(id||profileType)addHit('profiles',/(?:remov|uninstall|delet)/i.test(pathLower)?'Perfil removido':'Perfil instalado',path,text,id?text.indexOf(id):0);
  }
}
function select(path){const normalized=String(path).replace(/\.(?:gz|gzip)$/i,'');return ACCEPTED.test(normalized)||/(?:mcstate|profile|certificate|cert|trust|pair|lockdown|skywalk|systemversion)/i.test(normalized);}
function emitFinal(){
  for(const target of ['freefire','freefiremax'])if(!skywalkFound.has(target))addSys({label:`SYS MANIPULADA: log ${target} ausente em Skywalk`,status:'suspected'});
  if(!mcstateSeen){const modern=mcProfileEventsSeen&&mcSettingsEventsSeen;addSys({label:modern?'SYS MANIPULADA: McState.log com assinaturas originais ausente; plist MCState moderno presente':'SYS MANIPULADA: sys/summaries/McState.log ausente',status:'suspected'});}
  const categories=Object.fromEntries(Object.entries(results.hits).map(([k,v])=>[k,v.map(({dedupe,source,...item})=>item)]));
  const warnings=[...new Set(results.warnings)].slice(0,4);if(binaryPlists.size)warnings.push(`${binaryPlists.size} plist(s) binário(s) não decodificado(s).`);
  send('done',{report:{categories,iosVersions:results.ios,sysIntegrity:results.sysIntegrity,filesRead:results.filesSeen,expandedBytes:results.bytesExpanded,warnings,disclaimer:'Triagem heurística limitada aos arquivos lidos e às regras solicitadas. Um indicador precisa ser conferido no arquivo original; ausência de evidência não prova que o iPhone esteja limpo.'}});
}
async function consumeTar(file){
  const head=new Uint8Array(await file.slice(0,4).arrayBuffer());
  const isGzip=/\.(?:gz|gzip)$/i.test(file.name)||(head[0]===0x1f&&head[1]===0x8b);
  return new Promise((resolve,reject)=>{
    const decoder=new TextDecoder(), selected=true,nestedTasks=[];let text='',settled=false;
    const finish=()=>{if(!settled){settled=true;if(mode==='raw'&&selected)inspectText(text,file.name);Promise.all(nestedTasks).then(resolve,reject);}};
    let mode='detect',buffer=new Uint8Array(0),state='header',remaining=0,pad=0,current=null,parts=[],partBytes=0;
    const append=(a,b)=>{const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;};
    const collect=(piece)=>{if(current?.selected&&partBytes<MAX_SELECTED_FILE){const keep=piece.subarray(0,Math.min(piece.length,MAX_SELECTED_FILE-partBytes));if(keep.length){parts.push(keep.slice());partBytes+=keep.length;}}};
    const finalizeEntry=()=>{if(current){if(current.zipState)current.zipState.push(new Uint8Array(),true);else if(current.selected){const joined=new Uint8Array(partBytes);let offset=0;for(const p of parts){joined.set(p,offset);offset+=p.length;}inspectText(decoder.decode(joined),current.name,joined);}}
      parts=[];partBytes=0;current=null;state='header';};
    const process=(chunk,final=false)=>{
      if(stopped){finish();return;}
      if(mode==='detect'){buffer=append(buffer,chunk);if(buffer.length<512&&!final)return;const tar=buffer.length>=262&&String.fromCharCode(...buffer.slice(257,262))==='ustar';mode=tar?'tar':'raw';chunk=buffer;buffer=new Uint8Array(0);}
      if(mode==='raw'){if(selected&&text.length<MAX_SELECTED_FILE)text+=decoder.decode(chunk,{stream:!final}).slice(0,MAX_SELECTED_FILE-text.length);if(final)finish();return;}
      buffer=append(buffer,chunk);let cursor=0;
      while(cursor<buffer.length){
        if(state==='header'){
          if(buffer.length-cursor<512)break;
          const h=buffer.subarray(cursor,cursor+512);cursor+=512;
          if(h.every(x=>x===0)){state='done';continue;}
          const part=new TextDecoder().decode(h.subarray(345,500)).replace(/\0.*$/s,'').trim();
          const base=new TextDecoder().decode(h.subarray(0,100)).replace(/\0.*$/s,'').trim();
          const name=part?`${part}/${base}`:base;const octal=new TextDecoder().decode(h.subarray(124,136)).replace(/\0.*$/s,'').trim();
          const size=parseInt(octal.replace(/[^0-7]/g,''),8)||0;current={name,selected:select(name),size,probe:new Uint8Array(0),zipState:null};remaining=size;pad=(512-(size%512))%512;state=size?'data':(pad?'padding':'header');if(!size&&!pad)finalizeEntry();
        } else if(state==='data'){
          const n=Math.min(remaining,buffer.length-cursor),piece=buffer.subarray(cursor,cursor+n);cursor+=n;remaining-=n;
          if(current?.zipState)current.zipState.push(piece,false);
          else if(current?.probe.length<4){
            const needed=4-current.probe.length,take=Math.min(needed,piece.length);current.probe=append(current.probe,piece.subarray(0,take));
            if(current.probe.length===4){const sig=current.probe;const isNestedZip=sig[0]===0x50&&sig[1]===0x4b&&[0x03,0x05,0x07].includes(sig[2]);
              if(isNestedZip){current.zipState=createZipScanState(current.size);nestedTasks.push(current.zipState.promise);current.zipState.push(sig,false);}
              else collect(sig);
            }
            if(take<piece.length){const rest=piece.subarray(take);if(current.zipState)current.zipState.push(rest,false);else collect(rest);}
          }else collect(piece);
          if(remaining===0){if(pad)state='padding';else finalizeEntry();}
        } else if(state==='padding'){
          const n=Math.min(pad,buffer.length-cursor);cursor+=n;pad-=n;if(!pad)finalizeEntry();
        } else break;
      }
      buffer=buffer.slice(cursor);
      if(final){if(mode==='raw'&&selected)text+=decoder.decode();else if(current)finalizeEntry();finish();}
    };
    const onExpanded=(chunk,final)=>{
      results.bytesExpanded+=chunk.length;
      if(results.bytesExpanded>MAX_TOTAL){stopped=true;results.warnings.push('Limite de 1 GiB de conteúdo extraído atingido; o restante foi interrompido.');finish();return;}
      process(chunk,final);progress('extract',Math.min(98,Math.floor(results.bytesExpanded/MAX_TOTAL*100)));
    };
    if(isGzip){const gunzip=new Gunzip((chunk,final)=>{onExpanded(chunk,final);});
      const reader=file.stream().getReader();(async()=>{try{while(!stopped){const {value,done}=await reader.read();if(done){gunzip.push(new Uint8Array(),true);progress('extract',100);return;}gunzip.push(value,false);}finish();}catch(e){reject(e)}})();
    }else{
      const reader=file.stream().getReader();(async()=>{try{while(!stopped){const {value,done}=await reader.read();if(done){onExpanded(new Uint8Array(),true);progress('extract',100);return;}onExpanded(value,false);}finish();}catch(e){reject(e)}})();
    }
  });
}
function createZipScanState(expectedSize=0){
  const tasks=[],cancelers=new Set();let totalIn=0,ended=false;
  let resolvePromise,rejectPromise;const promise=new Promise((resolve,reject)=>{resolvePromise=resolve;rejectPromise=reject;});
  const unzipper=new Unzip(entry=>{
    if(++entriesSeen>10000){stopped=true;results.warnings.push('Limite de 10.000 entradas do arquivo atingido para proteger o navegador.');for(const cancel of [...cancelers])cancel();return;}
    tasks.push(new Promise(done=>{
      const selected=select(entry.name),decoder=new TextDecoder(),byteParts=[];let byteLength=0,text='',settled=false,cancel;
      const finish=()=>{if(!settled){settled=true;cancelers.delete(cancel);if(selected){let bytes=null;if(/\.(?:plist|mobileconfig|mobileprovision)$/i.test(entry.name)){bytes=new Uint8Array(byteLength);let offset=0;for(const part of byteParts){bytes.set(part,offset);offset+=part.length;}}inspectText(text,entry.name,bytes);}done();}};
      cancel=()=>{entry.terminate?.();finish();};cancelers.add(cancel);
      const addText=(data,final=false)=>{if(!selected)return;if(text.length<MAX_SELECTED_FILE)text+=decoder.decode(data,{stream:!final}).slice(0,MAX_SELECTED_FILE-text.length);if(final)text+=decoder.decode();};
      const nestedGzip=selected&&/\.(?:gz|gzip)$/i.test(entry.name)?new Gunzip((data,final)=>{results.bytesExpanded+=data.length;if(results.bytesExpanded>MAX_TOTAL){stopped=true;results.warnings.push('Limite de 1 GiB de conteúdo extraído atingido; o restante foi interrompido.');for(const stop of [...cancelers])stop();return;}addText(data,final);if(final)finish();}):null;
      entry.ondata=(err,chunk,final)=>{
        if(err){results.warnings.push(`Falha ao extrair ${entry.name}: ${err.message||err}`);finish();return;}
        results.bytesExpanded+=chunk.length;
        if(results.bytesExpanded>MAX_TOTAL){stopped=true;results.warnings.push('Limite de 1 GiB de conteúdo extraído atingido; o restante foi interrompido.');for(const stop of [...cancelers])stop();return;}
        if(!nestedGzip&&selected&&text.length<MAX_SELECTED_FILE)text+=decoder.decode(chunk,{stream:!final}).slice(0,MAX_SELECTED_FILE-text.length);
        if(selected&&/\.(?:plist|mobileconfig|mobileprovision)$/i.test(entry.name)&&byteLength<MAX_SELECTED_FILE){const piece=chunk.subarray(0,Math.min(chunk.length,MAX_SELECTED_FILE-byteLength));if(piece.length){byteParts.push(piece.slice());byteLength+=piece.length;}}
        progress('extract',Math.min(98,Math.floor(totalIn/Math.max(1,expectedSize||totalIn)*100)));
        if(nestedGzip){try{nestedGzip.push(chunk,final);}catch{results.warnings.push(`GZIP interno inválido: ${entry.name}`);finish();}return;}
        if(final){if(selected)text+=decoder.decode();finish();}
      };
      try{entry.start();}catch{results.warnings.push(`Formato ZIP não suportado em ${entry.name}`);finish();}
    }));
  });
  unzipper.register(UnzipInflate);unzipper.register(UnzipPassThrough);
  const push=(chunk,final=false)=>{
    if(ended)return;try{if(chunk?.length){totalIn+=chunk.length;unzipper.push(chunk,false);}if(final){ended=true;unzipper.push(new Uint8Array(),true);Promise.all(tasks).then(resolvePromise,rejectPromise);progress('extract',100);}}catch(e){ended=true;rejectPromise(e);}
  };
  return{push,promise};
}
async function scanZip(file){
  const state=createZipScanState(file.size),reader=file.stream().getReader();
  try{while(!stopped){const{value,done}=await reader.read();if(done)break;state.push(value,false);}state.push(new Uint8Array(),true);await state.promise;}
  catch(e){throw e;}
}
async function scan(file){
  stopped=false;lastProgress=0;mcstateSeen=false;mcProfileEventsSeen=false;mcSettingsEventsSeen=false;entriesSeen=0;results.filesSeen=0;results.bytesExpanded=0;results.ios.length=0;results.sysIntegrity.length=0;results.sources.clear();results.warnings.length=0;for(const list of Object.values(results.hits))list.length=0;seenSignals.clear();hitCounts.clear();skywalkFound.clear();binaryPlists.clear();seenSys.clear();
  const lower=file.name.toLowerCase();
  if(file.size>2*1024**3)throw new Error('O arquivo ultrapassa o limite selecionado de 2 GiB.');
  const probe=new Uint8Array(await file.slice(0,512).arrayBuffer());
  const isZip=probe[0]===0x50&&probe[1]===0x4b&&[0x03,0x05,0x07].includes(probe[2]);
  const isGzip=probe[0]===0x1f&&probe[1]===0x8b;
  const isTar=probe.length>=262&&String.fromCharCode(...probe.subarray(257,262))==='ustar';
  if(isZip||lower.endsWith('.zip'))await scanZip(file);
  else if(isGzip||isTar||lower.endsWith('.tar')||lower.endsWith('.tar.gz')||lower.endsWith('.tgz')||lower.endsWith('.gz')||lower.endsWith('.gzip'))await consumeTar(file);
  else{
    if(file.size>MAX_SELECTED_FILE){results.warnings.push(`${file.name}: arquivo individual acima de 12 MiB omitido para proteger a memória do navegador.`);}
    else{const bytes=new Uint8Array(await file.arrayBuffer()),text=new TextDecoder().decode(bytes);results.bytesExpanded+=file.size;inspectText(text,file.name,bytes);}
  }
  progress('analysis',100);emitFinal();
}
self.onmessage=async event=>{if(event.data?.type==='scan')try{await scan(event.data.file)}catch(error){send('error',{message:`Não foi possível concluir a leitura: ${error.message||error}`})}};
