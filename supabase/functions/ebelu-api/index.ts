import { createClient } from "npm:@supabase/supabase-js@2";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const FUNCTION_URL = SUPABASE_URL + "/functions/v1/ebelu-api";
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ORIGIN = "*";
const cors = {"Access-Control-Allow-Origin":ORIGIN,"Access-Control-Allow-Headers":"authorization, apikey, content-type, x-client-info, x-ebelu-admin-session","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin"};
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{...cors,"Content-Type":"application/json","Cache-Control":"no-store, max-age=0","Pragma":"no-cache"}});
const db=createClient(SUPABASE_URL,SERVICE,{auth:{persistSession:false,autoRefreshToken:false}});
async function sha(s:string){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");}
function code(){return [...crypto.getRandomValues(new Uint8Array(12))].map(x=>x.toString(16).padStart(2,"0")).join("").toUpperCase();}
function voucherCode(){const letters="ABCDEFGHJKLMNPQRSTUVWXYZ",digits="0123456789";const bytes=crypto.getRandomValues(new Uint8Array(6));return [...bytes.slice(0,3)].map(x=>letters[x%letters.length]).join("")+"-"+[...bytes.slice(3)].map(x=>digits[x%10]).join("");}
function safeEqual(a:string,b:string){const x=new TextEncoder().encode(a),y=new TextEncoder().encode(b);if(x.length!==y.length)return false;let d=0;for(let i=0;i<x.length;i++)d|=x[i]^y[i];return d===0;}
function clientKey(req:Request){return req.headers.get("cf-connecting-ip")||req.headers.get("x-real-ip")||"unknown";}
async function createIssueTicket(issueId:string){
 const token=[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,"0")).join("");
 const {error}=await db.from("ebelu_issue_tickets").insert({token_hash:await sha(token),issue_id:issueId,expires_at:new Date(Date.now()+10*60*1000).toISOString()});
 if(error)throw new Error("Einmal-Link konnte nicht erstellt werden.");
 return FUNCTION_URL+"?ticket="+token;
}
async function limited(prefix:string,req:Request){const {data,error}=await db.rpc("ebelu_consume_rate_limit",{p_key_hash:await sha(prefix+":"+clientKey(req))});if(error){console.error("Rate limit RPC failed",error);return true;}return data===true;}
async function isAdmin(req:Request){
 const expected=Deno.env.get("EBELU_AKTUELL_PASSWORT")||"";
 const token=req.headers.get("x-ebelu-admin-session")||"";
 if(!expected||token.length<32)return false;
 const {data,error}=await db.from("ebelu_admin_sessions").select("id,password_hash,expires_at").eq("token_hash",await sha(token)).maybeSingle();
 if(error||!data)return false;
 if(data.password_hash!==await sha(expected)||new Date(data.expires_at).getTime()<=Date.now()){
  await db.from("ebelu_admin_sessions").delete().eq("id",data.id);
  return false;
 }
 return true;
}
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
 if(req.method==="GET"){
  const token=new globalThis.URL(req.url).searchParams.get("ticket")||"";
  if(!/^[a-f0-9]{64}$/.test(token))return json({error:"Dieser Einmal-Link ist ungültig."},400);
  const now=new Date().toISOString();
  const {data:ticket,error:ticketError}=await db.from("ebelu_issue_tickets").update({consumed_at:now}).eq("token_hash",await sha(token)).is("consumed_at",null).gt("expires_at",now).select("issue_id").maybeSingle();
  if(ticketError)return json({error:"Einmal-Link konnte nicht geprüft werden."},503);
  if(!ticket)return json({error:"Dieser Link wurde bereits verwendet oder ist abgelaufen."},410);
  const {data:issue,error:issueError}=await db.from("ebelu_issues").select("title,file_path").eq("id",ticket.issue_id).maybeSingle();
  if(issueError||!issue)return json({error:"Ausgabe nicht gefunden."},404);
  const {data:file,error:fileError}=await db.storage.from("ebelu-issues").download(issue.file_path);
  if(fileError||!file)return json({error:"PDF konnte nicht geladen werden."},503);
  const filename=(String(issue.title||"Ebelu-Aktuell").replace(/[^a-zA-Z0-9äöüÄÖÜß_-]+/g,"-").slice(0,80)||"Ebelu-Aktuell")+".pdf";
  return new Response(await file.arrayBuffer(),{status:200,headers:{...cors,"Content-Type":"application/pdf","Content-Disposition":'inline; filename="'+filename+'"',"Cache-Control":"no-store, max-age=0","Pragma":"no-cache","X-Content-Type-Options":"nosniff"}});
 }
 if(req.method!=="POST")return json({error:"Method not allowed"},405);
 const origin=req.headers.get("Origin");if(origin&&origin!=="https://lordlolqdh.github.io"&&origin!=="https://ebelu-aktuell.pntr.dev")return json({error:"Origin not allowed"},403);
 try{
  const len=Number(req.headers.get("Content-Length")||0);if(len>16*1024*1024)return json({error:"Datei zu groß."},413);
  const ct=req.headers.get("Content-Type")||"";let body:Record<string,unknown>={};let form:FormData|null=null;
  if(ct.includes("multipart/form-data"))form=await req.formData();else body=await req.json();
  const action=String(form?.get("action")||body.action||"");
  if(action==="admin-login"){
   const expected=Deno.env.get("EBELU_AKTUELL_PASSWORT")||"";
   if(!expected)return json({error:"Das Admin-Passwort ist auf dem Server nicht eingerichtet. Bitte das vorhandene Secret EBELU_AKTUELL_PASSWORT prüfen."},503);
   if(!safeEqual(String(body.password||""),expected))return json({error:"Das eingegebene Admin-Passwort ist falsch."},401);
   const token=code()+code();const {error}=await db.from("ebelu_admin_sessions").insert({token_hash:await sha(token),password_hash:await sha(expected),expires_at:new Date(Date.now()+36500*86400000).toISOString()});if(error)return json({error:"Anmeldung konnte nicht gespeichert werden."},500);return json({success:true,token});
  }
  if(action==="ai-chat"){
   if(!await limited("ai-chat",req))return json({error:"Zu viele Nachrichten. Bitte warte kurz und versuche es erneut."},429);
   const incoming=Array.isArray(body.messages)?body.messages:[];
   const messages=incoming.slice(-10).filter((m:Record<string,unknown>)=>(m.role==="user"||m.role==="assistant")&&typeof m.content==="string").map((m:Record<string,unknown>)=>({role:m.role,content:String(m.content).slice(0,1800)}));
   if(!messages.length||messages[messages.length-1].role!=="user")return json({error:"Bitte gib zuerst eine Frage ein."},400);
   if(messages[messages.length-1].content.trim().length<2)return json({error:"Deine Frage ist zu kurz."},400);
   const {data:recentIssues}=await db.from("ebelu_issues").select("title,edition_number,description").eq("published",true).order("edition_number",{ascending:false}).limit(12);
   const issueContext=(recentIssues||[]).map((i:Record<string,unknown>)=>"Ausgabe "+i.edition_number+": "+i.title+" – "+(i.description||"Keine Beschreibung")).join("\n");
   const system="Du bist der freundliche KI-Assistent von Ebelu Aktuell, einer Schülerzeitung am Ebelu in Stuttgart. Antworte auf Deutsch, verständlich, freundlich und altersgerecht. Hilf bei Schulthemen, erkläre Begriffe und unterstütze beim Lernen, ohne Hausaufgaben nur stumpf zu erledigen. Bei Fragen zu Ebelu Aktuell darfst du nur die unten aufgeführten Ausgaben als bekannte Inhalte nennen. Du hast keinen Zugriff auf vollständige PDF-Artikel oder Live-Websuche. Erfinde keine Artikel, Termine, Personen oder Schulregeln. Wenn du etwas nicht weißt, sage es offen und verweise auf die Redaktion. Gib keine privaten Daten von Schülern preis. Bei persönlichen Krisen oder Gefahren verweise auf eine vertrauenswürdige erwachsene Person.\n\nBekannte veröffentlichte Ausgaben:\n"+(issueContext||"Noch keine veröffentlichten Ausgaben verfügbar.");
   // Failover: try each provider with a configured key, in order. Any network,
   // HTTP, or malformed-response error advances to the next configured provider.
   const providers=[
    {name:"Groq",key:Deno.env.get("GROQ-EBELU")||Deno.env.get("GROQ_EBELU")||"",url:"https://api.groq.com/openai/v1/chat/completions",model:"openai/gpt-oss-120b"},
    {name:"OpenRouter",key:Deno.env.get("OPENROUTER_EBELU")||"",url:"https://openrouter.ai/api/v1/chat/completions",model:Deno.env.get("OPENROUTER_EBELU_MODEL")||"meta-llama/llama-3.3-70b-instruct"},
    {name:"Cerebras",key:Deno.env.get("CEREBRAS_EBELU")||"",url:"https://api.cerebras.ai/v1/chat/completions",model:Deno.env.get("CEREBRAS_EBELU_MODEL")||"llama-3.3-70b"},
    {name:"Together",key:Deno.env.get("TOGETHER_EBELU")||"",url:"https://api.together.xyz/v1/chat/completions",model:Deno.env.get("TOGETHER_EBELU_MODEL")||"meta-llama/Llama-3.3-70B-Instruct-Turbo"}
   ].filter(p=>p.key);
   if(!providers.length)return json({error:"Kein KI-Anbieter ist konfiguriert. Bitte mindestens GROQ-EBELU oder einen Backup-Key hinterlegen."},503);
   const failures:string[]=[];
   for(const provider of providers){
    try{
     const response=await fetch(provider.url,{method:"POST",headers:{"Authorization":"Bearer "+provider.key,"Content-Type":"application/json"},body:JSON.stringify({model:provider.model,messages:[{role:"system",content:system},...messages],max_tokens:700,temperature:0.6}),signal:AbortSignal.timeout(12000)});
     if(!response.ok){const detail=await response.text();console.error("AI provider failure",provider.name,response.status,detail.slice(0,300));failures.push(provider.name+": HTTP "+response.status);continue;}
     const result=await response.json();const answer=result?.choices?.[0]?.message?.content;
     if(typeof answer!=="string"||!answer.trim()){failures.push(provider.name+": empty response");continue;}
     return json({success:true,answer:answer.trim(),provider:provider.name});
    }catch(err){console.error("AI provider error",provider.name,String(err));failures.push(provider.name+": network/timeout");}
   }
   const configured=providers.map(p=>p.name);const missing=["OpenRouter","Cerebras","Together"].filter(n=>!configured.includes(n));return json({error:"Alle konfigurierten KI-Anbieter sind fehlgeschlagen. Versucht: "+(configured.join(", ")||"keine")+". Nicht eingerichtet: "+(missing.join(", ")||"keine")+". Backup-Anbieter benötigen ihre API-Secrets in Supabase."},502);
  }
  if(action==="issue-open"){
   if(!await limited("issue",req))return json({error:"Zu viele Versuche. Bitte später erneut versuchen."},429);
   const c=String(body.code||"").trim().toUpperCase();
   const issueId=String(body.issue_id||"").trim();
   if(!/^[0-9a-f-]{36}$/i.test(issueId))return json({error:"Ausgabe nicht gefunden."},400);
   const {data:issue}=await db.from("ebelu_issues").select("id,title").eq("published",true).eq("id",issueId).maybeSingle();
   if(!issue)return json({error:"Diese Ausgabe ist nicht veröffentlicht oder wurde nicht gefunden."},404);
   if(/^[A-Z]{3}-[0-9]{3}$/.test(c)){
    const token=[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,"0")).join("");
    const tokenHash=await sha(token);
    const {error:ticketError}=await db.from("ebelu_issue_tickets").insert({token_hash:tokenHash,issue_id:issue.id,expires_at:new Date(Date.now()+10*60*1000).toISOString()});
    if(ticketError)return json({error:"Einmal-Link konnte nicht erstellt werden."},503);
    const {data:redeemed,error:redeemError}=await db.from("ebelu_vouchers").update({redeemed_at:new Date().toISOString(),redeemed_by:issue.id}).eq("code_hash",await sha(c)).is("redeemed_at",null).is("revoked_at",null).select("id").maybeSingle();
    if(redeemError||!redeemed){await db.from("ebelu_issue_tickets").delete().eq("token_hash",tokenHash);if(redeemError)return json({error:"Gutschein konnte nicht geprüft werden."},503);return json({error:"Gutschein bereits verwendet, gesperrt oder ungültig. Jeder Gutschein kann nur eine Ausgabe einmalig freischalten."},409);}
    await db.from("ebelu_audit_log").insert({actor:null,action:"voucher_redeemed_for_issue",target_id:issue.id});
    return json({title:issue.title,url:FUNCTION_URL+"?ticket="+token,expiresIn:600,access:"voucher"});
   }
   if(!/^[A-F0-9]{24}$/.test(c))return json({error:"Bitte einen gültigen Zugangscode oder Gutschein im Format ABC-123 eingeben."},400);
   const {data:matched}=await db.from("ebelu_issues").select("id").eq("code_hash",await sha(c)).eq("published",true).eq("id",issueId).maybeSingle();
   if(!matched)return json({error:"Code ungültig oder Ausgabe nicht freigegeben."},404);
   const ticketUrl=await createIssueTicket(issue.id);
   return json({title:issue.title,url:ticketUrl,expiresIn:600,access:"issue-code"});
  }
  if(action==="contact-submit"){
   if(!await limited("contact",req))return json({error:"Zu viele Nachrichten. Bitte später erneut versuchen."},429);
   const name=String(body.name||"").trim(),email=String(body.email||"").trim(),subject=String(body.subject||"").trim(),message=String(body.message||"").trim();
   if(name.length<2||name.length>80||!/^\S+@\S+\.\S+$/.test(email)||email.length>254||subject.length<2||subject.length>120||message.length<10||message.length>3000)return json({error:"Bitte überprüfe deine Angaben."},400);
   if(String(body.website||"").trim())return json({success:true,message:"Nachricht erhalten."});
   const {error}=await db.from("ebelu_contact_messages").insert({name,email,subject,message});
   if(error)return json({error:"Nachricht konnte nicht gespeichert werden. Bitte später erneut versuchen."},503);
   return json({success:true,message:"Danke! Deine Nachricht wurde an die Redaktion übermittelt."},201);
  }
  if(action==="voucher-request-submit"){
   if(!await limited("voucher-request",req))return json({error:"Zu viele Gutscheinanfragen. Bitte später erneut versuchen."},429);
   const name=String(body.name||"").trim(),email=String(body.email||"").trim(),reason=String(body.reason||"").trim();
   if(name.length<2||name.length>80||!/^\S+@\S+\.\S+$/.test(email)||email.length>254||reason.length<5||reason.length>1000)return json({error:"Bitte überprüfe deine Angaben."},400);
   if(String(body.website||"").trim())return json({success:true,message:"Anfrage erhalten."});
   const {error}=await db.from("ebelu_voucher_requests").insert({name,email,reason});
   if(error)return json({error:"Gutscheinanfrage konnte nicht gespeichert werden."},503);
   return json({success:true,message:"Deine Gutscheinanfrage wurde an die Redaktion gesendet. Du erhältst nach Prüfung eine Rückmeldung."},201);
  }
  if(action==="voucher-redeem"){
   return json({error:"Bitte wähle zuerst eine veröffentlichte Ausgabe aus und gib den Gutschein direkt auf deren Seite ein. So wird genau diese eine Ausgabe freigeschaltet."},400);
  }
  if(action==="issues-public-list"){
   const {data,error}=await db.from("ebelu_issues").select("id,title,edition_number,description,created_at,file_path").eq("published",true).order("edition_number",{ascending:false});
   if(error)return json({error:"Ausgaben konnten nicht geladen werden."},500);
   const issues=await Promise.all((data||[]).map(async issue=>{
    const {data:signed}=await db.storage.from("ebelu-issues").createSignedUrl(issue.file_path,3600);
    return {id:issue.id,title:issue.title,edition_number:issue.edition_number,description:issue.description,created_at:issue.created_at,previewUrl:signed?.signedUrl||null};
   }));
   return json({issues});
  }
  if(action==="admin-logout"){const token=req.headers.get("x-ebelu-admin-session")||"";if(token)await db.from("ebelu_admin_sessions").delete().eq("token_hash",await sha(token));return json({success:true});}
  if(!await isAdmin(req))return json({error:"Admin-Anmeldung erforderlich."},401);
  if(action==="admin-voucher-requests"){
   const {data,error}=await db.from("ebelu_voucher_requests").select("id,name,email,reason,status,created_at").order("created_at",{ascending:false}).limit(100);
   if(error)return json({error:"Gutscheinanfragen konnten nicht geladen werden."},500);
   return json({requests:data});
  }
  if(action==="admin-voucher-request-process"){
   const id=String(body.id||""),decision=String(body.decision||"");
   if(!/^[0-9a-f-]{36}$/i.test(id)||!["approve","reject"].includes(decision))return json({error:"Ungültige Angaben."},400);
   const {data:request,error:re}=await db.from("ebelu_voucher_requests").select("id,status").eq("id",id).maybeSingle();
   if(re||!request)return json({error:"Anfrage nicht gefunden."},404);
   if(request.status!=="pending")return json({error:"Diese Anfrage wurde bereits bearbeitet."},409);
   if(decision==="reject"){
    const {error}=await db.from("ebelu_voucher_requests").update({status:"rejected",processed_at:new Date().toISOString()}).eq("id",id).eq("status","pending");
    if(error)return json({error:"Anfrage konnte nicht abgelehnt werden."},500);
    return json({success:true,status:"rejected"});
   }
   const voucherCodeValue=voucherCode();
   const {data:voucher,error:ve}=await db.from("ebelu_vouchers").insert({code_hash:await sha(voucherCodeValue)}).select("id").single();
   if(ve||!voucher)return json({error:"Gutschein konnte nicht erstellt werden."},500);
   const {error:ue}=await db.from("ebelu_voucher_requests").update({status:"approved",voucher_id:voucher.id,processed_at:new Date().toISOString()}).eq("id",id).eq("status","pending");
   if(ue){await db.from("ebelu_vouchers").update({revoked_at:new Date().toISOString()}).eq("id",voucher.id);return json({error:"Anfrage konnte nicht abgeschlossen werden."},500);}
   await db.from("ebelu_audit_log").insert({actor:null,action:"voucher_request_approved",target_id:id});
   return json({success:true,status:"approved",code:voucherCodeValue});
  }
  if(action==="admin-messages"){
   const {data,error}=await db.from("ebelu_contact_messages").select("id,name,email,subject,message,status,created_at").order("created_at",{ascending:false}).limit(100);
   if(error)return json({error:"Nachrichten konnten nicht geladen werden."},500);
   return json({messages:data});
  }
  if(action==="admin-message-status"){
   const id=String(body.id||""),status=String(body.status||"");
   if(!/^[0-9a-f-]{36}$/i.test(id)||!["read","closed"].includes(status))return json({error:"Ungültige Angaben."},400);
   const {data,error}=await db.from("ebelu_contact_messages").update({status}).eq("id",id).select("id,status").maybeSingle();
   if(error||!data)return json({error:"Status konnte nicht geändert werden."},404);
   return json({message:data});
  }
  if(action==="admin-list"){
   const [{data:issues,error:ie},{data:vouchers,error:ve}]=await Promise.all([
    db.from("ebelu_issues").select("id,title,edition_number,description,published,created_at").order("edition_number",{ascending:false}),
    db.from("ebelu_vouchers").select("id,redeemed_at,revoked_at,created_at").order("created_at",{ascending:false}).limit(200)
   ]);
   if(ie||ve)return json({error:"Verwaltungsdaten konnten nicht geladen werden."},500);
   return json({issues,vouchers});
  }
  if(action==="admin-upload"&&form){
   const title=String(form.get("title")||"").trim(),edition=Number(form.get("edition_number")),description=String(form.get("description")||"").trim(),file=form.get("pdf");
   if(title.length<2||title.length>120||!Number.isInteger(edition)||edition<1||description.length>1000||!(file instanceof File))return json({error:"Angaben bitte prüfen."},400);
   if(file.type!=="application/pdf"||file.size<8||file.size>15*1024*1024)return json({error:"Nur PDF-Dateien bis 15 MB."},400);
   const bytes=new Uint8Array(await file.arrayBuffer());if(new TextDecoder().decode(bytes.slice(0,5))!=="%PDF-")return json({error:"Ungültige PDF-Datei."},400);
   const id=crypto.randomUUID(),path=id+".pdf",access=code();
   const {error:up}=await db.storage.from("ebelu-issues").upload(path,bytes,{contentType:"application/pdf",upsert:false});
   if(up)return json({error:"Upload fehlgeschlagen."},500);
   const {data,error}=await db.from("ebelu_issues").insert({id,title,edition_number:edition,description,file_path:path,code_hash:await sha(access),published:false}).select("id,title,edition_number").single();
   if(error){await db.storage.from("ebelu-issues").remove([path]);return json({error:"Ausgabe konnte nicht gespeichert werden. Nummer eventuell vergeben."},409);}
   await db.from("ebelu_audit_log").insert({actor:null,action:"issue_uploaded",target_id:id});
   return json({issue:data,accessCode:access},201);
  }
  if(action==="admin-issue-delete"){const id=String(body.id||"");if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Ungültige Ausgabe."},400);const {data:issue,error:readError}=await db.from("ebelu_issues").select("id,file_path").eq("id",id).maybeSingle();if(readError||!issue)return json({error:"Ausgabe nicht gefunden."},404);const {error:removeError}=await db.storage.from("ebelu-issues").remove([issue.file_path]);if(removeError)return json({error:"PDF konnte nicht gelöscht werden."},500);const {error}=await db.from("ebelu_issues").delete().eq("id",id);if(error)return json({error:"Ausgabe konnte nicht gelöscht werden."},500);await db.from("ebelu_audit_log").insert({actor:null,action:"issue_deleted",target_id:id});return json({success:true});}
  if(action==="admin-publish"){
   const id=String(body.id||""),published=body.published===true;
   const {data,error}=await db.from("ebelu_issues").update({published}).eq("id",id).select("id,published").maybeSingle();
   if(error||!data)return json({error:"Status konnte nicht geändert werden."},404);
   await db.from("ebelu_audit_log").insert({actor:null,action:published?"issue_published":"issue_unpublished",target_id:id});
   return json({issue:data});
  }
  if(action==="admin-voucher"){
   const c=voucherCode();const {data,error}=await db.from("ebelu_vouchers").insert({code_hash:await sha(c)}).select("id").single();
   if(error||!data)return json({error:"Gutschein konnte nicht erstellt werden."},500);
   await db.from("ebelu_audit_log").insert({actor:null,action:"voucher_created",target_id:data.id});
   return json({id:data.id,code:c,created_at:new Date().toISOString()},201);
  }
  if(action==="admin-voucher-delete"){const id=String(body.id||"");if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Ungültiger Gutschein."},400);await db.from("ebelu_voucher_requests").update({voucher_id:null}).eq("voucher_id",id);const {data,error}=await db.from("ebelu_vouchers").delete().eq("id",id).select("id").maybeSingle();if(error||!data)return json({error:"Gutschein konnte nicht gelöscht werden."},500);await db.from("ebelu_audit_log").insert({actor:null,action:"voucher_deleted",target_id:id});return json({success:true});}
  if(action==="admin-voucher-revoke"){
   const id=String(body.id||"");if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Ungültige Gutschein-ID."},400);
   const {data,error}=await db.from("ebelu_vouchers").update({revoked_at:new Date().toISOString()}).eq("id",id).is("redeemed_at",null).is("revoked_at",null).select("id").maybeSingle();
   if(error)return json({error:"Gutschein konnte nicht gesperrt werden."},500);
   if(!data)return json({error:"Gutschein ist bereits eingelöst, gesperrt oder existiert nicht."},409);
   await db.from("ebelu_audit_log").insert({actor:null,action:"voucher_revoked",target_id:id});
   return json({success:true});
  }
  return json({error:"Unbekannte Aktion."},400);
 }catch{return json({error:"Anfrage konnte nicht verarbeitet werden."},400);}
});