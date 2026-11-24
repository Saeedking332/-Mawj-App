import { createHash } from "node:crypto";
import { get, put } from "@vercel/blob";
function send(res,status,body){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store, max-age=0");res.end(JSON.stringify(body))}
function validKey(key){return typeof key==="string"&&/^[A-Za-z0-9_-]{43}$/.test(key)}
function isSameOrigin(req){const origin=req.headers.origin;if(!origin)return true;const host=String(req.headers["x-forwarded-host"]||req.headers.host||"").split(",")[0].trim();try{return new URL(origin).host===host}catch{return false}}
export default async function handler(req,res){
 if(req.method!=="POST")return send(res,405,{error:"Method not allowed"});
 if(!isSameOrigin(req))return send(res,403,{error:"Cross-origin request blocked"});
 try{
  let body=req.body;if(Buffer.isBuffer(body))body=body.toString("utf8");if(typeof body==="string")body=JSON.parse(body);
  if(!body||typeof body!=="object"){const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>3*1024*1024)return send(res,413,{error:"Backup is too large"});chunks.push(chunk)}body=JSON.parse(Buffer.concat(chunks).toString("utf8"))}
  if(Buffer.byteLength(JSON.stringify(body))>3*1024*1024)return send(res,413,{error:"Backup is too large"});
  const {action,key}=body;if(!validKey(key))return send(res,400,{error:"Invalid recovery code"});
  const id=createHash("sha256").update(key,"utf8").digest("hex"),pathname="mawj-backups/"+id+".json";
  if(action==="save"){
   const payload=body.payload;
   if(!payload||typeof payload.iv!=="string"||!/^[A-Za-z0-9_-]{16}$/.test(payload.iv)||typeof payload.ciphertext!=="string"||!/^[A-Za-z0-9_-]+$/.test(payload.ciphertext))return send(res,400,{error:"Invalid encrypted backup"});
   const savedAt=Date.now();await put(pathname,JSON.stringify({payload,savedAt}),{access:"private",contentType:"application/json",allowOverwrite:true,cacheControlMaxAge:60});
   return send(res,200,{ok:true,savedAt});
  }
  if(action==="load"){
   const blob=await get(pathname,{access:"private",useCache:false});if(!blob||blob.statusCode!==200)return send(res,404,{error:"No cloud backup found for this recovery code"});
   const stored=await new Response(blob.stream).json();if(!stored?.payload?.iv||!stored?.payload?.ciphertext)return send(res,500,{error:"Stored backup is invalid"});
   return send(res,200,{ok:true,payload:stored.payload,savedAt:stored.savedAt||null});
  }
  return send(res,400,{error:"Unknown backup action"});
 }catch(error){console.error("MAWJ cloud backup API error",error);return send(res,500,{error:"Cloud backup service is temporarily unavailable"})}
}
