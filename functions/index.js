const {onRequest}=require("firebase-functions/v2/https");
const {setGlobalOptions}=require("firebase-functions/v2");
const {defineSecret}=require("firebase-functions/params");
const admin=require("firebase-admin");
const crypto=require("crypto");

admin.initializeApp();
setGlobalOptions({region:"asia-northeast1",maxInstances:20});
const db=admin.firestore();
const RESEND_API_KEY=defineSecret("RESEND_API_KEY");
const MAIL_FROM=defineSecret("MAIL_FROM");

const ALLOWED_ORIGINS=new Set([
  "https://wara326-glitch.github.io",
  "http://localhost:5000",
  "http://127.0.0.1:5000"
]);
const TYPES=new Set(["safety","emergency","detail"]);
const REQUIRED=["facility","facilityType","municipality","reporter","phone","email","reportedAt"];
const PRIVATE_FIELDS=new Set(["reporter","phone","email"]);
const ALLOWED=["type","email","facility","facilityType","municipality","reporter","phone","reportedAt","emisStatus","seismic","staffSafety","facilityDamage","careStatus","supportNeeded","safetyNote","building","buildingRisk","power","water","gas","comms","careEmergency","emergencyAccept","inpatientImpact","transferNeed","staffShort","supplyShort","emergencySupport","transportSupport","emergencyNote","detailDamage","flood","fire","gridPower","generator","fuelHours","detailWater","tank","fixedPhone","internet","outpatient","er","ward","surgery","icu","dialysis","delivery","homecare","pharmacy","oxygen","inpatients","transferCount","newAccept","criticalAccept","doctorShort","nurseShort","supplies","detailNote"];

exports.submitReport=onRequest({secrets:[RESEND_API_KEY,MAIL_FROM]},async(req,res)=>{
  const origin=req.get("origin")||"";
  if(ALLOWED_ORIGINS.has(origin)){res.set("Access-Control-Allow-Origin",origin);res.set("Vary","Origin");}
  if(req.method==="OPTIONS"){res.set("Access-Control-Allow-Methods","POST");res.set("Access-Control-Allow-Headers","Content-Type");return res.status(204).send("");}
  if(req.method!=="POST") return res.status(405).json({error:"method_not_allowed"});
  if(!ALLOWED_ORIGINS.has(origin)) return res.status(403).json({error:"origin_not_allowed"});

  const raw=JSON.stringify(req.body||{});
  if(Buffer.byteLength(raw,"utf8")>30000) return res.status(413).json({error:"too_large"});
  const input=req.body||{};
  if(!TYPES.has(input.type)) return res.status(400).json({error:"invalid_type"});
  for(const k of REQUIRED){
    if(typeof input[k]!=="string"||!input[k].trim()) return res.status(400).json({error:"missing_"+k});
  }
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim())||input.email.length>254) return res.status(400).json({error:"invalid_email"});
  if(input.phone.length>50||input.reporter.length>200) return res.status(400).json({error:"invalid_contact"});

  for(const k of ["patientName","patientDob","dateOfBirth","chartNumber","medicalRecordNumber"]){
    if(input[k]!=null) return res.status(400).json({error:"patient_identifier_not_allowed"});
  }

  const publicData={};
  const privateData={};
  for(const k of ALLOWED){
    if(input[k]===undefined) continue;
    const v=input[k];
    let clean;
    if(typeof v==="string"){
      if(v.length>2000) return res.status(400).json({error:"field_too_long"});
      clean=v.trim();
    }else if(typeof v==="number"&&Number.isFinite(v)){
      clean=v;
    }else{
      continue;
    }
    (PRIVATE_FIELDS.has(k)?privateData:publicData)[k]=clean;
  }

  const receiptId="FMA-"+new Date().toISOString().slice(0,10).replaceAll("-","")+"-"+crypto.randomBytes(4).toString("hex").toUpperCase();
  const now=admin.firestore.FieldValue.serverTimestamp();
  Object.assign(publicData,{receiptId,status:"unverified",source:"public-web",createdAt:now,updatedAt:now});
  Object.assign(privateData,{receiptId,createdAt:now,updatedAt:now});

  const batch=db.batch();
  batch.set(db.collection("reports").doc(receiptId),publicData);
  batch.set(db.collection("private_reports").doc(receiptId),privateData);
  await batch.commit();

  const escapeHtml=s=>String(s??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const mailData={...publicData,reporter:privateData.reporter,phone:privateData.phone};
  const rows=Object.entries(mailData)
    .filter(([k,v])=>!["createdAt","updatedAt"].includes(k)&&typeof v==="string"&&v)
    .map(([k,v])=>"<tr><th style='text-align:left;padding:5px'>"+escapeHtml(k)+"</th><td style='padding:5px'>"+escapeHtml(v)+"</td></tr>").join("");

  let mailSent=false;
  try{
    const mr=await fetch("https://api.resend.com/emails",{
      method:"POST",
      headers:{Authorization:"Bearer "+RESEND_API_KEY.value(),"Content-Type":"application/json"},
      body:JSON.stringify({
        from:MAIL_FROM.value(),
        to:[privateData.email],
        subject:"【福島県医師会】災害時医療情報 受付完了 "+receiptId,
        html:"<p>災害時医療情報の報告を受け付けました。</p><p><b>受付番号："+escapeHtml(receiptId)+"</b></p><table>"+rows+"</table><p>このメールは入力内容の控えです。</p>"
      })
    });
    mailSent=mr.ok;
    if(!mr.ok) console.error("receipt mail failed",mr.status);
  }catch(e){console.error("receipt mail error",e);}
  return res.status(201).json({ok:true,receiptId,mailSent});
});
