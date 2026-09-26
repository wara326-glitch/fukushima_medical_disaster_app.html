const {onRequest}=require("firebase-functions/v2/https");
const {setGlobalOptions}=require("firebase-functions/v2");
const admin=require("firebase-admin");
admin.initializeApp();
setGlobalOptions({region:"asia-northeast1",maxInstances:20});
const db=admin.firestore();
const ALLOWED_ORIGINS=new Set([
 "https://wara326-glitch.github.io",
 "http://localhost:5000",
 "http://127.0.0.1:5000"
]);
const TYPES=new Set(["safety","emergency","detail"]);
const REQUIRED=["facility","facilityType","municipality","reporter","phone","reportedAt"];
const ALLOWED=["type","facility","facilityType","municipality","reporter","phone","reportedAt","emisStatus","seismic","staffSafety","facilityDamage","careStatus","supportNeeded","safetyNote","building","buildingRisk","power","water","gas","comms","careEmergency","emergencyAccept","inpatientImpact","transferNeed","staffShort","supplyShort","emergencySupport","transportSupport","emergencyNote","detailDamage","flood","fire","gridPower","generator","fuelHours","detailWater","tank","fixedPhone","internet","outpatient","er","ward","surgery","icu","dialysis","delivery","homecare","pharmacy","oxygen","inpatients","transferCount","newAccept","criticalAccept","doctorShort","nurseShort","supplies","detailNote"];
exports.submitReport=onRequest(async(req,res)=>{
 const origin=req.get("origin")||"";
 if(ALLOWED_ORIGINS.has(origin)){res.set("Access-Control-Allow-Origin",origin);res.set("Vary","Origin");}
 if(req.method==="OPTIONS"){res.set("Access-Control-Allow-Methods","POST");res.set("Access-Control-Allow-Headers","Content-Type");return res.status(204).send("");}
 if(req.method!=="POST") return res.status(405).json({error:"method_not_allowed"});
 if(!ALLOWED_ORIGINS.has(origin)) return res.status(403).json({error:"origin_not_allowed"});
 const raw=JSON.stringify(req.body||{}); if(Buffer.byteLength(raw,"utf8")>30000) return res.status(413).json({error:"too_large"});
 const input=req.body||{}; if(!TYPES.has(input.type)) return res.status(400).json({error:"invalid_type"});
 for(const k of REQUIRED){if(typeof input[k]!=="string"||!input[k].trim()) return res.status(400).json({error:"missing_"+k});}
 const data={};
 for(const k of ALLOWED){if(input[k]!==undefined){const v=input[k];if(typeof v==="string"){if(v.length>2000)return res.status(400).json({error:"field_too_long"});data[k]=v.trim();}else if(typeof v==="number"&&Number.isFinite(v))data[k]=v;}}
 // Explicitly reject common patient-identifying fields.
 for(const k of ["patientName","patientDob","dateOfBirth","chartNumber","medicalRecordNumber"]){if(input[k]!=null)return res.status(400).json({error:"patient_identifier_not_allowed"});}
 data.createdAt=admin.firestore.FieldValue.serverTimestamp();
 data.updatedAt=admin.firestore.FieldValue.serverTimestamp();
 data.source="public-web";
 const ref=await db.collection("reports").add(data);
 return res.status(201).json({ok:true,reportId:ref.id});
});
