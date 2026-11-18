const sanitizeHtml = require('sanitize-html');
const db = require('../db/database');
const defaults = (process.env.BLOCKED_TERMS || 'fuck,shit,bitch,asshole').split(',').map(word=>word.trim().toLowerCase()).filter(Boolean);

// Read staff-managed blocked terms, falling back to the configured base list.
function getBlockedTerms(){const row=db.prepare("SELECT value FROM settings WHERE key='blocked_terms'").get();return row?row.value.split(',').map(word=>word.trim().toLowerCase()).filter(Boolean):defaults;}
// Match configured terms as whole words, so short terms do not block normal words.
function containsBlockedTerm(value){const text=String(value||'').toLowerCase();return getBlockedTerms().some(word=>new RegExp(`(^|\\W)${word.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}($|\\W)`,'i').test(text));}
// Remove markup, reject overlong messages, and replace unsafe text with [removed].
function moderateText(input){
  if(typeof input!=='string')return{ok:false,reason:'Message must be text.'};
  const text=sanitizeHtml(input,{allowedTags:[],allowedAttributes:{}}).trim();
  if(!text||text.length>500)return{ok:false,reason:'Messages must be 1–500 characters.'};
  const unsafe=[/(?:\+?\d[\s().-]*){8,}/, /\b\d{1,6}\s+[\w.-]+\s+(?:street|st\.?|road|rd\.?|avenue|ave\.?|barangay|brgy\.?|drive|lane)\b/i, /\b(?:student|school)\s+(?:id|number|no\.?)\s*[:#-]?\s*[a-z0-9-]{4,}\b/i, /\bID(?:\s*(?:number|no\.?|#|:))?\s*[:#-]?\s*\d{5,}\b/i, /(?:https?:\/\/|www\.)\S+/i, /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i, /(?:^|\s)@[a-z0-9_.]{2,32}\b/i, /\b(?:instagram|snapchat|telegram|tiktok|discord)\s*[:@]/i, /\b(?:kill yourself|send nudes|nude|porn|sex chat|sext(?:ing)?|onlyfans|masturbat(?:e|ion)|dick pics?)\b/i];
  if(unsafe.some(pattern=>pattern.test(text))||containsBlockedTerm(text))return{ok:true,text:'[removed]',redacted:true};
  return{ok:true,text,redacted:false};
}
module.exports={moderateText,containsBlockedTerm,getBlockedTerms};
