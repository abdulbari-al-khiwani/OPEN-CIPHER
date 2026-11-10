'use strict';

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = (bytes) => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2,'0')).join('');
function toast(message){const t=$('toast');t.textContent=message;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800)}
function bytesToB64Url(bytes){return b64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function b64UrlToBytes(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return unb64(s)}
function randomBytes(n){const a=new Uint8Array(n);crypto.getRandomValues(a);return a}
function downloadBlob(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
function requireCrypto(){if(!window.isSecureContext||!crypto.subtle)throw new Error('واجهة التشفير الحديثة تحتاج إلى سياق آمن. افتح المشروع عبر HTTPS أو معاينة Acode المحلية (localhost).')}

const pageNames={dashboard:'لوحة التحكم',classical:'الشفرات الكلاسيكية',aes:'تشفير AES',rsa:'تشفير RSA',hash:'البصمات الرقمية',files:'تشفير الملفات',password:'مولّد كلمات المرور'};
function showPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===id));document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.page===id));$('pageTitle').textContent=pageNames[id]||'OPEN CIPHER';$('sidebar').classList.remove('open');window.scrollTo(0,0)}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.go)));
$('menuBtn').addEventListener('click',()=>$('sidebar').classList.toggle('open'));
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{const el=$(b.dataset.copy);if(!el.value)return toast('لا يوجد محتوى لنسخه');try{await navigator.clipboard.writeText(el.value);toast('تم النسخ')}catch{el.select();document.execCommand('copy');toast('تم النسخ')}}));

function caesar(text,shift){return text.replace(/[a-z]/gi,c=>{const base=c===c.toUpperCase()?65:97;return String.fromCharCode((c.charCodeAt(0)-base+shift+26)%26+base)})}
function vigenere(text,key,decrypt=false){key=key.toUpperCase().replace(/[^A-Z]/g,'');if(!key)throw new Error('أدخل مفتاحًا يحتوي على أحرف إنجليزية');let i=0;return text.replace(/[a-z]/gi,c=>{const base=c===c.toUpperCase()?65:97,k=key.charCodeAt(i++%key.length)-65,s=decrypt?-k:k;return String.fromCharCode((c.charCodeAt(0)-base+s+26)%26+base)})}
$('classicalType').addEventListener('change',()=>{const v=$('classicalType').value;$('shiftWrap').classList.toggle('hidden',v!=='caesar');$('keyWrap').classList.toggle('hidden',v!=='vigenere')});
function classical(run){try{const text=$('classicalInput').value;if(!text)throw new Error('اكتب النص أولًا');const type=$('classicalType').value;let out;if(type==='caesar'){let s=Number($('shift').value);if(!Number.isInteger(s)||s<0||s>25)throw new Error('الإزاحة يجب أن تكون من 0 إلى 25');out=caesar(text,run?-s:s)}else out=vigenere(text,$('vigKey').value,!run);$('classicalOutput').value=out}catch(e){toast(e.message)}}
$('classicalEncrypt').onclick=()=>classical(true);$('classicalDecrypt').onclick=()=>classical(false);

async function deriveAesKey(password,salt){requireCrypto();const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function encryptBytes(data,password){if(!password)throw new Error('أدخل عبارة المرور');const salt=randomBytes(16),iv=randomBytes(12),key=await deriveAesKey(password,salt);const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,data);return enc.encode('OC1.'+[bytesToB64Url(salt),bytesToB64Url(iv),bytesToB64Url(cipher)].join('.'))}
async function decryptBytes(payload,password){requireCrypto();if(!password)throw new Error('أدخل عبارة المرور');const parts=dec.decode(payload).trim().split('.');if(parts.length!==4||parts[0]!=='OC1')throw new Error('صيغة الملف أو النص المشفر غير صحيحة');const salt=b64UrlToBytes(parts[1]),iv=b64UrlToBytes(parts[2]),cipher=b64UrlToBytes(parts[3]),key=await deriveAesKey(password,salt);return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv},key,cipher))}
$('aesEncrypt').onclick=async()=>{try{const text=$('aesInput').value;if(!text)throw new Error('اكتب النص أولًا');$('aesOutput').value=dec.decode(await encryptBytes(enc.encode(text),$('aesPassword').value));toast('اكتمل التشفير')}catch(e){toast(e.message)}};
$('aesDecrypt').onclick=async()=>{try{$('aesOutput').value=dec.decode(await decryptBytes(enc.encode($('aesInput').value),$('aesPassword').value));toast('تم فك التشفير والتحقق من سلامة البيانات')}catch(e){toast('تعذر فك التشفير: كلمة المرور أو البيانات غير صحيحة')}};

let rsaPublicKey=null,rsaPrivateKey=null;
function pemFromBytes(bytes,label){const raw=b64(bytes);const lines=raw.match(/.{1,64}/g).join('\n');return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`}
function pemToBytes(pem){return unb64(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,''))}
$('rsaGenerate').onclick=async()=>{try{requireCrypto();const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);rsaPublicKey=pair.publicKey;rsaPrivateKey=pair.privateKey;const pub=await crypto.subtle.exportKey('spki',rsaPublicKey),priv=await crypto.subtle.exportKey('pkcs8',rsaPrivateKey);$('rsaPublic').value=pemFromBytes(pub,'PUBLIC KEY');$('rsaPrivate').value=pemFromBytes(priv,'PRIVATE KEY');toast('تم إنشاء زوج المفاتيح محليًا')}catch(e){toast(e.message)}};
$('rsaEncrypt').onclick=async()=>{try{requireCrypto();if(!rsaPublicKey)throw new Error('أنشئ زوج المفاتيح أولًا');const result=await crypto.subtle.encrypt({name:'RSA-OAEP'},rsaPublicKey,enc.encode($('rsaInput').value));$('rsaOutput').value=bytesToB64Url(result);toast('تم التشفير بالمفتاح العام')}catch(e){toast(e.message||'تعذر التشفير؛ استخدم نصًا قصيرًا')}};
$('rsaDecrypt').onclick=async()=>{try{requireCrypto();if(!rsaPrivateKey)throw new Error('أنشئ زوج المفاتيح في هذه الجلسة أولًا');const result=await crypto.subtle.decrypt({name:'RSA-OAEP'},rsaPrivateKey,b64UrlToBytes($('rsaOutput').value.trim()));$('rsaOutput').value=dec.decode(result);toast('تم فك التشفير')}catch(e){toast('تعذر فك التشفير. تأكد من المفتاح والنص المشفر.')}};

$('hashRun').onclick=async()=>{try{requireCrypto();const result=await crypto.subtle.digest($('hashType').value,enc.encode($('hashInput').value));$('hashOutput').value=hex(result);toast('تم حساب البصمة')}catch(e){toast(e.message)}};

$('fileEncrypt').onclick=async()=>{try{const file=$('fileInput').files[0];if(!file)throw new Error('اختر ملفًا أولًا');$('fileStatus').textContent='جارٍ التشفير...';const data=new Uint8Array(await file.arrayBuffer()),encrypted=await encryptBytes(data,$('filePassword').value);downloadBlob(new Blob([encrypted],{type:'application/octet-stream'}),file.name+'.ocipher');$('fileStatus').textContent='اكتمل التشفير والتنزيل. احتفظ بعبارة المرور.';toast('تم تشفير الملف')}catch(e){$('fileStatus').textContent=e.message;toast(e.message)}};
$('fileDecrypt').onclick=async()=>{try{const file=$('fileInput').files[0];if(!file)throw new Error('اختر ملف OCIPHER أولًا');$('fileStatus').textContent='جارٍ فك التشفير...';const plain=await decryptBytes(new Uint8Array(await file.arrayBuffer()),$('filePassword').value);let name=file.name.endsWith('.ocipher')?file.name.slice(0,-8):'decrypted-file';downloadBlob(new Blob([plain]),name);$('fileStatus').textContent='اكتمل فك التشفير والتنزيل.';toast('تم فك تشفير الملف')}catch(e){$('fileStatus').textContent='تعذر فك التشفير؛ تحقق من الملف وعبارة المرور.';toast('فشل فك التشفير')}};

$('passLength').oninput=()=>$('passLengthValue').value=$('passLength').value;
$('generatePassword').onclick=()=>{const groups=[];if($('useUpper').checked)groups.push('ABCDEFGHJKLMNPQRSTUVWXYZ');if($('useLower').checked)groups.push('abcdefghijkmnopqrstuvwxyz');if($('useNumbers').checked)groups.push('23456789');if($('useSymbols').checked)groups.push('!@#$%^&*()-_=+[]{}?');if(!groups.length)return toast('اختر نوعًا واحدًا على الأقل');const all=groups.join(''),len=Number($('passLength').value),out=[];for(const g of groups)out.push(g[randomBytes(1)[0]%g.length]);while(out.length<len)out.push(all[randomBytes(1)[0]%all.length]);for(let i=out.length-1;i>0;i--){const j=randomBytes(1)[0]%(i+1);[out[i],out[j]]=[out[j],out[i]]}$('passwordOutput').value=out.join('');toast('تم توليد كلمة المرور')};

if(!window.isSecureContext||!crypto.subtle){const status=document.querySelector('.top-status span');status.textContent='يلزم HTTPS أو localhost';document.querySelector('.top-status i').style.background='#ffbd69'}
