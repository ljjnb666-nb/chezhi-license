'use strict';
// Only UI convenience; every operation remains server-validated.
const preset = document.getElementById('preset');
const days = document.getElementById('days');
if (preset && days) {
  const sync = () => { days.disabled = preset.value !== 'custom'; };
  preset.addEventListener('change', sync); sync();
}
const result = document.querySelector('#issue-result textarea');
const copy = document.getElementById('copy-keys');
const feedback = document.getElementById('copy-feedback');
if (copy && result && feedback) {
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(result.value.trim()); feedback.textContent = '已复制'; }
    catch (_) { result.focus(); result.select(); feedback.textContent = '已选中，请按 Ctrl+C 复制'; }
  });
}
const all = document.getElementById('select-all');
const items = Array.from(document.querySelectorAll('input[name="ids"][form="batch"]'));
const count = document.getElementById('selected-count');
if (all && count) {
 const sync = () => { const n = items.filter(x => x.checked).length; count.textContent = '已选 ' + n + ' 项'; all.checked = items.length > 0 && n === items.length; all.indeterminate = n > 0 && n < items.length; };
 all.addEventListener('change', () => { items.forEach(x => x.checked = all.checked); sync(); });
 items.forEach(x => x.addEventListener('change', sync)); sync();
}
// Read-only trend display; exact figures remain available in the table.
document.querySelectorAll('.trend-bar').forEach(el => { const n=Number(el.dataset.height); if(Number.isFinite(n)&&n>=0&&n<=100) el.style.height=n+'%'; });
const price=document.getElementById('amount'), quantity=document.getElementById('quantity'), total=document.getElementById('amount-total');
if(price&&quantity&&total){const update=()=>{const m=price.value.match(/^(\d+)(?:\.(\d{1,2}))?$/),n=Number(quantity.value); if(!m||!Number.isInteger(n)||n<1||n>100||Number(m[1])>1000000||Number(price.value)>1000000){total.textContent='—';return;}const cents=(Number(m[1])*100+Number((m[2]||'').padEnd(2,'0')))*n;total.textContent='¥'+Math.floor(cents/100)+'.'+String(cents%100).padStart(2,'0');};price.addEventListener('input',update);quantity.addEventListener('input',update);update();}
// Confirmation is additive; existing form constraints and server guards remain.
const dialog=document.getElementById('confirm-dialog');
if(dialog&&typeof dialog.showModal==='function'){
 let pending=null, approved=null;
 document.addEventListener('submit',e=>{const b=e.submitter;if(!b||!['revoke','unbind','batch-revoke','batch-unbind','member-disable','member-reset','member-role'].includes(b.value))return;if(approved===b){approved=null;return;}e.preventDefault();if(dialog.open)return;pending={form:e.target,button:b};document.getElementById('confirm-text').textContent=b.value.includes('revoke')?'吊销后授权不可恢复，请确认所选卡密。':b.value.startsWith('member-')?'此操作将使该成员当前登录会话失效，是否继续？':'解绑不会延长有效期，请确认所选卡密。';dialog.showModal();document.getElementById('confirm-cancel').focus();});
 document.getElementById('confirm-cancel').addEventListener('click',()=>dialog.close());
 dialog.addEventListener('close',()=>{pending=null;});
 document.getElementById('confirm-ok').addEventListener('click',()=>{if(!pending)return;const {form,button}=pending;pending=null;dialog.close();approved=button;try{form.requestSubmit(button);}finally{approved=null;}});
}
// Apply a reference price when changing a preset; the operator may override it.
if(preset && price){const suggest=()=>{if(preset.value!=='custom'){const p=preset.selectedOptions[0]?.dataset.price;price.value=p||'0.00';price.dispatchEvent(new Event('input'));}};preset.addEventListener('change',suggest);suggest();}
