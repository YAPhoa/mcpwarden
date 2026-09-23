(() => {
'use strict';
const $=id=>document.getElementById(id);
const pad=n=>String(n).padStart(2,'0');
const UTC=(y,m,d)=>{const x=new Date(0);x.setUTCFullYear(y,m-1,d);x.setUTCHours(0,0,0,0);return x;};
const dateIso=p=>`${String(p.y).padStart(4,'0')}-${pad(p.m)}-${pad(p.d)}`;
function parseDate(s){const a=/^(\d{4})-(\d{2})-(\d{2})$/.exec(s);if(!a)return null;const p={y:+a[1],m:+a[2],d:+a[3]},x=UTC(p.y,p.m,p.d);return p.y>=1&&p.y<=9999&&x.getUTCFullYear()===p.y&&x.getUTCMonth()+1===p.m&&x.getUTCDate()===p.d?p:null;}
// Calendar. UTC dates below represent calendar days only, not query timestamps.
const cal=$('calendar');let calSide='calls-from',calFocus=UTC(2026,9,21),calMonth=8,calYear=2026,calTrigger=null;
function partsUTC(d){return {y:d.getUTCFullYear(),m:d.getUTCMonth()+1,d:d.getUTCDate()};}
function fromIso(iso){const p=parseDate(iso);return p?UTC(p.y,p.m,p.d):null;}
function localToday(){
 const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:window.MCPWardenTime.zone(),year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date()).map(p=>[p.type,p.value]));
 return UTC(+p.year,+p.month,+p.day);
}
function drawCalendar(focus=false){const selected=parseDate($(calSide).value),selectedIso=selected?dateIso(selected):null;const current=dateIso(partsUTC(localToday()));$('cal-month').textContent=new Intl.DateTimeFormat('en-GB',{month:'long',year:'numeric',timeZone:'UTC'}).format(UTC(calYear,calMonth+1,1));const first=UTC(calYear,calMonth+1,1),begin=new Date(+first-((first.getUTCDay()+6)%7)*86400000);const tbody=$('calendar-body');tbody.replaceChildren();for(let row=0;row<6;row++){const tr=document.createElement('tr');for(let col=0;col<7;col++){const day=new Date(+begin+(row*7+col)*86400000),p=partsUTC(day),iso=dateIso(p),td=document.createElement('td'),btn=document.createElement('button');btn.type='button';btn.dataset.date=iso;btn.textContent=p.d;btn.tabIndex=+day===+calFocus?0:-1;btn.disabled=p.y<1||p.y>9999;btn.setAttribute('aria-label',new Intl.DateTimeFormat('en-GB',{weekday:'long',year:'numeric',month:'long',day:'numeric',timeZone:'UTC'}).format(day));td.setAttribute('aria-selected',String(iso===selectedIso));if(iso===selectedIso)btn.classList.add('chosen');if(iso===current){btn.classList.add('today');btn.setAttribute('aria-current','date');}if(p.m-1!==calMonth)btn.classList.add('outside');btn.addEventListener('click',()=>chooseDay(day));btn.addEventListener('keydown',onCalendarKey);td.append(btn);tr.append(td);}tbody.append(tr);}if(focus)tbody.querySelector('button[tabindex="0"]')?.focus();}
function moveCalendar(delta){const candidate=UTC(calFocus.getUTCFullYear(),calFocus.getUTCMonth()+1+delta,1);const last=UTC(candidate.getUTCFullYear(),candidate.getUTCMonth()+2,0).getUTCDate();candidate.setUTCDate(Math.min(calFocus.getUTCDate(),last));if(candidate.getUTCFullYear()<1||candidate.getUTCFullYear()>9999)return;calFocus=candidate;calYear=candidate.getUTCFullYear();calMonth=candidate.getUTCMonth();drawCalendar(true);}
function onCalendarKey(e){const d=fromIso(e.currentTarget.dataset.date);if(!d)return;let next=null;if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End'].includes(e.key)){let delta={ArrowLeft:-1,ArrowRight:1,ArrowUp:-7,ArrowDown:7}[e.key];const weekday=(d.getUTCDay()+6)%7;if(e.key==='Home')delta=-weekday;if(e.key==='End')delta=6-weekday;next=new Date(+d+delta*86400000);}else if(e.key==='PageUp'||e.key==='PageDown'){e.preventDefault();calFocus=d;moveCalendar((e.key==='PageUp'?-1:1)*(e.shiftKey?12:1));return;}else return;e.preventDefault();if(next.getUTCFullYear()<1||next.getUTCFullYear()>9999)return;calFocus=next;calYear=next.getUTCFullYear();calMonth=next.getUTCMonth();drawCalendar(true);}
function chooseDay(day){$(calSide).value=dateIso(partsUTC(day));$(calSide).dispatchEvent(new Event('input',{bubbles:true}));cal.close();}
function positionCalendar(){if(!cal.open||!calTrigger)return;const r=calTrigger.getBoundingClientRect(),w=cal.offsetWidth,h=cal.offsetHeight;const x=Math.max(12,Math.min(r.right-w,innerWidth-w-12));const below=r.bottom+8;const y=below+h<innerHeight-12?below:Math.max(12,r.top-h-8);cal.style.left=x+'px';cal.style.top=y+'px';}
function openCalendar(input,trigger){
 calSide=input.id;calTrigger=trigger;
 const p=parseDate(input.value);calFocus=p?UTC(p.y,p.m,p.d):localToday();calMonth=calFocus.getUTCMonth();calYear=calFocus.getUTCFullYear();
 $('cal-context').textContent='Choose '+(calSide==='calls-from'?'From':'Until')+' date';
 drawCalendar();cal.showModal();positionCalendar();$('calendar-body').querySelector('button[tabindex="0"]')?.focus();
}
for(const button of document.querySelectorAll('[data-calendar]')) {
 const input=$(button.dataset.calendar);
 button.addEventListener('click',()=>openCalendar(input,button));
 input.addEventListener('click',e=>{e.preventDefault();openCalendar(input,input);});
 input.addEventListener('keydown',e=>{if(e.key==='Enter'||(e.altKey&&e.key==='ArrowDown')){e.preventDefault();openCalendar(input,input);}});
}
$('cal-prev').addEventListener('click',()=>moveCalendar(-1));$('cal-next').addEventListener('click',()=>moveCalendar(1));$('cal-today').addEventListener('click',()=>chooseDay(localToday()));$('cal-close').addEventListener('click',()=>cal.close());cal.addEventListener('close',()=>calTrigger?.focus());cal.addEventListener('click',e=>{if(e.target!==cal)return;const r=cal.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)cal.close();});cal.addEventListener('keydown',e=>{if(e.key!=='Tab')return;const focusable=[...cal.querySelectorAll('button:not([disabled])')].filter(b=>b.tabIndex>=0);const first=focusable[0],last=focusable.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}});window.addEventListener('resize',positionCalendar);

})();
