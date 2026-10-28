// Shared silver/chrome theme + slide builders for PDFSentry decks
const pptxgen = require('pptxgenjs');
const A = __dirname + '/assets/';
const C = { INK:'1b1e22', GRAPH:'3a3f46', MUT:'6b7178', FAINT:'9aa0a8',
  TEAL:'2f8f82', AMBER:'c08a2e', RED:'b4473f', LINE:'b9bec6', CARD:'eef0f2', CARDLINE:'ced2d8' };
const HEAD='Arial Black', BODY='Calibri', MONO='Consolas';
const W=13.333, H=7.5;

let PAGE=0;
function mk(){ PAGE=0; const p=new pptxgen(); p.layout='LAYOUT_WIDE'; p.author='Alok Singh'; p.company='VIT'; return p; }
function newslide(p){ PAGE++; return p.addSlide(); }

function nav(s, right){
  s.addText('PDFSENTRY',{x:0.55,y:0.32,w:5,h:0.3,isTextBox:true,margin:0,fontFace:BODY,fontSize:11,bold:true,color:C.MUT,charSpacing:4});
  s.addText(right||'',{x:W-6.05,y:0.32,w:5.5,h:0.3,isTextBox:true,margin:0,align:'right',fontFace:BODY,fontSize:11,color:C.MUT,charSpacing:3});
}
function foot(s){
  s.addText('PDFSentry · Reachability over Recognition',{x:0.55,y:7.14,w:7,h:0.26,isTextBox:true,margin:0,fontFace:BODY,fontSize:8.5,color:C.FAINT,charSpacing:1.5});
  s.addText(String(PAGE).padStart(2,'0'),{x:W-0.95,y:7.12,w:0.5,h:0.28,isTextBox:true,margin:0,align:'right',fontFace:BODY,fontSize:9.5,bold:true,color:C.MUT});
}
function orn(s,name,x,y,w,transp){ s.addImage({path:A+'orn_'+name+'.png',x,y,w,h:w,transparency:transp==null?28:transp}); }
function eyebrow(s,txt){ if(txt) s.addText(txt,{x:0.56,y:0.86,w:11,h:0.28,isTextBox:true,margin:0,fontFace:BODY,fontSize:11,bold:true,color:C.TEAL,charSpacing:4}); }
function title(s,txt,sz,eb){ const y=eb?1.18:0.9; if(eb) eyebrow(s,eb);
  s.addText(txt,{x:0.55,y,w:12.2,h:0.8,isTextBox:true,margin:0,fontFace:HEAD,fontSize:sz||32,color:C.INK}); }
function card(s,x,y,w,h){ s.addShape('roundRect',{x,y,w,h,rectRadius:0.07,fill:{color:C.CARD},line:{color:C.CARDLINE,width:0.75},
  shadow:{type:'outer',color:'9aa0a8',blur:8,offset:3,angle:90,opacity:0.3}}); }
function metricStrip(s,metrics,y){ const n=metrics.length, gap=0.4, cw=(11.9-(n-1)*gap)/n;
  metrics.forEach((m,i)=>{ const x=0.6+i*(cw+gap); card(s,x,y,cw,1.2);
    s.addText(m[0],{x:x+0.28,y:y+0.17,w:cw-0.56,h:0.6,isTextBox:true,margin:0,fontFace:HEAD,fontSize:m[3]||27,color:m[2]||C.INK});
    s.addText(m[1],{x:x+0.28,y:y+0.76,w:cw-0.56,h:0.4,isTextBox:true,margin:0,fontFace:BODY,fontSize:10.5,color:C.MUT,lineSpacingMultiple:1.0}); }); }

// ---- COVER ----
function cover(p,o){ const s=newslide(p); s.background={path:A+'bg_cover.jpg'}; nav(s,o.right||'BCSE321L · MALWARE ANALYSIS');
  s.addImage({path:A+'orn_globe.png',x:8.7,y:1.45,w:4.0,h:4.0,transparency:28});
  s.addImage({path:A+'orn_arcs.png',x:11.2,y:5.0,w:1.5,h:1.5,transparency:45});
  s.addText(o.eyebrow,{x:0.6,y:1.95,w:8,h:0.4,isTextBox:true,margin:0,fontFace:BODY,fontSize:14,bold:true,color:C.TEAL,charSpacing:5});
  s.addText(o.title,{x:0.52,y:2.37,w:9,h:1.5,isTextBox:true,margin:0,fontFace:HEAD,fontSize:o.titleSize||82,color:C.INK,charSpacing:1});
  s.addText(o.subtitle,{x:0.6,y:o.subY||3.95,w:7.7,h:0.9,isTextBox:true,margin:0,fontFace:BODY,fontSize:21,color:C.GRAPH,lineSpacingMultiple:1.05});
  if(o.tagline) s.addText(o.tagline,{x:0.6,y:(o.subY||3.95)+0.95,w:7.7,h:0.5,isTextBox:true,margin:0,fontFace:BODY,fontSize:13,italic:true,color:C.MUT,lineSpacingMultiple:1.05});
  const team=o.team.map((t,i)=>({text:t,options:{breakLine:i<o.team.length-1}}));
  s.addText(team,{x:0.6,y:5.95,w:7.4,h:1.1,isTextBox:true,margin:0,fontFace:BODY,fontSize:14,color:C.MUT,lineSpacingMultiple:1.3});
  if(o.guide) s.addText(o.guide,{x:0.6,y:7.02,w:8,h:0.3,isTextBox:true,margin:0,fontFace:BODY,fontSize:11,italic:true,color:C.FAINT});
  return s; }

// ---- SECTION DIVIDER (big number) ----
function divider(p,o){ const s=newslide(p); s.background={path:A+'bg_cover.jpg'}; nav(s,o.right||'');
  orn(s,o.orn||'star', o.ornX!=null?o.ornX:10.0, o.ornY!=null?o.ornY:1.1, o.ornW||2.3, 20);
  s.addText(o.num,{x:0.5,y:1.85,w:5,h:2.2,isTextBox:true,margin:0,fontFace:HEAD,fontSize:150,color:C.FAINT});
  s.addText(o.title,{x:0.56,y:4.05,w:11,h:1.0,isTextBox:true,margin:0,fontFace:HEAD,fontSize:o.tsz||52,color:C.INK,charSpacing:2});
  s.addText(o.desc,{x:0.6,y:5.2,w:9.4,h:0.9,isTextBox:true,margin:0,fontFace:BODY,fontSize:18,color:C.GRAPH,lineSpacingMultiple:1.1});
  if(o.covers){ s.addText(o.covers,{x:0.6,y:6.25,w:11,h:0.5,isTextBox:true,margin:0,fontFace:BODY,fontSize:12,color:C.MUT,lineSpacingMultiple:1.1,charSpacing:0.5}); }
  return s; }

// ---- NUMBERED STEPS + optional right card ----
function numbered(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||32,o.eb);
  const top=o.eb?2.15:1.95, bh=o.items.length>5?0.80:0.95; let yy=top;
  const lw=o.card?7.4:11.9;
  o.items.forEach((it,i)=>{ s.addText(String(i+1).padStart(2,'0'),{x:0.6,y:yy,w:0.7,h:0.5,isTextBox:true,margin:0,fontFace:HEAD,fontSize:19,color:C.TEAL});
    s.addText([{text:it[0]+'   ',options:{bold:true,color:C.INK}},{text:it[1],options:{color:C.GRAPH}}],
      {x:1.35,y:yy-0.02,w:lw-0.75,h:bh,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:o.fs||15,lineSpacingMultiple:1.06}); yy+=bh; });
  if(o.card){ const ch=o.card.h||4.6; card(s,9.15,top,3.6,ch);
    s.addText(o.card.head,{x:9.45,y:top+0.25,w:3.1,h:0.3,isTextBox:true,margin:0,fontFace:BODY,fontSize:11,bold:true,color:C.MUT,charSpacing:3});
    s.addText(o.card.body,{x:9.45,y:top+0.65,w:3.05,h:ch-0.9,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:14,color:C.GRAPH,lineSpacingMultiple:1.18});
  }
  foot(s); return s; }

// ---- BULLETS (left) + optional right image/visual + optional bottom metric strip ----
function bullets(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||32,o.eb);
  const topY=o.eb?1.95:(o.lede?1.72:1.95); const hasM=o.metrics&&o.metrics.length;
  if(o.lede) s.addText(o.lede,{x:0.6,y:o.eb?1.95:1.72,w:o.img?6.9:11.9,h:0.6,isTextBox:true,margin:0,fontFace:BODY,fontSize:15.5,color:C.GRAPH,lineSpacingMultiple:1.05});
  const by=o.lede?(o.eb?2.65:2.42):(o.eb?2.15:1.95), bw=o.img?6.9:11.9;
  const runs=o.bullets.map((b)=>{ const bold=Array.isArray(b); const head=bold?b[0]:null; const txt=bold?b[1]:b;
    return head!=null ? [{text:head+'  ',options:{bold:true,color:C.INK,bullet:{code:'2022'},breakLine:false}},{text:txt,options:{color:C.GRAPH,breakLine:true,paraSpaceAfter:13}}]
      : [{text:txt,options:{color:C.GRAPH,bullet:{code:'2022'},breakLine:true,paraSpaceAfter:13}}]; }).flat();
  const bh=hasM?3.05:4.6;
  s.addText(runs,{x:0.62,y:by,w:bw,h:bh,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:o.fs||16,color:C.GRAPH,lineSpacingMultiple:1.18});
  if(o.img){ const iw=o.imgW||5.3, ih=o.imgH||(iw*0.62), ix=W-iw-0.6, iy=o.imgY||2.4;
    card(s,ix-0.12,iy-0.12,iw+0.24,ih+0.24);
    s.addImage({path:o.img,x:ix,y:iy,w:iw,h:ih});
    if(o.caption) s.addText(o.caption,{x:ix,y:iy+ih+0.12,w:iw,h:0.4,isTextBox:true,margin:0,align:'center',fontFace:BODY,fontSize:11,italic:true,color:C.MUT}); }
  if(hasM) metricStrip(s,o.metrics,5.55);
  else if(!o.img) orn(s,o.orn||'ring',11.55,5.6,1.2,55);
  foot(s); return s; }

// ---- FRAMED IMAGE (big, e.g. dashboard screenshot) + side notes ----
function imageSlide(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||32,o.eb);
  const iw=o.notes?8.4:11.6, ih=iw*(o.ratio||0.573), ix=0.6, iy=o.eb?2.4:2.15;
  s.addShape('roundRect',{x:ix-0.1,y:iy-0.1,w:iw+0.2,h:ih+0.2,rectRadius:0.05,fill:{color:'0f141b'},line:{color:'2b3542',width:1},
    shadow:{type:'outer',color:'7c8795',blur:10,offset:4,angle:90,opacity:0.4}});
  s.addImage({path:o.img,x:ix,y:iy,w:iw,h:ih});
  if(o.caption) s.addText(o.caption,{x:ix,y:iy+ih+0.14,w:iw,h:0.4,isTextBox:true,margin:0,fontFace:BODY,fontSize:11.5,italic:true,color:C.MUT});
  if(o.notes){ let yy=iy+0.15; const nx=iw+0.95, step=Math.min(1.05,(ih-0.2)/o.notes.length);
    o.notes.forEach(nt=>{ s.addText([{text:(nt[0]?nt[0]+'  ':''),options:{bold:true,color:C.INK}},{text:nt[1],options:{color:C.GRAPH}}],
      {x:nx,y:yy,w:W-nx-0.5,h:step,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:13.5,lineSpacingMultiple:1.12,bullet:{code:'2022'}}); yy+=step; }); }
  foot(s); return s; }

// ---- STAT CALLOUTS ----
function stats(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||32,o.eb);
  if(o.lede) s.addText(o.lede,{x:0.6,y:o.eb?1.95:1.72,w:11.9,h:0.6,isTextBox:true,margin:0,fontFace:BODY,fontSize:15.5,color:C.GRAPH,lineSpacingMultiple:1.05});
  const n=o.stats.length, cols=Math.min(n,3), gapx=0.5, startY=o.lede?(o.eb?3.0:2.75):2.35;
  const cw=(11.9-(cols-1)*gapx)/cols;
  o.stats.forEach((st,i)=>{ const r=Math.floor(i/cols), c=i%cols; const x=0.6+c*(cw+gapx), y=startY+r*2.05;
    card(s,x,y,cw,1.8);
    s.addText(st[0],{x:x+0.3,y:y+0.2,w:cw-0.6,h:0.8,isTextBox:true,margin:0,fontFace:HEAD,fontSize:o.big||42,color:st[2]||C.INK});
    s.addText(st[1],{x:x+0.3,y:y+1.04,w:cw-0.6,h:0.66,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:12.5,color:C.MUT,lineSpacingMultiple:1.05}); });
  if(o.note) s.addText(o.note,{x:0.6,y:6.62,w:12,h:0.5,isTextBox:true,margin:0,fontFace:BODY,fontSize:13,italic:true,color:C.GRAPH,lineSpacingMultiple:1.05});
  foot(s); return s; }

// ---- CHART + stat callouts ----
function chartSlide(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||30,o.eb);
  if(o.lede) s.addText(o.lede,{x:0.6,y:o.eb?1.95:1.72,w:11.9,h:0.6,isTextBox:true,margin:0,fontFace:BODY,fontSize:15.5,color:C.GRAPH,lineSpacingMultiple:1.05});
  const cx=0.55, cy=o.lede?(o.eb?2.75:2.5):2.1, cw=o.stats?7.7:11.9, ch=o.lede?4.35:4.95;
  s.addChart(o.type, o.data, Object.assign({ x:cx,y:cy,w:cw,h:ch, showLegend:!!o.legend, legendPos:'b', legendColor:C.MUT, legendFontFace:BODY, legendFontSize:11,
    showTitle:false, valGridLine:{color:'e2e4e8',size:0.75}, catGridLine:{style:'none'},
    catAxisLabelColor:C.MUT, valAxisLabelColor:C.MUT, catAxisLabelFontFace:BODY, valAxisLabelFontFace:BODY,
    catAxisLabelFontSize:10, valAxisLabelFontSize:10 }, o.opts||{}));
  if(o.stats){ let yy=cy+0.15; o.stats.forEach(st=>{ s.addText(st[0],{x:8.65,y:yy,w:4.3,h:0.9,isTextBox:true,margin:0,fontFace:HEAD,fontSize:o.big||42,color:st[2]||C.INK});
    s.addText(st[1],{x:8.65,y:yy+0.86,w:4.3,h:0.66,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:12.5,color:C.MUT,lineSpacingMultiple:1.05}); yy+=1.55; }); }
  foot(s); return s; }

// ---- COMPARISON TABLE ----
function tableSlide(p,o){ const s=newslide(p); s.background={path:A+'bg_content.jpg'}; nav(s,o.right||''); title(s,o.title,o.tsz||32,o.eb);
  if(o.lede) s.addText(o.lede,{x:0.6,y:o.eb?1.95:1.72,w:11.9,h:0.5,isTextBox:true,margin:0,fontFace:BODY,fontSize:15,color:C.GRAPH});
  const rows=[]; const hdr=o.headers.map((h,i)=>({text:h,options:{bold:true,color:'ffffff',fill:{color:C.INK},align:i?'center':'left',fontFace:BODY,fontSize:13,valign:'middle'}}));
  rows.push(hdr);
  o.rows.forEach((r,ri)=>{ const hr=(o.highlightRow===ri); rows.push(r.map((cval,ci)=>{ const hl=(o.highlightCol!=null&&ci===o.highlightCol)||hr;
    return {text:String(cval),options:{color:hl?C.TEAL:(ci===0?C.INK:C.GRAPH),bold:ci===0||hl,align:ci?'center':'left',
      fill:{color:hr?'e3f0ed':(ri%2? 'ffffff':'f1f3f5')},fontFace:BODY,fontSize:12,valign:'middle'}}; })); });
  const cw=[3.6]; const rest=(11.9-3.6)/(o.headers.length-1); for(let i=1;i<o.headers.length;i++)cw.push(rest);
  const rh=o.rows.length>5?0.5:0.56;
  s.addTable(rows,{x:0.6,y:o.lede?(o.eb?2.75:2.5):2.15,w:11.9,colW:cw,rowH:rh,border:{type:'solid',color:'dde1e6',pt:0.75},margin:5});
  if(o.note) s.addText(o.note,{x:0.6,y:6.68,w:12,h:0.5,isTextBox:true,margin:0,fontFace:BODY,fontSize:12.5,italic:true,color:C.GRAPH});
  foot(s); return s; }

// ---- CLOSING ----
function closing(p,o){ const s=newslide(p); s.background={path:A+'bg_cover.jpg'}; nav(s,o.right||'THANK YOU');
  s.addImage({path:A+'orn_globe.png',x:9.0,y:1.7,w:3.6,h:3.6,transparency:30});
  s.addText(o.eyebrow||'CONCLUSION',{x:0.6,y:1.9,w:8,h:0.4,isTextBox:true,margin:0,fontFace:BODY,fontSize:14,bold:true,color:C.TEAL,charSpacing:5});
  s.addText(o.title,{x:0.52,y:2.35,w:8.3,h:1.5,isTextBox:true,margin:0,fontFace:HEAD,fontSize:o.tsz||44,color:C.INK,lineSpacingMultiple:0.95});
  if(o.lines){ const runs=o.lines.map((l)=>({text:l,options:{bullet:{code:'2022'},breakLine:true,paraSpaceAfter:9}}));
    s.addText(runs,{x:0.62,y:o.linesY||3.85,w:7.9,h:2.0,isTextBox:true,margin:0,valign:'top',fontFace:BODY,fontSize:15,color:C.GRAPH,lineSpacingMultiple:1.12}); }
  let yy=o.linksY||6.25;
  if(o.repo){ s.addText([{text:'Repository   ',options:{bold:true,color:C.INK}},{text:o.repo,options:{color:C.TEAL}}],
    {x:0.6,y:yy,w:12,h:0.35,isTextBox:true,margin:0,fontFace:BODY,fontSize:13.5}); yy+=0.42; }
  if(o.dash){ s.addText([{text:'Live dashboard   ',options:{bold:true,color:C.INK}},{text:o.dash,options:{color:C.TEAL}}],
    {x:0.6,y:yy,w:12,h:0.35,isTextBox:true,margin:0,fontFace:BODY,fontSize:13.5}); }
  return s; }

module.exports={ mk,nav,orn,title,card,cover,divider,numbered,bullets,imageSlide,stats,chartSlide,tableSlide,closing,metricStrip,C,W,H,A };
