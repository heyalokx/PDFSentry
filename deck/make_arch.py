from PIL import Image, ImageDraw, ImageFont
import os
W,H=2400,760
im=Image.new('RGBA',(W,H),(0,0,0,0)); d=ImageDraw.Draw(im)
def font(sz,bold=True):
    paths=['/usr/share/fonts/opentype/inter/InterDisplay-Bold.otf' if bold else '/usr/share/fonts/opentype/inter/Inter-Regular.otf']
    for pth in paths:
        if os.path.exists(pth):return ImageFont.truetype(pth,sz)
    return ImageFont.load_default()
INK=(27,30,34,255); GREY=(90,96,104,255); TEAL=(47,143,130,255); FILL=(255,255,255,235); SILV=(185,190,198,255)
def box(x,y,w,h,title,sub,accent=False,r=22):
    col=TEAL if accent else INK
    d.rounded_rectangle([x,y,x+w,y+h],radius=r,fill=FILL,outline=col,width=5 if accent else 4)
    f1=font(42);f2=font(27,False)
    tw=d.textlength(title,font=f1); d.text((x+w/2-tw/2,y+28),title,font=f1,fill=INK)
    # wrap sub
    words=sub.split();lines=[];cur=''
    for wd in words:
        t=(cur+' '+wd).strip()
        if d.textlength(t,font=f2)>w-44: lines.append(cur);cur=wd
        else: cur=t
    lines.append(cur)
    yy=y+86
    for ln in lines:
        lw=d.textlength(ln,font=f2); d.text((x+w/2-lw/2,yy),ln,font=f2,fill=GREY); yy+=34
def arrow(x1,y,x2):
    d.line([x1,y,x2-18,y],fill=SILV,width=5)
    d.polygon([(x2,y),(x2-18,y-11),(x2-18,y+11)],fill=SILV)

bw,bh=360,180; y=150; gap=52
xs=120
steps=[("PDF","input document, never executed"),
       ("Parse","pikepdf → object-reference graph"),
       ("Triggers","/OpenAction /AA /Names JS, chains"),
       ("Reachability","BFS trigger → dangerous action")]
cx=xs
for t,s in steps:
    box(cx,y,bw,bh,t,s); 
    arrow(cx+bw,y+bh/2,cx+bw+gap); cx+=bw+gap
# fusion node (accent)
box(cx,y,bw,bh,"Fusion",u"65-D reach vector ⊕ EMBER score",accent=True)
# second row: verdict output centered below fusion
vy=y+bh+120
d.line([cx+bw/2,y+bh,cx+bw/2,vy],fill=SILV,width=5)
d.polygon([(cx+bw/2,vy),(cx+bw/2-11,vy-18),(cx+bw/2+11,vy-18)],fill=SILV)
box(cx-40,vy,bw+80,150,"Verdict + Witness",u"ACTIVE_ONOPEN · minimal catalog→danger path",accent=False,r=22)
im.save('deck/assets/arch.png')
print('arch.png', im.size, os.path.getsize('deck/assets/arch.png')//1024,'KB')
