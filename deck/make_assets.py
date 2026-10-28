import numpy as np
from PIL import Image, ImageDraw, ImageFilter
W,H=2560,1440
rng=np.random.default_rng(7)

def brushed(top,bot,sheen=0.06,streak=0.012):
    # vertical gradient top->bot (RGB tuples)
    ty=np.linspace(0,1,H)[:,None]
    base=np.array(top)[None,None,:]*(1-ty[:,:,None])+np.array(bot)[None,None,:]*ty[:,:,None]
    img=np.repeat(base,W,axis=1).astype(np.float32)
    # horizontal brushed streaks
    streaks=rng.normal(0,1,(H,1))
    streaks=np.convolve(streaks[:,0],np.ones(3)/3,mode='same')[:,None]
    img+=(streaks[:,:,None]*255*streak)
    fine=rng.normal(0,1,(1,W))
    fine=np.convolve(fine[0],np.ones(9)/9,mode='same')[None,:]
    img+=(fine[:,:,None]*255*streak*0.6)
    # soft diagonal sheen
    xx,yy=np.meshgrid(np.linspace(0,1,W),np.linspace(0,1,H))
    d=1-np.abs((xx*0.6+yy*0.4)-0.42)*1.6
    d=np.clip(d,0,1)**2
    img+=(d[:,:,None]*255*sheen)
    return Image.fromarray(np.clip(img,0,255).astype(np.uint8),'RGB')

brushed((244,245,247),(222,225,230),sheen=0.05).save('deck/assets/bg_content.png')
brushed((205,208,214),(230,232,236),sheen=0.10,streak=0.016).save('deck/assets/bg_cover.png')

# ---- thin black line ornaments (transparent) ----
INK=(17,18,20,255)
def canvas(s=900): return Image.new('RGBA',(s,s),(0,0,0,0))

def save_orn(im,name): im.save(f'deck/assets/{name}.png')

# sparkle 4-point star
im=canvas(700);d=ImageDraw.Draw(im);cx,cy=350,350
def star(d,cx,cy,R,r,w):
    pts=[]
    import math
    for k in range(8):
        ang=math.pi/2+ k*math.pi/4
        rad=R if k%2==0 else r
        pts.append((cx+rad*math.cos(ang),cy-rad*math.sin(ang)))
    d.line(pts+[pts[0]],fill=INK,width=w,joint='curve')
star(d,cx,cy,330,70,6)
save_orn(im,'orn_star')

# wireframe globe
im=canvas(900);d=ImageDraw.Draw(im);cx,cy,R=450,450,360
d.ellipse([cx-R,cy-R,cx+R,cy+R],outline=INK,width=5)
for f in (0.35,0.72):
    d.ellipse([cx-R*f,cy-R,cx+R*f,cy+R],outline=INK,width=4)
d.line([cx,cy-R,cx,cy+R],fill=INK,width=4)
for yy in (-0.6,-0.25,0.1,0.45,0.78):
    import math
    w=R*math.sqrt(max(0,1-yy*yy))
    d.line([cx-w,cy+yy*R,cx+w,cy+yy*R],fill=INK,width=4)
save_orn(im,'orn_globe')

# concentric ring arcs
im=canvas(900);d=ImageDraw.Draw(im);cx,cy=450,450
for i,R in enumerate([160,250,340]):
    st,en=(200,20) if i%2==0 else (30,210)
    d.arc([cx-R,cy-R,cx+R,cy+R],st,en,fill=INK,width=5)
save_orn(im,'orn_arcs')

# small full ring (thin)
im=canvas(600);d=ImageDraw.Draw(im)
d.ellipse([40,40,560,560],outline=INK,width=5)
d.ellipse([150,150,450,450],outline=INK,width=4)
save_orn(im,'orn_ring')

print("assets written:")
import os
for f in sorted(os.listdir('deck/assets')): print(" ",f, os.path.getsize('deck/assets/'+f)//1024,'KB')
