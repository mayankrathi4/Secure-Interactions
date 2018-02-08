import tkinter as tk
from tkinter.tix import *
from tkinter import filedialog
import socket as s
import subprocess as sb
from threading import Thread
from netifaces import interfaces, ifaddresses, AF_INET
import os
import sys
import random
import base64
import pickle
class rsa():
    def __init__(self):
        self.key = self.generate_keypair(13, 23)
    def gcd(self,a, b):
        while b != 0:
            a, b = b, a % b
        return a
    def multiplicative_inverse(self,a, b):
        x = 0
        y = 1
        lx = 1
        ly = 0
        oa = a
        ob = b
        while b != 0:
            q = a // b
            (a, b) = (b, a % b)
            (x, lx) = ((lx - (q * x)), x)
            (y, ly) = ((ly - (q * y)), y)
        if lx < 0:
            lx += ob
        if ly < 0:
            ly += oa
        return lx
    def is_prime(self,num):
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num**0.5)+2, 2):
            if num % n == 0:
                return False
        return True
    def generate_keypair(self,p, q):
        if not (self.is_prime(p) and self.is_prime(q)):
            raise ValueError('Both numbers must be prime.')
        elif p == q:
            raise ValueError('p and q cannot be equal')
        n = p * q
        phi = (p-1) * (q-1)
        e = random.randrange(1, phi)
        g = self.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = self.gcd(e, phi)
        d = self.multiplicative_inverse(e, phi)
        return ((e, n), (d, n))

    def rsaencrypt(self,pk, plaintext):
        key, n = pk
        cipher = [(ord(char)**key)%n for char in plaintext]
        return cipher

    def rsadecrypt(self,pk, ciphertext):
        key, n = pk
        plain = [chr((char ** key) % n) for char in ciphertext]
        return ''.join(plain)
class aes():
    def __init__(self):
        self.key=self.generate_encryption_key()
        self.matrix=self.generate_encryption_matrix()
    def generate_encryption_matrix(self):
        print()
    def generate_encryption_key(self):
        return os.urandom(32)
    def encrypt(self,pt):
        print()
    def decrypt(self,ct):
        print()
class nssl():
    def __init__(self):
        self.key=self.generate_encryption_key()
    def generate_encryption_key(self):
        x=os.urandom(16)
        y=base64.b64encode(x).decode('utf-8')
        return y
    def encrypt(self,pt,k):
        aa=k
        a=len(k)
        b=int(len(pt)/len(k))
        k=k*b
        c=len(pt)-(a*b)
        i=0
        while(i<c):
            k=k+aa[i]
            i=i+1
        ct=[chr(ord(a) ^ ord(b)) for (a, b) in zip(pt,k)]
        return ct
    def decrypt(self,ct,k):
        aa = k
        a = len(k)
        b = int(len(ct) / len(k))
        k = k * b
        c = len(ct) - (a * b)
        i = 0
        while (i < c):
            k = k + aa[i]
            i = i + 1
        pt=[chr(ord(a) ^ ord(b)) for (a, b) in zip(ct, k)]
        jt="".join(pt)
        return jt
    def generate_ssl_certificate(self,rsaob):
        l=[rsaob.key[0],[""],["SIMPLE"]]
        return l
i = 0
soc = None
sock = None
con = None
tt = None
ff = None
thr = None
cond = True
p = None
c = None
encrypter=None
decrypter=None
crypt=None
opt=None
options=None
defaultloc="/"
stegtext=""
f4=None
f5=None
ttt=None
stegfile=""
sadd=None
sport=None
listbox=None
def sendto(data,op):
    global tt
    global i
    global con
    global soc
    global ff
    global listbox
    j=None
    na=""
    if(op==1):
        j=soc
        na="Client :"
    elif(op==2):
        j=con
        na="Server :"
    xx=str(data.get())
    xj=encrypt(xx)
    j.sendall(xj)
    i=i+1
    print(na,xx)
   # print("Encrypted :",xj)
    #Label(ff, text=na+xx).grid(row=i, column=0)
    listbox.insert(END,str(na+xx))
    listbox.select_clear(listbox.size()-2)
    listbox.select_set(END)
    listbox.yview(END)
def recvfrom(op):
    global i
    global tt
    global con
    global soc
    global sock
    global ff
    global cond
    global listbox
    na=""
    if(int(op)==1):
        j=soc
        na="Server :"
    elif(int(op)==2):
        j=con
        na="Client :"
    name=""
    while(True):
        if(cond==True):
            try:
                dat =j.recv(4096)
                if(len(dat)==0):
                    raise Exception
                data=decrypt(dat)
                if(data=="syn234"):
                    cond=False
                    ok=encrypt("pass")
                    j.sendall(ok)
                    continue
                if (data != ""):
                    print(na,data)
                    if(data!="fi"):
                        i = i + 1
                        #Label(ff, text=na+data).grid(row=i, column=0)
                        listbox.insert(END,str(na+data))
                    if(data=="fi"):
                        ok=encrypt("syn234")
                        j.sendall(ok)
                        aa = decrypt(j.recv(4096))
                        ok=encrypt("Send name")
                        j.sendall(ok)
                        name = decrypt(j.recv(4096))
                        name=name[:-4]+"xx"+name[-4:]
                        ok=encrypt("Send size")
                        j.sendall(ok)
                        size = decrypt(j.recv(4096))
                        size = int(size)
                        #f = open(name,"wb")
                        ok=encrypt("Send file")
                        j.sendall(ok)
                        print("Starting file recieving : Name=",name," Size=",size)
                        l =None
                        while sys.getsizeof(l) < size:
                            packet = j.recv(size - sys.getsizeof(l))
                            if not packet:
                                return None
                            if(l==None):
                                l=packet
                            else:
                                l += packet
                        oo=decrypt(l)
                        oj=oo.encode("utf-8")
                        with open(name,"wb") as f:
                            f.write(base64.b64decode(oj))
                        print("\nFile recieved")
                        i=i+1
                        #Label(ff,text=na+"Image["+str(name)+"]").grid(row=i,column=0)
                        listbox.insert(END,na+"Image["+str(name)+"]")
                        if(name.endswith(".txt")):
                            sb.call(["gedit",name])
                        elif(name.endswith(".jpg")):
                            sb.call(["eog",name])
                        elif (name.endswith(".pdf")):
                            sb.call(["evince", name])
                        name=""
                listbox.select_clear(listbox.size() - 2)
                listbox.select_set(END)
                listbox.yview(END)
            except Exception as eee:
                discon(int(op))
                return
def createserver():
    global f2
    global p
    global c
    f2.grid_forget()
    f2.grid(row=5, column=0, rowspan=6)
    p = IntVar(f2,value=89)
    c = IntVar(f2,value=1)
    Label(f2, text="Enter port :").grid(row=5, column=0)
    Entry(f2, bd=5,textvariable=p).grid(row=5, column=2)
    tk.Button(f2, text="Start", command=lambda:server(p,c),justify=RIGHT).grid(row=7, column=1)
def attach(op):
    global i
    global ff
    global soc
    global con
    global tt
    global cond
    global defaultloc
    global listbox
    j=None
    if(op==1):
        j=soc
    elif(op==2):
        j=con
    tt.filename = filedialog.askopenfilename(initialdir=defaultloc, title="Select file",filetypes=(("jpeg files", "*.jpg"), ("txt files", "*.txt"),("all files","*.*")))
    name=str(tt.filename)
    if(name==""):
        return
    size=os.path.getsize(name)
    x=''
    with open(name, "rb") as image_file:
        x = base64.b64encode(image_file.read())
    xk=encrypt(x.decode("utf-8"))
    size=sys.getsizeof(xk)
    name = name.split('/')
    name = name[len(name) - 1]
    print("Sending file :",name," , Size :",size)
    sen=encrypt("fi")
    j.sendall(sen)
    print("Waiting for name command")
    com=j.recv(4096)
    sen=encrypt(str(name))
    j.sendall(sen)
    print("Waiting for size command")
    com=j.recv(4096)
    sen=encrypt(str(size))
    j.sendall(sen)
    print("Wating for send command")
    com=j.recv(4096)
    print("Initiating file transfer")
    j.sendall(xk)
    i=i+1
    listbox.insert(END,"Image["+str(name)+"]")
    cond=True
def recvbox():
    global con
    global i
    global tt
    global sock
    global thr
    global ff
    global tt
    global crypt
    global encrypter
    global decrypter
    global listbox
    global opt
    con, add = sock.accept()
    print("Client ", add, " connected ");
    opt=str(con.recv(2048).decode())
    print("Encryption technique : ", opt)
    if(opt=="RSA"):
        crypt=rsa()
        decrypter=crypt.key[1]
        print("Decryption key :", decrypter)
        xx = crypt.key[0]
        dd = str(xx[0]) + "," + str(xx[1])
        con.sendall(dd.encode())
        hh = str(con.recv(4096).decode())
        print(hh)
        kk=hh.split(",")
        encrypter= (int(kk[0]),int(kk[1]))
        print("Encryption key :", encrypter)
    elif(opt=="SSL"):
        crypt=nssl()
        ch=rsa()
        z1=pickle.dumps(crypt.generate_ssl_certificate(ch))
        con.sendall(z1)
        encrypter=con.recv(4096)
        encrypter=pickle.loads(encrypter)
        encrypter=ch.rsadecrypt(ch.key[1],encrypter)
        decrypter=encrypter
    tt = tk.Tk()
    tt.title('Server')
    ff = Frame(tt, bg="green", bd=5)
    ff.pack(side=BOTTOM,fill=BOTH)
    data = StringVar(ff)
    Label(ff, text="Connected to client " + str(add[0])).pack(side=TOP)
    i = 3
    thr = Thread(target=recvfrom, args=(2,))
    thr.start()
    Entry(ff, bd=5, textvariable=data).pack(side=LEFT)
    tk.Button(ff, text="SEND", command=lambda: sendto(data, 2), justify=RIGHT).pack(side=LEFT)
    tk.Button(ff, text="FILES", command=lambda: attach(2), justify=RIGHT).pack(side=LEFT)
    tk.Button(ff,text="STEGO",command=lambda:stego(),justify=RIGHT).pack(side=LEFT)
    ff2 = Frame(tt, bg="white", bd=5)
    ff2.pack(side=BOTTOM,fill=BOTH)
    sb = Scrollbar(ff2)
    sb.pack(side=RIGHT, fill=Y)
    sb1 = Scrollbar(ff2, orient=HORIZONTAL)
    sb1.pack(side=BOTTOM, fill=X)
    listbox = Listbox(ff2, yscrollcommand=sb.set, xscrollcommand=sb1.set)
    listbox.pack(side=LEFT, fill=BOTH)
    sb.config(command=listbox.yview)
    sb1.config(command=listbox.xview)
    tt.mainloop()
    discon(2)
def discon(a):
    global f3
    global f2
    global sock
    global p
    global c
    global soc
    global con
    global thr
    global tt
    if(a==1):
        soc.close()
        print("Client stopped")
        tk.Button(f2, text="Connect", command=lambda: client(), justify=RIGHT).grid(row=8, column=1)
        try:
            tt.destroy()
        except Exception as ex:
            pass
        thr.join()
    elif(a==2):
        con.close()
        print("Client connection terminated")
        sock.close()
        print("Socket destroyed")
        Label(f3, text="       Connection close       ").grid(row=13, column=0)
        tk.Button(f2, text="Start", command=lambda: server(p, c), justify=RIGHT).grid(row=7, column=1)
        try:
            tt.destroy()
        except Exception as ex:
            pass
        thr.join()
def server(p,c):
    global tt
    global i
    global con
    global f3
    global ff
    global thr
    global sock
    try:
        sock=s.socket(s.AF_INET,s.SOCK_STREAM)
        print("Server port : ",p.get())
        for ifaceName in interfaces():
            addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr': 'xx'}])]
        ip = addresses[0]
        sock.bind((ip,p.get()))
        print("Client limit : ",c.get())
        sock.listen(c.get())
        print("Server Created ")
        print("Waiting for client to join..")
        Label(f3,text="Waiting for client to join..").grid(row=13,column=0)
        tk.Button(f2, text="Stop", command=lambda:discon(2), justify=RIGHT).grid(row=7, column=1)
        thr1 = Thread(target=recvbox)
        thr1.start()
    except Exception as e:
        Label(f3,text="          Try Again            ").grid(row=13,column=0)
        sock.close()
def client():
    global tt
    global i
    global soc
    global ff
    global thr
    global options
    global f3
    global f2
    global encrypter
    global decrypter
    global crypt
    global opt
    global sadd
    global sport
    global listbox
    try:
        soc=s.socket(s.AF_INET,s.SOCK_STREAM)
        soc.connect((sadd.get(),sport.get()))
        bb = tk.Button(f2, text="Disconnect", command=lambda: discon(1), justify=RIGHT).grid(row=8, column=1)
        opt=str(options.get())
        print("Encryption technique : ", opt)
        if(opt=="RSA"):
            soc.sendall("RSA".encode())
            xx=str(soc.recv(4096).decode())
            l=xx.split(",")
            encrypter=(int(l[0]),int(l[1]))
            crypt=rsa()
            decrypter=crypt.key[1]
            xx=crypt.key[0]
            dd=str(xx[0])+","+str(xx[1])
            soc.sendall(dd.encode())
        elif(opt=="SSL"):
            soc.sendall("SSL".encode())
            xx=soc.recv(4096)
            xx=pickle.loads(xx)
            crypt=nssl()
            ch = rsa()
            #Certificate verification
            """"
            z1=xx[0][0]
            z2=xx[1]
            ch=rsa()
            z3=ch.rsadecrypt(z1,z2)
            if(a.get()==z3):
                z4=ch.rsaencrypt(crypt.key,z2)
            """
            print(xx[0])
            z6=ch.rsaencrypt(xx[0],crypt.key)
            z6=pickle.dumps(z6)
            soc.sendall(z6)
            encrypter=crypt.key
            decrypter=crypt.key
        print("Encryption key :", encrypter)
        print("Decryption key :", decrypter)
        tt = tk.Tk()
        tt.title('Client')
        ff = Frame(tt,bg="green",bd=5)
        ff.pack(side=BOTTOM,fill=BOTH)
        data = StringVar(ff)
        Label(ff, text="Connected to server :"+str(sadd.get())).pack(side=TOP)
        i=3
        t=Thread(target=recvfrom,args=(1,))
        t.start()
        Entry(ff,bd=5,textvariable=data).pack(side=LEFT)
        tk.Button(ff,text="SEND",command=lambda:sendto(data,1),justify=RIGHT).pack(side=LEFT)
        tk.Button(ff, text="FILES", command=lambda:attach(1), justify=RIGHT).pack(side=LEFT)
        tk.Button(ff, text="STEGO", command=lambda: stego(), justify=RIGHT).pack(side=LEFT)
        ff2 = Frame(tt, bg="white", bd=5)
        ff2.pack(side=BOTTOM,fill=BOTH)
        sb = Scrollbar(ff2)
        sb.pack(side=RIGHT,fill=Y)
        sb1 = Scrollbar(ff2,orient=HORIZONTAL)
        sb1.pack(side=BOTTOM,fill=X)
        listbox = Listbox(ff2, yscrollcommand=sb.set, xscrollcommand=sb1.set)
        listbox.pack(side=LEFT, fill=BOTH)
        sb.config(command=listbox.yview)
        sb1.config(command=listbox.xview)
        tt.mainloop()
        soc.close()
    except Exception as e:
        Label(f3,text="          Try Again            ").grid(row=13,column=0)
def joinserver():
    global top
    global f2
    global options
    global sadd
    global sport
    f2.grid_forget()
    f2.grid(row=5, column=0, rowspan=6)
    sadd=StringVar(f2,value="127.0.0.1")
    sport=IntVar(f2,value=89)
    Label(f2, text="Enter Server address :").grid(row=5,column=0)
    Entry(f2, bd =5,textvariable=sadd).grid(row=5,column=2)
    Label(f2, text="Enter Server port :").grid(row=6, column=0)
    Entry(f2, bd=5,textvariable=sport).grid(row=6, column=2)
    Label(f2, text="Enter encryption technique :").grid(row=7, column=0)
    options=StringVar(f2)
    choices = {'RSA', 'AES','SSL'}
    options.set('RSA')
    tk.OptionMenu(f2,options,*choices).grid(row=7,column=2)
    tk.Button(f2,text="Connect",command=lambda:client(),justify=RIGHT).grid(row=8,column=1)
def encrypt(data):
    global opt
    global encrypter
    global crypt
    if(opt=="RSA"):
        dat=crypt.rsaencrypt(encrypter,data)
        da=pickle.dumps(dat)
    elif(opt=="SSL"):
        dat=crypt.encrypt(data,encrypter)
        da=pickle.dumps(dat)
    return da
def decrypt(data):
    global opt
    global decrypter
    global crypt
    if(opt=="RSA"):
        dat=pickle.loads(data)
        da=str(crypt.rsadecrypt(decrypter,dat))
    elif(opt=="SSL"):
        dat=pickle.loads(data)
        da=str(crypt.decrypt(dat,decrypter))
    return da
def stego():
    global ttt
    global f4
    global f5
    global stegtext
    ttt=tk.Tk()
    ttt.title("Steganography")
    f4=Frame(ttt,bg="green",bd=5)
    f4.grid(row=1, column=0, rowspan=7)
    Label(f4, text="Select Image :").grid(row=2, column=0)
    tk.Button(f4, text="Files", command=lambda:stegf()).grid(row=2, column=4)
    Label(f4, text="Enter info to hide :").grid(row=4, column=0)
    Entry(f4, bd=5, textvariable=stegtext).grid(row=4, column=4)
    tk.Button(f4, text="Hide Info", command=steghide).grid(row=6, column=3)
    f5=Frame(ttt,bg="blue",bd=5)
    f5.grid(row=8,column=0,rowspan=14)
    Label(f5, text="Select Image :").grid(row=9, column=0)
    tk.Button(f5, text="Files", command=stego).grid(row=9, column=4)
    tk.Button(f5, text="Retrieve hidden info", command=stego).grid(row=11, column=3)
    ttt.mainloop()
def steghide():
    print("")
def stegretrieve():
    print("")
def stegf():
    global ttt
    global defaultloc
    global stegfile
    global f4
    ttt.filename = filedialog.askopenfilename(initialdir=defaultloc, title="Select file",filetypes=(("jpeg files", "*.jpg"),))
    stegfile=str(ttt.filename)
    if((stegfile=="") or (not ("." in stegfile))):
        return
    stegfile = stegfile.split('/')
    stegfile = stegfile[len(stegfile) - 1]
    tk.Button(f4, text=str(stegfile), command=lambda:stegf()).grid(row=2, column=3)
def setdefaultloc():
    global defaultloc
    defaultloc = filedialog.askdirectory(initialdir="/", title="Select default folder")
    print("Default location set to :",defaultloc)
top=tk.Tk()
top.title("Information security project")
menubar=Menu(top)
fileMenu = Menu(menubar)
top.config(menu=menubar)
fileMenu.add_command(label="Set default location", command=setdefaultloc)
fileMenu.add_command(label="Exit", command=quit)
menubar.add_cascade(label="File", menu=fileMenu)
f1=Frame(top,bg="red",bd=5)
f1.grid(row=1,column=0,rowspan=3)
tk.Button(f1,text="Connect to server",command=joinserver).grid(row=1,column=0)
tk.Button(f1,text="Create a server",command=createserver).grid(row=2,column=0)
tk.Button(f1,text="Steganography",command=stego).grid(row=3,column=0)
f2=Frame(top,bg="blue",bd=5)
f2.grid(row=5,column=0,rowspan=6)
f3=Frame(top,bg="green",bd=5)
f3.grid(row=12,column=0,rowspan=25)
top.mainloop()
