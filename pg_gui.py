#! /usr/bin/env python

import tkinter as tk
from tkinter.ttk import *
from scapy.all import *
root = tk.Tk()
root.geometry("800x600+300+100")

note = Notebook(root)

tab1 = Frame(note, width=500, height=300)
tab2 = Frame(note, width=500, height=300)
tab3 = Frame(note, width=500, height=300)
butonE = tk.Button(root, text='Exit', command=root.destroy).pack()

note.add(tab1, text="Tab One", compound=tk.TOP)


label = Label(tab1,text="Kaynak MAC")
label.grid(row=0, sticky=tk.W)
srcMAC = tk.Text(tab1, width=17, height=1)
srcMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
srcMAC.grid(row=0, column=1)


label = Label(tab1,text="Hedef MAC")
label.grid(row=1,sticky=tk.W)
dstMAC = tk.Text(tab1, width=17, height=1)
dstMAC.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
dstMAC.grid(row=1, column=1)


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

def gonderARP():
    kaynakMAC = srcMAC.get(1.0,1.17)
    hedefMAC = dstMAC.get(1.0,1.17)
    kaynakPA = psrc.get(1.0,1.15)
    hedefPA = pdst.get(1.0,1.15)
    kaynakHA = hwsrc.get(1.0,1.17)
    hedefHA = hwdst.get(1.0,1.17)
    arp = send(Ether(src=kaynakMAC, dst=hedefMAC)/ARP(op=2, psrc=kaynakPA, hwdst=hedefHA, hwsrc=kaynakHA, pdst=hedefPA))
    if arp:
     arp.show()
butonGonder = tk.Button(tab1, text='Gönder', command=gonderARP).grid(row=6, sticky=tk.W)

note.add(tab2, text="Tab Two")

labelk = Label(tab2,text="Kaynak MAC")
labelk.grid(row=0, sticky=tk.W)
srcMAC1 = tk.Text(tab2, width=17, height=1)
srcMAC1.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
srcMAC1.grid(row=0, column=1)


labelk = Label(tab2,text="Hedef MAC")
labelk.grid(row=0, column=2, sticky=tk.W)
dstMAC1 = tk.Text(tab2, width=17, height=1)
dstMAC1.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
dstMAC1.grid(row=0, column=3)

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

def gonderIP():
    kaynakMAC = srcMAC1.get(1.0, 'end-1c')
    hedefMAC = dstMAC1.get(1.0, 'end-1c')
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
    
    #ip = send(Ether(src=kaynakMAC, dst=hedefMAC)/IP(options=IPOption()))
    #if ip:
     #p.show()
	
	
    ip = send(Ether(src=kaynakMAC, dst=hedefMAC)/IP(version=versionN, ihl=internetBaslikU, tos=servisTuru, len=toplamUzunluk, id=kimlikBilgisi, flags=bayraklar, frag=parcaNo, ttl=yasamSuresi, proto=protokolNo, chksum=kontrolB, src=kaynakIPadres, dst=hedefIPadres))
    if ip:
     p.show()

butonGonder = tk.Button(tab2, text='Gönder', command=gonderIP).grid(row=9, sticky=tk.W)


note.add(tab3, text="Tab Three")

labelk = Label(tab3,text="Kaynak MAC")
labelk.grid(row=0, sticky=tk.W)
srcMAC1 = tk.Text(tab3, width=17, height=1)
srcMAC1.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
srcMAC1.grid(row=0, column=1)


labelk = Label(tab3,text="Hedef MAC")
labelk.grid(row=0, column=2, sticky=tk.W)
dstMAC1 = tk.Text(tab3, width=17, height=1)
dstMAC1.insert(tk.INSERT, "ff:ff:ff:ff:ff:ff")
dstMAC1.grid(row=0, column=3)
#ip
labelk = Label(tab3,text="IP versiyon")
labelk.grid(row=2,sticky=tk.W)
versiyon = tk.Text(tab3, width=15, height=1)
versiyon.insert(tk.INSERT, "4")
versiyon.grid(row=2, column=1)

labelk = Label(tab3,text="Başlık uzunluğu")
labelk.grid(row=2, column=2, sticky=tk.W)
ibu = tk.Text(tab3, width=15, height=1)
ibu.insert(tk.INSERT, "4")
ibu.grid(row=2, column=3)

labelk = Label(tab3,text="Hizmet tipi")
labelk.grid(row=3,sticky=tk.W)
servisT = tk.Text(tab3, width=15, height=1)
servisT.insert(tk.INSERT, "4")
servisT.grid(row=3, column=1)

labelk = Label(tab3,text="Toplam uzunluk")
labelk.grid(row=3, column=2, sticky=tk.W)
toplamU = tk.Text(tab3, width=15, height=1)
toplamU.insert(tk.INSERT, "4")
toplamU.grid(row=3, column=3)

labelk = Label(tab3,text="Identification")
labelk.grid(row=4,sticky=tk.W)
idBilgisi = tk.Text(tab3, width=15, height=1)
idBilgisi.insert(tk.INSERT, "4")
idBilgisi.grid(row=4, column=1)

labelk = Label(tab3,text="Bayraklar")
labelk.grid(row=4, column=2, sticky=tk.W)
bayrak = tk.Text(tab3, width=1, height=1)
bayrak.insert(tk.INSERT, "4")
bayrak.grid(row=4, column=3)

labelk = Label(tab3,text="Fragment ofseti")
labelk.grid(row=5,sticky=tk.W)
parcaN = tk.Text(tab3, width=15, height=1)
parcaN.insert(tk.INSERT, "4")
parcaN.grid(row=5, column=1)

labelk = Label(tab3,text="Yaşam süresi")
labelk.grid(row=5, column=2, sticky=tk.W)
yasamS = tk.Text(tab3, width=15, height=1)
yasamS.insert(tk.INSERT, "4")
yasamS.grid(row=5, column=3)

labelk = Label(tab3,text="Protokol")
labelk.grid(row=6,sticky=tk.W)
protokol = tk.Text(tab3, width=15, height=1)
protokol.insert(tk.INSERT, "00")
protokol.grid(row=6, column=1)

labelk = Label(tab3,text="Header checksum")
labelk.grid(row=6, column=2, sticky=tk.W)
kontrol = tk.Text(tab3, width=15, height=1)
kontrol.insert(tk.INSERT, "36")
kontrol.grid(row=6, column=3)

labelk = Label(tab3,text="Kaynak IP adresi")
labelk.grid(row=7,sticky=tk.W)
kaynakIP = tk.Text(tab3, width=15, height=1)
kaynakIP.insert(tk.INSERT, "0.0.0.0")
kaynakIP.grid(row=7, column=1)

labelk = Label(tab3,text="Hedef IP adresi")
labelk.grid(row=7, column=2, sticky=tk.W)
hedefIP = tk.Text(tab3, width=15, height=1)
hedefIP.insert(tk.INSERT, "0.0.0.0")
hedefIP.grid(row=7, column=3)

labelk = Label(tab3,text="Seçenekler")
labelk.grid(row=8,sticky=tk.W)
secenek = tk.Text(tab3, width=15, height=1)
secenek.insert(tk.INSERT, "4")
secenek.grid(row=8, column=1)
#tcp
labelk = Label(tab3,text="Kaynak port")
labelk.grid(row=9,sticky=tk.W)
kaynakPort = tk.Text(tab3, width=15, height=1)
kaynakPort.insert(tk.INSERT, "80")
kaynakPort.grid(row=9, column=1)

labelk = Label(tab3,text="Hedef port")
labelk.grid(row=9, column=2, sticky=tk.W)
hedefPort = tk.Text(tab3, width=15, height=1)
hedefPort.insert(tk.INSERT, "80")
hedefPort.grid(row=9, column=3)

labelk = Label(tab3,text="Dizi numarası")
labelk.grid(row=10,sticky=tk.W)
diziNo = tk.Text(tab3, width=15, height=1)
diziNo.insert(tk.INSERT, "25")
diziNo.grid(row=10, column=1)

labelk = Label(tab3,text="Alındı numarası")
labelk.grid(row=10, column=2, sticky=tk.W)
ackNo = tk.Text(tab3, width=15, height=1)
ackNo.insert(tk.INSERT, "26")
ackNo.grid(row=10, column=3)

labelk = Label(tab3,text="Data offset")
labelk.grid(row=11,sticky=tk.W)
dataOfseti = tk.Text(tab3, width=15, height=1)
dataOfseti.insert(tk.INSERT, "270")
dataOfseti.grid(row=11, column=1)

labelk = Label(tab3,text="Reserved")
labelk.grid(row=11, column=2, sticky=tk.W)
reservedT = tk.Text(tab3, width=15, height=1)
reservedT.insert(tk.INSERT, "0")
reservedT.grid(row=11, column=3)

labelk = Label(tab3,text="Bayraklar")
labelk.grid(row=12,sticky=tk.W)
bayrakT = tk.Text(tab3, width=15, height=1)
bayrakT.insert(tk.INSERT, "2")
bayrakT.grid(row=12, column=1)

labelk = Label(tab3,text="Pencere boyutu")
labelk.grid(row=12, column=2, sticky=tk.W)
pencereB = tk.Text(tab3, width=15, height=1)
pencereB.insert(tk.INSERT, "300")
pencereB.grid(row=12, column=3)

labelk = Label(tab3,text="TCP checksum")
labelk.grid(row=13,sticky=tk.W)
checksumT = tk.Text(tab3, width=15, height=1)
checksumT.insert(tk.INSERT, "755")
checksumT.grid(row=13, column=1)

labelk = Label(tab3,text="Urgent pointer")
labelk.grid(row=13, column=2, sticky=tk.W)
urgentP = tk.Text(tab3, width=15, height=1)
urgentP.insert(tk.INSERT, "12")
urgentP.grid(row=13, column=3)

labelk = Label(tab3,text="TCP seçenekler")
labelk.grid(row=14,sticky=tk.W)
secenekT = tk.Text(tab3, width=15, height=1)
secenekT.insert(tk.INSERT, "34")
secenekT.grid(row=14, column=1)

def gonderTCP():
    kaynakMAC = srcMAC1.get(1.0, 'end-1c')
    hedefMAC = dstMAC1.get(1.0, 'end-1c')
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
    kaynakPortadres = int(kaynakPort.get(1.0, 'end-1c'))
    hedefPortadres = int(hedefPort.get(1.0, 'end-1c'))
    diziNumarasi = diziNo.get(1.0, 'end-1c')
    ackNumarasi = ackNo.get(1.0, 'end-1c')
    dataOffset = dataOfseti.get(1.0, 'end-1c')
    reservedAlani = reservedT.get(1.0, 'end-1c')
    bayraklarT = bayrakT.get(1.0, 'end-1c')
    pencereBoyutu = pencereB.get(1.0, 'end-1c')
    checksumAlani = checksumT.get(1.0, 'end-1c')
    urgentPointer = urgentP.get(1.0, 'end-1c')
    seceneklerT = secenekT.get(1.0, 'end-1c')

    tcp = send(Ether(src=kaynakMAC, dst=hedefMAC)/IP(version=versionN, ihl=internetBaslikU,\
tos=servisTuru, len=toplamUzunluk, id=kimlikBilgisi, flags=bayraklar, frag=parcaNo,\
ttl=yasamSuresi, proto=protokolNo, chksum=kontrolB, src=kaynakIPadres, dst=hedefIPadres)/TCP(sport=kaynakPortadres, dport=hedefPortadres, seq=diziNumarasi,\
ack=ackNumarasi, dataofs=dataOffset, reserved=reservedAlani, flags=bayraklarT, window=pencereBoyutu, chksum=checksumAlani, urgptr=urgentPointer, options=seceneklerT))
    if tcp:
     p.show()


butonGonder = tk.Button(tab3, text='Gönder', command=gonderTCP).grid(row=15, sticky=tk.W)

note.pack()
root.mainloop()
