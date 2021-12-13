import time


class Encryption:
    def __init__(self):
        # --------------------------------DEĞİŞKENLERİ TANIMLA-----------------------------------------
        self.onaltilikBINARYANAHTARlist = []
        self.onaltilikBINARYPLAINTEXTlist = []
        self.allCipherbits16lik = []

    # --------------------------------FONSİYONLARI TANIMLA-----------------------------------------
    def strTOBinIkiliGrupluListe(self, plaintext: str):
        """
        BU FONKSİYON ALDIĞI STRİNG PARAMETREDEKİ HER BİR KARAKTERİ
        SEKİZ BİT E DONUSTUREREK, HER BİR 8 BİT İ BİR LİSTEYE EKLER
        DAHA SONRA BAŞTAN BAŞLAYARAK HER İKİLİ 8 BİT İ BİRLEŞTİREREK 16 BİT HALİNE GETİRİR
        HER BİR 16 BİT BİR LİSTEYE EKLENİR VE NİHAİ LİSTE GERİ DÖNDÜRÜLÜR
        :param plaintext: STRING
        :return: 16 BITS LIST
        """
        onaltibitsiralibinarylist = []
        sekizbitliksiralikarakterler = '/'.join((format(ord(i), '08b') for i in plaintext)).split("/")

        k = 2
        for i in range(0, len(sekizbitliksiralikarakterler), 2):
            temp = "".join(sekizbitliksiralikarakterler[i:k])
            # print(i, temp)
            k += 2
            if len(temp) < 16:  # eğer 16 bit uzunluğa ulaşamıyorsak 8 bitlik 0 ekliyoruz.
                temp += "00000000"
            onaltibitsiralibinarylist.append(temp)
        return onaltibitsiralibinarylist

    def anahtariveplaintexi16likBINARYyap(self, plaintext: str, anahtar: str):
        self.onaltilikBINARYPLAINTEXTlist.extend(self.strTOBinIkiliGrupluListe(plaintext))
        self.onaltilikBINARYANAHTARlist.extend(self.strTOBinIkiliGrupluListe(anahtar))

    def xorvepermutasyonUygula(self, plainBIN16list: list, anahtarBIN16list: list):
        """
        BU FONKSİYON 16 BİTLİK VERİLERDEN OLUŞAN İKİ LİSTE ALIR
        VE BU LİSTELERİN HER BİR İNDEXİNDEKİ 16 BİTLİK VERİLERİ ALARAK
        İÇERİDEKİ HER BİR BİTİ BİRBİRİ İLE XOR İŞLEMİNE TABİ TUTAR
        :param plainBIN16list: LIST
        :param anahtarBIN16list: LIST
        :return: LIST
        """
        donulecekcipherliste = []
        tempXor = []
        for plainidex in plainBIN16list:
            tempplainindex = plainidex
            for keyindex in anahtarBIN16list:
                for i in range(16):
                    tempXor.append(str(int(tempplainindex[i]) ^ int(keyindex[i])))
                tempplainindex = "".join(tempXor)
                tempXor.clear()
                if keyindex == anahtarBIN16list[-1]:
                    donulecekcipherliste.append(self.CipherOlustur(tempplainindex))
                    self.allCipherbits16lik.append(tempplainindex)
                    continue  # burası çalışınca plainBin16listin diğer indexine geçiyoruz
                tempplainindex = self.permutasyonislemiUygula(tempplainindex)
        print("allbitscp", self.allCipherbits16lik)
        return donulecekcipherliste

    def BinaryToDecimal(self, binary):
        string = int(binary, 2)
        return string

    def CipherOlustur(self, bitdegerial: str):
        str_data = ""
        liste = []
        for i in range(0, len(bitdegerial), 8):
            temp_data = bitdegerial[i:i + 8]
            decimal_data = self.BinaryToDecimal(temp_data)
            str_data = str_data + chr(decimal_data)
            print("BIN: {}   DEC: {:>4}   CHR {}".format(temp_data, decimal_data, chr(decimal_data)))
            liste.append(chr(decimal_data))
        return str_data

    def permutasyonislemiUygula(self, permuyg16bitveri: str):
        temppermtsynliste = []
        iter = 0
        for i in range(16):
            temppermtsynliste.append("0")
        liste = [5, 9, 0, 12, 7, 3, 11, 14, 1, 4, 13, 8, 2, 15, 6, 10]
        for i in liste:
            temppermtsynliste[i] = permuyg16bitveri[iter]
            iter += 1
        return "".join(temppermtsynliste)

    def cipherSonuc(self, cipherliste: list):
        return "".join(cipherliste)


class Decyrption:
    def __init__(self, ):
        # --------------------------------DEĞİŞKENLERİ TANIMLA-----------------------------------------
        self.allcipeherbitsdatareversed=[]
        self.allanahtarbitsdata=[]
        self.allplaintbits16lik = []

    def TersxorvepermutasyonUygula(self,allcipherbitsdata: list, allanahtarbits: list ):
        # self.allcipeherbitsdata ^ self.allanahtarbitsdata = bir önceki xor hali bunu ters permütasyon yap

        self.allcipeherbitsdatareversed.extend(allcipherbitsdata)
        self.allcipeherbitsdatareversed.reverse()
        self.allanahtarbitsdata.extend(allanahtarbits)
        donulecekplainliste = []
        tempXor = []
        for plainidex in self.allcipeherbitsdatareversed:
            tempplainindex = plainidex
            for keyindex in self.allanahtarbitsdata:
                for i in range(16):
                    tempXor.append(str(int(tempplainindex[i]) ^ int(keyindex[i])))
                tempplainindex = "".join(tempXor)
                tempXor.clear()
                if keyindex == self.allanahtarbitsdata[-1]:
                    donulecekplainliste.append(self.PlainOlustur(tempplainindex))
                    self.allplaintbits16lik.append(tempplainindex)
                    continue  # burası çalışınca plainBin16listin diğer indexine geçiyoruz
                tempplainindex = self.TersPermutasyonislemiUygula(tempplainindex)
        print("allbitspl", self.allplaintbits16lik)
        return donulecekplainliste

    def TersPermutasyonislemiUygula(self, permuyg16bitveri: str):
        temppermtsynliste = []
        iter = 0
        for i in range(16):
            temppermtsynliste.append("0")

        for i in [5, 9, 0, 12, 7, 3, 11, 14, 1, 4, 13, 8, 2, 15, 6, 10]:
            temppermtsynliste[iter] = permuyg16bitveri[i]
            iter += 1
        return "".join(temppermtsynliste)

    def PlainOlustur(self, bitdegerial: str):
        str_data = ""
        liste = []
        for i in range(0, len(bitdegerial), 8):
            temp_data = bitdegerial[i:i + 8]
            decimal_data = self.BinaryToDecimalDec(temp_data)
            str_data = str_data + chr(decimal_data)
            print("BIN: {}   DEC: {:>4}   CHR {}".format(temp_data, decimal_data, chr(decimal_data)))
            liste.append(chr(decimal_data))
        return str_data

    def BinaryToDecimalDec(self, binary):
        string = int(binary, 2)
        return string

    def PlainSonuc(self, cipherliste: list):
        return "".join(cipherliste)



# --------------------------------FONSİYONLARI ÇALIŞTIR-----------------------------------------

while True:
    E = Encryption()
    D = Decyrption()
    plainText = input("Bir mesaj yazin: ")
    anahtar = input("Bir anahtar yazin: ")
    E.anahtariveplaintexi16likBINARYyap(plainText, anahtar)
    cipherTextliste = E.xorvepermutasyonUygula(E.onaltilikBINARYPLAINTEXTlist, E.onaltilikBINARYANAHTARlist)
    print(f"16BITPLAIN: {E.onaltilikBINARYPLAINTEXTlist}")
    print(f"16BITANAHTAR: {E.onaltilikBINARYANAHTARlist}")
    cipherSONUCTEXT = E.cipherSonuc(cipherTextliste)
    print(f"Cipher Text Sonucu: {cipherSONUCTEXT}")
    print("Şifre Çözülüyor....")
    time.sleep(1.37)
    plainTextListe = D.TersxorvepermutasyonUygula(E.allCipherbits16lik,E.onaltilikBINARYANAHTARlist)
    plainSonucText = D.PlainSonuc(plainTextListe)
    print(f"PlainText: {plainSonucText}")
    E=None
    D=None