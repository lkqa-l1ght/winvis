# 📘 Chip-based Citizen ID Card Reader (CCCD)

## 📌 Introduction

This is a **C# application** designed to read and extract data from **Vietnamese chip-based Citizen ID cards (CCCD)** via **NFC communication**.

The application implements **BAC (Basic Access Control)** based on the **ICAO 9303** standard to ensure secure data access.

### 🎯 Objectives
- Read personal information from DG1  
- Extract portrait image from DG2  
- Analyze extended information from DG13  

---

## 🧠 Technical Background

The application uses:

- **APDU protocol** to communicate with the chip
```csharp
public byte[] GetChallenge()
{
    var apdu = new CommandApdu(IsoCase.Case2Short, _iso.ActiveProtocol)
    {
        CLA = 0x00,
        INS = 0x84,
        P1 = 0x00,
        P2 = 0x00,
        Le = 8
    };

    var resp = _iso.Transmit(apdu);

    if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
        throw new Exception($"GET CHALLENGE lỗi: {resp.SW1:X2}{resp.SW2:X2}");

    return resp.GetData();
}
```
- Encryption algorithms:
  - **3DES**
```csharp
public static byte[] EncryptNoPadding(byte[] kenc, byte[] iv, byte[] data)
{
    using var t = TripleDES.Create();
    t.Key = Util.Cat(kenc, Util.Sub(kenc, 0, 8));
    t.IV = iv;
    t.Mode = CipherMode.CBC;
    t.Padding = PaddingMode.None;

    return t.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
}
```
  - **SHA-1**
```csharp
public static byte[] Seed(string mrzKey)
{
    byte[] h = SHA1.HashData(Encoding.ASCII.GetBytes(mrzKey));
    return Util.Sub(h, 0, 16);
}
```
- Authentication mechanism:
  - **BAC (Basic Access Control)**
```csharp
public (byte[] KSenc, byte[] KSmac, byte[] SSC) Run()
{
    var chip = new PassportChip(_iso);
    chip.SelectLdsApp();

    byte[] rndIcc = chip.GetChallenge();

    byte[] seed = Kdf.Seed(_mrz.Key);
    byte[] kenc = Kdf.Des(seed, 1);
    byte[] kmac = Kdf.Des(seed, 2);

    byte[] rndIfd = Util.Rand(8);
    byte[] kIfd = Util.Rand(16);

    byte[] s = Util.Cat(rndIfd, rndIcc, kIfd);

    byte[] eIfd = Des3.EncryptNoPadding(kenc, new byte[8], s);
    byte[] mIfd = Des3.Mac(kmac, eIfd).Take(8).ToArray();

    byte[] cmdData = Util.Cat(eIfd, mIfd);

    var apdu = new CommandApdu(IsoCase.Case4Short, _iso.ActiveProtocol)
    {
        CLA = 0x00,
        INS = 0x82,
        P1 = 0x00,
        P2 = 0x00,
        Data = cmdData,
        Le = 0
    };

    var resp = _iso.Transmit(apdu);

    if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
        throw new Exception($"BAC auth lỗi: {resp.SW1:X2}{resp.SW2:X2}");
    byte[] respData = resp.GetData();
    byte[] eIcc = Util.Sub(respData, 0, 32);
    byte[] sIcc = Des3.Decrypt(kenc, new byte[8], eIcc);
    byte[] kIcc = Util.Sub(sIcc, 16, 16);

    byte[] kSeed = Util.XOR(kIfd, kIcc);
    byte[] ksEnc = Kdf.Des(kSeed, 1);
    byte[] ksMac = Kdf.Des(kSeed, 2);
    byte[] ssc = Util.Cat(Util.Sub(rndIcc, 4, 4), Util.Sub(rndIfd, 4, 4));

    return (ksEnc, ksMac, ssc);
}
```
---

## ⚙️ Workflow

1. Input MRZ string
2. Validate MRZ (check digit)
3. Generate keys from MRZ (KDF)
4. Perform BAC authentication
5. Establish Secure Messaging
6. Read data from chip:
   - DG1 (Personal information)
   - DG13 (Additional information)
   - DG2 (Portrait image)
7. Export and save data

---

## 📂 Output

- Personal information displayed on console/UI
- Portrait image (Base64 or image file)
- Data files saved to Desktop

---

