# 📘 CCCD Chip Reader (C#)

A C# application for reading data from **Vietnamese chip-based Citizen ID cards (CCCD)** via NFC, using **BAC (ICAO 9303)** security.

---

## 🚀 Features
- Read **DG1**: Personal information  
- Read **DG13**: Extended information  
- Read **DG2**: Portrait image (JPEG/JPEG2000 → Base64)  
- Secure communication with the chip (Secure Messaging)

---

## 🧠 Technical Background

- **Communication Protocol**: 
    - Uses the **APDU (Application Protocol Data Unit)** protocol to communicate with the chip.
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
        throw new Exception($"GET CHALLENGE error: {resp.SW1:X2}{resp.SW2:X2}");

    return resp.GetData();
}
```

- **Encryption Algorithms**:
    
  - **3DES** (Triple Data Encryption Algorithm)
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
  - **SHA-1** (Secure Hash Algorithm 1)
    ```csharp
    public static byte[] Seed(string mrzKey)
    {
        byte[] h = SHA1.HashData(Encoding.ASCII.GetBytes(mrzKey));
        return Util.Sub(h, 0, 16);
    }
    ```

- **Authentication Mechanism**:
    - **BAC** (Basic Access Control) to securely establish a session with the smart card.
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
        throw new Exception($"BAC auth error: {resp.SW1:X2}{resp.SW2:X2}");

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

## ⚙️ Workflow
1. Input **MRZ**  
2. Generate keys (KENC, KMAC)  
3. Perform **BAC authentication**  
4. Establish Secure Messaging  
5. Read DG1, DG13, DG2  
6. Export and save data  

---

## 📂 Output
- Citizen information  
- Base64 image file  
- Files saved to Desktop  