# AES-Cryptography #
### *The Best Aes Cryptography Library For C# ✔️*

## Supports

- `CBC { Specified IV }`✔️
- `CBC { Random IV }`✔️
- `ECB`✔️
---

## Dev =>  T.me/Ali_Cod7 
        
*Return Encrypted Strings With `CBC` | `ECB` Mode { Custom Paddings And Keysizes }*
        
*2 Modes Are Avalible For CBC Method :*
        
- *`Specified IV` [By User]*

- *`Random IV` [Generates Random IV]*
        
*Note => For ECB Mode Leave IV Filed Blank (Or You Can Fill It. Doesn't Make Change...)*

*Note => An Encrypted CBC String With Random Initialization Vector Can Not Be Decrypted!*
 
`128-Bit` | Secret Key Length -> 16 { IV Length For CBC -> 16 }

`192-Bit` | Secret Key Length -> 24 { IV Length For CBC -> 16 }

`256-Bit` | Secret Key Length -> 32 { IV Length For CBC -> 16 }
        
*PKCS7 , ANSIX923 , Zeros => Stable Result*

*SO10126 => Variable Result*

# **Usage** #
---
```c#
using System;
using static AesCrypto.AesManager;

string Original_Text = "Advanced Encryption Standard";

//=====================================[ECB Methoed]====================================\\ 

string EncryptedECB = Encrypt(Original_Text, "X3C2{-1K#YU3*W#A", null, Ctype.ECB, KeySize.Bit128, Ptype.PKCS7); 

string DecryptedECB = Decrypt(EncryptedECB, "X3C2{-1K#YU3*W#A", null, Ctype.ECB, KeySize.Bit128, Ptype.PKCS7);

//==================================[CBC { Random IV }]==================================\\

string EncryptedCBC_RandomIV = Encrypt("AES-Cryptography", "K$1<(:VHDWE^AS2(4*:R%DUE", null, Ctype.CBC, KeySize.Bit192, Ptype.ANSIX923);

//=================================[CBC { Specified IV }]================================\\

string EncryptedCBC = Encrypt("AES", "V}&EXWCU5OM|M|*B3YKZ1#LBFR}T!*M#", "DWE^AS2(4*:R%DUE", Ctype.CBC, KeySize.Bit256, Ptype.ISO10126);

string DecryptedCBC = Decrypt(EncryptedCBC, "V}&EXWCU5OM|M|*B3YKZ1#LBFR}T!*M#", "DWE^AS2(4*:R%DUE", Ctype.CBC, KeySize.Bit256, Ptype.ISO10126);

//========================================[Exaples]======================================\\

Console.WriteLine(">> Encrypted Text [ECB] : " + EncryptedECB);
Console.WriteLine(">> Decrypted Text [ECB] : " + DecryptedECB + "\n\n");
Console.WriteLine(">> Encrypted Text [CBC Random IV] : " + EncryptedCBC_RandomIV + "\n\n");
Console.WriteLine(">> Encrypted Text [CBC] : " + EncryptedCBC);
Console.WriteLine(">> Decrypted Text [CBC] : " + DecryptedCBC);
Console.WriteLine("\n>> Dev : T.me/Error772\n\n");
```
---

- ### **Telegram ID : [Error772](https://T.me/Error772)**
