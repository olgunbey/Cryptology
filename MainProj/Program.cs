// See https://aka.ms/new-console-template for more information


using System.Numerics;
using System.Security.Cryptography;
using System.Text;

static BigInteger GeneratePrime(int bitLength)
{
    using (var rng = new RNGCryptoServiceProvider())
    {
        var randomBytes = new byte[bitLength / 8];
        rng.GetBytes(randomBytes);

        // En yüksek ve en düşük bitleri 1 olan bir asal sayı oluştur
        randomBytes[0] |= 0x80; // En yüksek biti 1 yap
        randomBytes[randomBytes.Length - 1] |= 0x01; // En düşük biti 1 yap

        return new BigInteger(randomBytes);
    }
}
static string CreateKey(byte[] array)
{
    StringBuilder stringBuilder = new StringBuilder();
    for (int i = 0; i < array.Length; i++)
    {
        stringBuilder.Append(array[i].ToString("x2"));
    }

    return stringBuilder.ToString();
}

Kullanici alice = new Kullanici();
Kullanici bob = new Kullanici();
SHA256 sha256=SHA256.Create();
using (DiffieHellmanAlg diffieHellmanAlg = new DiffieHellmanAlg())
{

BigInteger prime = GeneratePrime(2048); //2048bit uzunluğunda bir asal modül elde ediyoruz

BigInteger generator = 2; //2 üreteçtir;

BigInteger alicePriveKey = diffieHellmanAlg.GeneratePrivateKey(prime);
BigInteger bobPrivateKey = diffieHellmanAlg.GeneratePrivateKey(prime);
var alicePrivateKeys= sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(alicePriveKey))); //256 bitlik bir anahtar 
var bobPrivateKeys = sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(bobPrivateKey)));

var alicePrivate = CreateKey(alicePrivateKeys);
var bobPrivate = CreateKey(bobPrivateKeys);
Console.WriteLine("alice için private key : {0}", alicePrivate);
Console.WriteLine("bob için private key: {0}", bobPrivate);
alice.PrivateKey = alicePrivate;
bob.PrivateKey = bobPrivate;


BigInteger alicePublicKey = diffieHellmanAlg.CalculatePublicKey(generator, prime, alicePriveKey);
BigInteger bobPublicKey = diffieHellmanAlg.CalculatePublicKey(generator, prime, bobPrivateKey);
var alicePublicKeys = sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(alicePublicKey)));
var bobPublicKeys = sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(bobPublicKey)));

var alicePublic=CreateKey(alicePublicKeys);

var bobPublic=CreateKey(bobPublicKeys);

alice.PublicKey = alicePublic;
bob.PublicKey = bobPublic;


BigInteger aliceSharedSecret = diffieHellmanAlg.CalculateSharedSecret(bobPublicKey, prime, alicePriveKey);
BigInteger bobSharedSecret = diffieHellmanAlg.CalculateSharedSecret(alicePublicKey, prime, bobPrivateKey);

var aliceSharedKey= sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(aliceSharedSecret)));
var bobSharedKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToString(bobSharedSecret)));

var aliceShared=CreateKey(aliceSharedKey);

var bobShared=CreateKey(bobSharedKey);
alice.SharedKey = aliceShared;
bob.SharedKey = bobShared;
Console.WriteLine("alice için ortak anahtar: {0}",aliceShared);
Console.WriteLine("bob için ortak anahtar: {0}",bobShared);
}

string AliceGonderilecekMesaj = "merhaba bob ben alice";
Aes aes = new Aes();
KeyAes keyAes = new KeyAes(aes);

using (AesEncrypt aesEncrypt = new AesEncrypt(aes,keyAes))
{
  byte[] EncryptData=  aesEncrypt.Encrypt(AliceGonderilecekMesaj, alice.SharedKey);
  
  
  using (var aliceRSA = new RSACryptoServiceProvider(2048))
  using (var bobRSA = new RSACryptoServiceProvider(2048)) 
  {
      
      RSAParameters alicePrivateKey = aliceRSA.ExportParameters(true);
      
      RSAParameters bobPrivateKey = bobRSA.ExportParameters(true);

      // Alice bir mesajı imzalar
      string messageFromAlice = "Bu bir örnek mesajdır.";
      byte[] signatureFromAlice = RSASignData.SignData(EncryptData, alicePrivateKey);

      Console.WriteLine("Alice tarafından oluşturulan imza: " + Convert.ToBase64String(signatureFromAlice));

      // // Bob, Alice'in imzalı mesajını doğrular
      // bool isVerifiedByBob = RSASignData.VerifyData(EncryptData, signatureFromAlice, aliceRSA.ExportParameters(false));
      //
      // Console.WriteLine("Bob tarafından doğrulama sonucu: " + isVerifiedByBob);
  }
}















public class RSASignData:IDisposable
{
    public static byte[] SignData(byte[] data, RSAParameters privateKey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(data, new SHA256CryptoServiceProvider());
        }
    }
    public static bool VerifyData(byte[] data, byte[] signature, RSAParameters publicKey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(data, new SHA256CryptoServiceProvider(), signature);
        }
    }

    public void Dispose()
    {
        // TODO release managed resources here
    }
}
public class DiffieHellmanAlg : IDisposable
{
     public BigInteger GeneratePrivateKey(BigInteger prime)
    {
        Random rand = new Random();
        BigInteger privateKey;

        do
        {
            byte[] privateKeyBytes = new byte[prime.ToByteArray().Length];
            rand.NextBytes(privateKeyBytes);

            // Özel anahtar, 1 ile prime arasında olmalıdır
            privateKey = new BigInteger(privateKeyBytes) % (prime - 1) + 1;
        }
        while (privateKey <= 1 || privateKey >= prime - 1);

        return privateKey;
    }
   
     public BigInteger CalculatePublicKey(BigInteger generator, BigInteger prime, BigInteger privateKey)
     {
         return BigInteger.ModPow(generator, privateKey, prime);
     }
     public BigInteger CalculateSharedSecret(BigInteger otherPartyPublicKey, BigInteger prime, BigInteger privateKey)
     {
         return BigInteger.ModPow(otherPartyPublicKey, privateKey, prime);
     }
     

     public void Dispose()
     {
         // TODO release managed resources here
     }
}

public interface IAes
{
    public byte SubByte(byte value);
    public void ShiftRows(byte[,] state);
    public void MixColumns(byte[,] state);
    public byte GaloisMultiply(byte a, byte b);
    public void SubBytes(byte[,] state);
}

public interface IAesKey
{
    public void AddRoundKey(byte[,] state, byte[,] roundKey, int round = 0);
    public byte[,] KeyExpansion(byte[] key, int Nr);
    public byte[] SubWord(byte[] word);
}
public class Kullanici
{
    public string PrivateKey { get; set; }
    public string PublicKey { get; set; }
    public string SharedKey { get; set; }
    public string Type { get; set; }
}

public class Aes:IAes
{
   public void SubBytes(byte[,] state)
    {   
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i, j] = SubByte(state[i, j]);
            }
        }
    }

   public byte SubByte(byte value)
   {
       byte[,] sBox = new byte[,]
       {
           {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
           {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
           {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
           {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
           {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
           {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
           {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
           {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
           {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
           {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
           {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
           {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
           {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
           {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
           {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
           {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
       };
       var y = value / 16;
       var x = value % 16;
       return sBox[y, x];

   }
   public void ShiftRows(byte[,] state)
   {
       // ShiftRows işlemi
       for (int i = 1; i < 4; i++)
       {
           for (int j = 0; j < i; j++)
           {
               byte temp = state[i, 0];
               for (int k = 0; k < 3; k++)
               {
                   state[i, k] = state[i, k + 1];
               }
               state[i, 3] = temp;
           }
       }
   }
   public void MixColumns(byte[,] state)
   {
       // MixColumns işlemi
       // (Bu örnek, gerçek MixColumns matris değerleri yerine sabit bir matris kullanmaktadır)
       byte[,] mixColumnsMatrix = {
           {0x02, 0x03, 0x01, 0x01},
           {0x01, 0x02, 0x03, 0x01},
           {0x01, 0x01, 0x02, 0x03},
           {0x03, 0x01, 0x01, 0x02}
       };

       byte[,] result = new byte[4, 4];

       for (int i = 0; i < 4; i++)
       {
           for (int j = 0; j < 4; j++)
           {
               byte val = 0;
               for (int k = 0; k < 4; k++)
               {
                   val ^= GaloisMultiply(mixColumnsMatrix[i, k], state[k, j]);
               }
               result[i, j] = val;
           }
       }

       // Sonucu state matrisine kopyala
       for (int i = 0; i < 4; i++)
       {
           for (int j = 0; j < 4; j++)
           {
               state[i, j] = result[i, j];
           }
       }
   }
   public byte GaloisMultiply(byte a, byte b)
   {
       // Galois çarpımı işlemi
       byte result = 0;
       byte hiBitSet;
       for (int i = 0; i < 8; i++)
       {
           if ((b & 1) == 1)
           {
               result ^= a;
           }

           hiBitSet = (byte)(a & 0x80);
           a <<= 1;
           if (hiBitSet == 0x80)
           {
               a ^= 0x1B; // XOR with the irreducible polynomial in GF(2^8)
           }

           b >>= 1;
       }

       return result;
   }
  
}

public class KeyAes:IAesKey
{
    private readonly IAes _aes;
    public KeyAes(IAes aes)
    {
        _aes = aes;
    }
    public void AddRoundKey(byte[,] state, byte[,] roundKey, int round = 0)
    {
        // AddRoundKey işlemi
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i, j] ^= roundKey[i, 4 * round + j];
            }
        }
    }
    public byte[,] KeyExpansion(byte[] key, int Nr)
    {
        byte[] Rcon = new byte[]
        {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };
        int Nk = key.Length / 4;
        int Nb = 4;

        byte[,] roundKey = new byte[4, Nb * (Nr + 1)];

        // İlk tur anahtarı, doğrudan anahtar kelimesini kullanır
        for (int i = 0; i < Nk; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                roundKey[j, i] = key[i * 4 + j];
            }
        }

        for (int i = Nk; i < Nb * (Nr + 1); i++)
        {
            byte[] temp = new byte[4];

            for (int j = 0; j < 4; j++)
            {
                temp[j] = roundKey[j, i - 1];
            }

            if (i % Nk == 0)
            {
                temp = SubWord(RotWord(temp));
                for (int j = 0; j < 4; j++)
                {
                    int rconIndex = j + i / Nk - 1;
                    temp[j] ^= (rconIndex < Rcon.Length) ? Rcon[rconIndex] : (byte)0;
                }
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                temp = SubWord(temp);
            }

            for (int j = 0; j < 4; j++)
            {
                roundKey[j, i] = (byte)(roundKey[j, i - Nk] ^ temp[j]);
            }
        }

        return roundKey;
    }
    public byte[] SubWord(byte[] word)
    {
        for (int i = 0; i < 4; i++)
        {
            word[i] = _aes.SubByte(word[i]);
        }
        return word;
    }

    public byte[] RotWord(byte[] word)
    {
        byte temp = word[0];
        for (int i = 0; i < 3; i++)
        {
            word[i] = word[i + 1];
        }
        word[3] = temp;
        return word;
    }
    
}


public class AesEncrypt:IDisposable
{
    private readonly IAes _aes;
    private readonly IAesKey _aesKey;
    public AesEncrypt(IAes aes,IAesKey aesKey)
    {
        _aes = aes;
        _aesKey = aesKey;
    }

    public byte[] Encrypt(string text, string keys)
    {
        var textBytes= Encoding.UTF8.GetBytes(text);
        var key= Encoding.UTF8.GetBytes(keys);
        int Nb = 4; // Blok boyutu (32-bit kelimelerin sayısı)
        int Nr = 14; // Tur sayısı

        byte[,] state = new byte[4, Nb];

        // Veriyi state matrisine kopyala
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < Nb; j++)
            {
                state[i, j] = textBytes[i + 4 * j];
            }
        }

        byte[,] roundKey = _aesKey.KeyExpansion(key, Nr);

       _aesKey.AddRoundKey(state, roundKey);

        for (int round = 1; round < Nr; round++)
        {
          _aes.SubBytes(state);
          _aes.ShiftRows(state);
          _aes.MixColumns(state);
          _aesKey.AddRoundKey(state, roundKey, round);
        }

        _aes.SubBytes(state);
        _aes.ShiftRows(state);
        _aesKey.AddRoundKey(state, roundKey, Nr);

        // Şifrelenmiş veriyi byte dizisine dönüştür
        byte[] encryptedData = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < Nb; j++)
            {
                encryptedData[i + 4 * j] = state[i, j];
            }
        }

        return encryptedData;
    }

    public void Dispose()
    {
        // TODO release managed resources here
    }
}