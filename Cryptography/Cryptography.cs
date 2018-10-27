using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public class Cryptography
    {
        private static AesCryptoServiceProvider GetAesCryptoServiceProvider(String secretKey, byte[] iv, bool padding)
        {
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

            return new AesCryptoServiceProvider
            {
                Mode = CipherMode.CBC,
                Padding = (padding == true) ? PaddingMode.PKCS7 : PaddingMode.None,
                KeySize = 128,
                BlockSize = 128,
                Key = secretKeyBytes,
                IV = iv
            };
        }

        private static byte[] EncryptByte(byte[] plainBytes, AesCryptoServiceProvider aesCryptoServiceProvider, byte[] randomIv)
        {
            var encrypted = aesCryptoServiceProvider.CreateEncryptor()
                .TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            byte[] result = new byte[encrypted.Length + randomIv.Length];

            for (int i = 0; i < randomIv.Length; i++)
                result[i] = randomIv[i];

            for (int i = randomIv.Length; i < result.Length; i++)
                result[i] = encrypted[i - randomIv.Length];

            return result;
        }

        private static byte[] DecryptByte(byte[] encryptedData, AesCryptoServiceProvider aesCryptoServiceProvider)
        {
            return aesCryptoServiceProvider.CreateDecryptor()
                .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        public static String EncryptString(String plainText, String key)
        {
            try
            {
                var plainBytes = Convert.FromBase64String(plainText);
                var randomIv = CreateRandomIv();
                return Convert.ToBase64String(EncryptByte(plainBytes, GetAesCryptoServiceProvider(key, randomIv, false), randomIv));
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("Exception! Variable key or plainText. " + e.Message);
                return null;
            }
            catch (FormatException e)
            {
                Console.WriteLine("Exception! Variable plainText. " + e.Message);
                return null;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Exception! Variable key. " + e.Message);
                return null;
            }
        }
        public static String DecryptString(String encryptedText, String key)
        {
            try
            {
                var encryptedBytes = Convert.FromBase64String(encryptedText);
                byte[] iv = new byte[16];
                byte[] msg = new byte[encryptedBytes.Length - 16];

                for (int i = 0; i < 16; i++)
                    iv[i] = encryptedBytes[i];

                for (int i = 16; i < encryptedBytes.Length; i++)
                    msg[i - 16] = encryptedBytes[i];

                return Convert.ToBase64String(DecryptByte(msg, GetAesCryptoServiceProvider(key, iv, false)));
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("Exception! Variable key or plainText. " + e.Message);
                return null;
            }
            catch (FormatException e)
            {
                Console.WriteLine("Exception! Variable plainText. " + e.Message);
                return null;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Exception! Variable key. " + e.Message);
                return null;
            }
        }

        public static String EncryptStringPadding(String plainText, String key)
        {
            //string plainBytes = plainText.Replace('-', '+').Replace('_', '/');
            try
            {
                var plainBytes = Convert.FromBase64String(plainText);
                byte[] randomIv = CreateRandomIv();
                return Convert.ToBase64String(EncryptByte(plainBytes, GetAesCryptoServiceProvider(key, randomIv, true), randomIv));
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("Exception! Variable key or plainText. " + e.Message);
                return null;
            }
            catch (FormatException e)
            {
                Console.WriteLine("Exception! Variable plainText. " + e.Message);
                return null;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Exception! Variable key. " + e.Message);
                return null;
            }
        }

        public static String DecryptStringPadding(String encryptedText, String key)
        {
            try
            {
                var encryptedBytes = Convert.FromBase64String(encryptedText);
                byte[] iv = new byte[16];
                byte[] msg = new byte[encryptedBytes.Length - 16];

                for (int i = 0; i < 16; i++)
                    iv[i] = encryptedBytes[i];

                for (int i = 16; i < encryptedBytes.Length; i++)
                    msg[i - 16] = encryptedBytes[i];

                return Convert.ToBase64String(DecryptByte(msg, GetAesCryptoServiceProvider(key, iv, true)));
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("Exception! Variable key or plainText. " + e.Message);
                return null;
            }
            catch (FormatException e)
            {
                Console.WriteLine("Exception! Variable encryptedText. " + e.Message);
                return null;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Exception! Variable key. " + e.Message);
                return null;
            }
        }

        private static byte[] CreateRandomIv()
        {
            byte[] iv = new byte[16];
            new Random().NextBytes(iv);

            return iv;
        }
    }
}

