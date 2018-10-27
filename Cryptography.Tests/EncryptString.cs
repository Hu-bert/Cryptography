using NUnit.Framework;
using System;

namespace Cryptography.Tests
{
    public class EncryptStringTests
    {
        [Test]
        public void EncryptString_PlaintText_EncryptTextEqualPlaintText()
        {
            // Arrange:
            string secretKey = "1234123412341234";
            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";


            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);
            // Assert:
            Assert.AreEqual(plainText, decryptText);
        }

        [Test]
        public void EncryptString_SecretKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "123412341234123";

            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }
        [Test]
        public void EncryptString_SecretKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = null;

            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }
        [Test]
        public void EncryptString_SecretKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = "123412341234123400";

            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIncorrectWithBase64_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";

            string plainText = "8AńZłŻ3QńJ1a9 ŃŁ#Xó1ŚŻRśZ 8 ŻP Ą2źT05TU  WL  ddąZeŻ żńóJ feń c żu%pb7%Z Y3!(899XkDÓIŻAÓńĄDRą 9U9TĄ ł";

            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIsNull_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";

            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptString(plainText, secretKey);
            string decryptText = Cryptography.DecryptString(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIsNullAndKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = null;
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIsNullAndKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "12341234123";
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIsNullAndKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = "1234123412341";
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIncorrectWithBase64AndKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = null;
            string plainText = "8AńZłŻ3QńJ1a9 ŃŁ#Xó1ŚŻRśZ 8 ŻP Ą2źT05TU  WL  ddąZeŻ żńóJ feń c żu%pb7%Z Y3!(899XkDÓIŻAÓńĄDRą 9U9TĄ ł";

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIncorrectWithBase64AndKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "12341234123";
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptString_PlainTextIncorrectWithBase64AndKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = "1234123412341";
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }
    }
}