using NUnit.Framework;
using System;

namespace Cryptography.Tests
{
    public class EncryptStringPaddingTests
    {
        [Test]
        public void EncryptStringPadding_PlaintText_EncryptTextEqualPlaintText()
        {
            // Arrange:
            string secretKey = "1234123412341234";

            string plainText1 = "1234abcd5678FGHI1234abcd5678FGHI";
            string plainText2 = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";


            // Act:
            string encryptText1 = Cryptography.EncryptStringPadding(plainText1, secretKey);
            string decryptText1 = Cryptography.DecryptStringPadding(encryptText1, secretKey);

            string encryptText2 = Cryptography.EncryptStringPadding(plainText2, secretKey);
            string decryptText2 = Cryptography.DecryptStringPadding(encryptText2, secretKey);

            // Assert:
            Assert.AreEqual(decryptText1, plainText1);
            Assert.AreEqual(decryptText2, plainText2);
        }

        [Test]
        public void EncryptStringPadding_SecretKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "123412341234123";
            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }
        [Test]
        public void EncryptStringPadding_SecretKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = null;
            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }
        [Test]
        public void EncryptStringPadding_SecretKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = "123412341234123400";
            string plainText = "1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI";

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptStringPadding_PlainTextIncorrectWithBase64_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";
            string plainText = "8AńZłŻ3QńJ1a9 ŃŁ#Xó1ŚŻRśZ 8 ŻP Ą2źT05TU  WL  ddąZeŻ żńóJ feń c żu%pb7%Z Y3!(899XkDÓIŻAÓńĄDRą 9U9TĄ ł";

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptStringPadding_PlainTextIsNull_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";
            string plainText = null;

            // Act:
            string encryptText = Cryptography.EncryptStringPadding(plainText, secretKey);
            string decryptText = Cryptography.DecryptStringPadding(encryptText, secretKey);

            // Assert:
            Assert.Null(decryptText);
        }

        [Test]
        public void EncryptStringPadding_PlainTextIsNullAndKeyIsNull_Null()
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
        public void EncryptStringPadding_PlainTextIsNullAndKeyIsToShort_Null()
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
        public void EncryptStringPadding_PlainTextIsNullAndKeyIsToLong_Null()
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
        public void EncryptStringPadding_PlainTextIncorrectWithBase64AndKeyIsNull_Null()
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
        public void EncryptStringPadding_PlainTextIncorrectWithBase64AndKeyIsToShort_Null()
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
        public void EncryptStringPadding_PlainTextIncorrectWithBase64AndKeyIsToLong_Null()
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