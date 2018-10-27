﻿using NUnit.Framework;
using System;

namespace Cryptography.Tests
{
    public class DecryptStringPaddingTests
    {
        [Test]
        public void DecryptStringPadding_EncryptTextFromJava_DecryptTextEqualPlaintText()
        {
            // Arrange:
            string secretKey = "1234123412341234";

            string encryptedText = "lho2lXzA7RL9FjR0Oo33htuTEKVvW/sRAucMUfBu74tLKbPmruDMXPtw55YNIvbdBfrVZPpOZriuBBSNxgyyA7B+/obwi2BDGqGoWJ1zJ86XJ9y3r54AbmvIfODl+LMmMlnMhZtYB/3VgX8o8BpTEoDyr2ooyrIvFnyOgN5Tl4s=";

            // Act:
            string result = Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.AreEqual("1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI", result);
        }

        [Test]
        public void DecryptStringPadding_SecretKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "12341234123";
            string encryptedText = "qgLOPmsh9sNOBx5dYkc8oxZol1xl8573Sbq+T4gAK9651rNuJ2W+CnWqGP0rLMh7H2ddDl3PHyq5p6pb13q9iaIjto5+dhgGhd2VeYj1p3zKw3wXZRNRC5QgcQzfd/dhqOoWjvvW+FP6Go6WGcExnQ==";

            // Act:
            string result = Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.AreNotEqual("1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI", result);
            Assert.Null(result);
        }
        [Test]
        public void DecryptStringPadding_SecretKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = "12341234123412341";
            string encryptedText = "qgLOPmsh9sNOBx5dYkc8oxZol1xl8573Sbq+T4gAK9651rNuJ2W+CnWqGP0rLMh7H2ddDl3PHyq5p6pb13q9iaIjto5+dhgGhd2VeYj1p3zKw3wXZRNRC5QgcQzfd/dhqOoWjvvW+FP6Go6WGcExnQ==";

            // Act:
            string result = Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.AreNotEqual("1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI", result);
            Assert.Null(result);
        }
        [Test]
        public void DecryptStringPadding_SecretKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = null;
            string encryptedText = "qgLOPmsh9sNOBx5dYkc8oxZol1xl8573Sbq+T4gAK9651rNuJ2W+CnWqGP0rLMh7H2ddDl3PHyq5p6pb13q9iaIjto5+dhgGhd2VeYj1p3zKw3wXZRNRC5QgcQzfd/dhqOoWjvvW+FP6Go6WGcExnQ==";

            // Act:
            string result = Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.AreNotEqual("1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI1234abcd5678FGHI", result);
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIncorrectWithBase64_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";
            string encryptedText = "8AńZłŻ3QńJ1a9 ŃŁ#Xó1ŚŻRśZ 8 ŻP Ą2źT05TU  WL  ddąZeŻ żńóJ feń c żu%pb7%Z Y3!(899XkDÓIŻAÓńĄDRą 9U9TĄ ł";

            // Act:
            string result =  Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIsNull_Null()
        {
            // Arrange:
            string secretKey = "1234123412341234";
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptStringPadding(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIsNullAndKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = null;
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIsNullAndKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "12341234123";
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextAndKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = "1234123412341";
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIncorrectWithBase64AndKeyIsNull_Null()
        {
            // Arrange:
            string secretKey = null;
            string encryptedText = "8AńZłŻ3QńJ1a9 ŃŁ#Xó1ŚŻRśZ 8 ŻP Ą2źT05TU  WL  ddąZeŻ żńóJ feń c żu%pb7%Z Y3!(899XkDÓIŻAÓńĄDRą 9U9TĄ ł";

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIncorrectWithBase64AndKeyIsToShort_Null()
        {
            // Arrange:
            string secretKey = "12341234123";
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }

        [Test]
        public void DecryptStringPadding_EncryptedTextIncorrectWithBase64AndKeyIsToLong_Null()
        {
            // Arrange:
            string secretKey = "1234123412341";
            string encryptedText = null;

            // Act:
            string result = Cryptography.DecryptString(encryptedText, secretKey);

            // Assert:
            Assert.Null(result);
        }
    }
}