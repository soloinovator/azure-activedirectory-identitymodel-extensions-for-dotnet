//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for references in specs
    /// https://datatracker.ietf.org/doc/html/rfc7518#appendix-A.3
    /// </summary>
    public class ReferenceTests
    {
#if NET_CORE
        [PlatformSpecific(TestPlatforms.Windows)]
#endif
#if NET472 || NETSTANDARD2_0
        class Alice
        {
            //public static byte[] alicePublicKey;
            public ECDiffieHellmanPublicKey aliceEcdhPublicKey;
            public ECParameters ecParametersAlice;
            public ECParameters ecParametersBob;
            public byte[] DerivedKey { get; private set; }

            public Bob Bob { get; private set; }

            public Alice(ECParameters ecpAlice, ECParameters ecpBob)
            {
                ecParametersAlice = ecpAlice;
                ecParametersBob = ecpBob;
                DerivedKey = new byte[16];
            }

            public void Run(string secretMessage, string enc, string apu, string apv, int keyDataLen)
            {
                try
                {
                    using (ECDiffieHellman ecdhAlice = ECDiffieHellman.Create(ecParametersAlice))
                    {
                        aliceEcdhPublicKey = ecdhAlice.PublicKey;
                        byte[] prepend, append;
                        prepend = new byte[] { 0, 0, 0, 1 };
                        SetAppendBytes(enc, apu, apv, keyDataLen, out append);

                        Bob = new Bob(ecParametersBob, ecdhAlice.PublicKey, prepend, append);
                        ECDiffieHellmanPublicKey bobPublicKey = Bob.bobEcdhPublicKey;
                        
                        /* Q: should the key being used only be the first 16 octets/128 bits? from rfc7518 Appendix C:
                         * The resulting derived key, which is the first 128 bits of the round 1
                           hash output is:
                           [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16,
                           26]

                        The base64url-encoded representation of this derived key is:
                            VqqN6vgjbSBcIijNcacQGg
                        */
                        byte[] aliceKey = ecdhAlice.DeriveKeyFromHash(bobPublicKey, HashAlgorithmName.SHA256, prepend, append);
                        Array.Copy(aliceKey, 0, DerivedKey, 0, 16);
                        byte[] encryptedMessage = null;
                        byte[] iv = null;
                        Send(DerivedKey, secretMessage, out encryptedMessage, out iv);
                        Bob.Receive(encryptedMessage, iv);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }

            private void SetAppendBytes(string enc, string apu, string apv, int keyDataLen, out byte[] append)
            {
                byte[] encBytes = Encoding.ASCII.GetBytes(enc); //should it be base64url?
                byte[] apuBytes = Base64UrlEncoder.DecodeBytes(apu);
                byte[] apvBytes = Base64UrlEncoder.DecodeBytes(apv);
                byte[] numOctetsEnc = BitConverter.GetBytes(encBytes.Length);
                byte[] numOctetsApu = BitConverter.GetBytes(apuBytes.Length);
                byte[] numOctetsApv = BitConverter.GetBytes(apvBytes.Length);
                byte[] keyDataLengthBytes = BitConverter.GetBytes(keyDataLen);

                if (BitConverter.IsLittleEndian)
                {
                    // these representations need to be big-endian
                    Array.Reverse(numOctetsEnc);
                    Array.Reverse(numOctetsApu);
                    Array.Reverse(numOctetsApv);
                    Array.Reverse(keyDataLengthBytes);
                }

                //byte[] algorithmIdBytes = Concat(numOctetsEnc, encBytes);
                //byte[] partyUInfoBytes = Concat(numOctetsApu, apuBytes);
                //byte[] partyVInfoBytes = Concat(numOctetsApv, apvBytes);
                //byte[] suppPubInfoBytes = keyDataLengthBytes;
                //byte[] append = Concat(algorithmIdBytes, partyUInfoBytes, partyVInfoBytes, suppPubInfoBytes);

                append = Concat(numOctetsEnc, encBytes, numOctetsApu, apuBytes, numOctetsApv, apvBytes, keyDataLengthBytes);
                //append = { 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128};
            }

            private byte[] Concat(params byte[][] arrays)
            {
                int length = 0;
                foreach (byte[] arr in arrays)
                    length += arr.Length;

                byte[] output = new byte[length];
                int x = 0;
                foreach (byte[] arr in arrays)
                    for (int j = 0; j < arr.Length; j++, x++)
                        output[x] = arr[j];

                return output;
            }

            private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
            {
                encryptedMessage = new byte[0];
                iv = new byte[0];
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    iv = aes.IV;

                    // Encrypt the message
                    using (MemoryStream ciphertext = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
        }

        public class Bob
        {
            //public byte[] bobPublicKey;
            public ECDiffieHellmanPublicKey bobEcdhPublicKey;
            private byte[] bobKey;
            public byte[] DerivedKey { get; private set; }
            public string MessageReceived { get; private set; }

            public Bob(ECParameters ecpBob, ECDiffieHellmanPublicKey publicKeyOtherParty, byte[] prepend, byte[] append)
            {
                try
                {
                    using (ECDiffieHellman ecdhBob = ECDiffieHellman.Create(ecpBob))
                    {
                        bobEcdhPublicKey = ecdhBob.PublicKey;
                        bobKey = ecdhBob.DeriveKeyFromHash(publicKeyOtherParty, HashAlgorithmName.SHA256, prepend, append);
                        DerivedKey = new byte[16];
                        Array.Copy(bobKey, 0, DerivedKey, 0, 16);
                    }
                }
                catch(Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }

            public void Receive(byte[] encryptedMessage, byte[] iv)
            {

                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = DerivedKey;
                    aes.IV = iv;
                    // Decrypt the message
                    using (MemoryStream plaintext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                            cs.Close();
                            MessageReceived = Encoding.UTF8.GetString(plaintext.ToArray());
                            Console.WriteLine(MessageReceived);
                        }
                    }
                }
            }
        }
#endif
        [Fact]
        public void Walkthrough()
        {
            var context = new CompareContext();
#if NET472 || NETSTANDARD2_0
            // arrange
            byte[] d1 = Base64UrlEncoder.DecodeBytes(ECDH_ES.AliceEphereralPrivateKey.D);
            byte[] x1 = Base64UrlEncoder.DecodeBytes(ECDH_ES.AliceEphereralPrivateKey.X);
            byte[] y1 = Base64UrlEncoder.DecodeBytes(ECDH_ES.AliceEphereralPrivateKey.Y);
            ECParameters ecpAlice = new ECParameters()
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d1,
                Q = new ECPoint()
                {
                    X = x1,
                    Y = y1
                }
            };

            byte[] d2 = Base64UrlEncoder.DecodeBytes(ECDH_ES.BobEphereralPrivateKey.D);
            byte[] x2 = Base64UrlEncoder.DecodeBytes(ECDH_ES.BobEphereralPrivateKey.X);
            byte[] y2 = Base64UrlEncoder.DecodeBytes(ECDH_ES.BobEphereralPrivateKey.Y);
            ECParameters ecpBob = new ECParameters()
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d2,
                Q = new ECPoint()
                {
                    X = x2,
                    Y = y2
                }
            };

            Alice alice = new Alice(ecpAlice, ecpBob);
            string secretMessage = "Secret message";

            // act
            // the values ecp, apu, apv, and keyDataLen should come from EPKString
            alice.Run(
                secretMessage,
                "A128GCM", //enc
                "QWxpY2U", //apu
                "Qm9i", //apv
                128); //keydatalen

            // assert
            // compare derived keys are the same and they're matching with expected
            if (!Utility.AreEqual(alice.DerivedKey, alice.Bob.DerivedKey)) // todo: nice to have, add utility to compare all three together
                context.AddDiff($"!Utility.AreEqual(alice.DerivedKey, alice.Bob.DerivedKey)");
            if (!Utility.AreEqual(alice.DerivedKey, ECDH_ES.DerivedKeyBytes))
                context.AddDiff($"!Utility.AreEqual(alice.DerivedKey, DerivedKeyBytes)");

            // compare string representation of derived key, second guessing if this is needed
            string stringRepresentation = Base64UrlEncoder.Encode(alice.DerivedKey, 0, 16);
            if (!String.Equals(stringRepresentation, ECDH_ES.DerivedKeyEncoded, StringComparison.InvariantCulture))
                context.AddDiff($"!String.Equals(derivedKeyFromBob, DerivedKeyBytes)");

            // compare sent and received messages are the same
            if (!String.Equals(secretMessage, alice.Bob.MessageReceived, StringComparison.InvariantCulture))
                context.AddDiff($"!String.Equals(secretMessage, alice.Bob.MessageReceived)");
#endif
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void AesGcmReferenceTest()
        {
            var context = new CompareContext();
            var providerForDecryption = CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(new SymmetricSecurityKey(RSAES_OAEP_KeyWrap.CEK), AES_256_GCM.Algorithm);
            var plaintext = providerForDecryption.Decrypt(AES_256_GCM.E, AES_256_GCM.A, AES_256_GCM.IV, AES_256_GCM.T);

            if (!Utility.AreEqual(plaintext, AES_256_GCM.P))
                context.AddDiff($"!Utility.AreEqual(plaintext, testParams.Plaintext)");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(AuthenticatedEncryptionTheoryData))]
        public void AuthenticatedEncryptionReferenceTest(AuthenticationEncryptionTestParams testParams)
        {
            var context = new CompareContext();
            var providerForEncryption = CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(testParams.EncryptionKey, testParams.Algorithm);
            var providerForDecryption = CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(testParams.DecryptionKey, testParams.Algorithm);
            var plaintext = providerForDecryption.Decrypt(testParams.Ciphertext, testParams.AuthenticationData, testParams.IV, testParams.AuthenticationTag);
            var encryptionResult = providerForEncryption.Encrypt(testParams.Plaintext, testParams.AuthenticationData, testParams.IV);

            if (!Utility.AreEqual(encryptionResult.IV, testParams.IV))
                context.AddDiff($"!Utility.AreEqual(encryptionResult.IV, testParams.IV)");

            if (!Utility.AreEqual(encryptionResult.AuthenticationTag, testParams.AuthenticationTag))
                context.AddDiff($"!Utility.AreEqual(encryptionResult.AuthenticationTag, testParams.AuthenticationTag)");

            if (!Utility.AreEqual(encryptionResult.Ciphertext, testParams.Ciphertext))
                context.AddDiff($"!Utility.AreEqual(encryptionResult.Ciphertext, testParams.Ciphertext)");

            if (!Utility.AreEqual(plaintext, testParams.Plaintext))
                context.AddDiff($"!Utility.AreEqual(plaintext, testParams.Plaintext)");

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AuthenticationEncryptionTestParams> AuthenticatedEncryptionTheoryData
        {
            get
            {
                var theoryData = new TheoryData<AuthenticationEncryptionTestParams>();

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_128_CBC_HMAC_SHA_256.Algorithm,
                    AuthenticationData = AES_128_CBC_HMAC_SHA_256.A,
                    AuthenticationTag = AES_128_CBC_HMAC_SHA_256.T,
                    Ciphertext = AES_128_CBC_HMAC_SHA_256.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_128_CBC_HMAC_SHA_256.K) { KeyId = "DecryptionKey.AES_128_CBC_HMAC_SHA_256.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_128_CBC_HMAC_SHA_256.K) { KeyId = "EncryptionKey.AES_128_CBC_HMAC_SHA_256.K" },
                    IV = AES_128_CBC_HMAC_SHA_256.IV,
                    Plaintext = AES_128_CBC_HMAC_SHA_256.P,
                    TestId = "AES_128_CBC_HMAC_SHA_256"
                });

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_192_CBC_HMAC_SHA_384.Algorithm,
                    AuthenticationData = AES_192_CBC_HMAC_SHA_384.A,
                    AuthenticationTag = AES_192_CBC_HMAC_SHA_384.T,
                    Ciphertext = AES_192_CBC_HMAC_SHA_384.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_192_CBC_HMAC_SHA_384.K) { KeyId = "DecryptionKey.AES_192_CBC_HMAC_SHA_384.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_192_CBC_HMAC_SHA_384.K) { KeyId = "EncryptionKey.AES_192_CBC_HMAC_SHA_384.K" },
                    IV = AES_192_CBC_HMAC_SHA_384.IV,
                    Plaintext = AES_192_CBC_HMAC_SHA_384.P,
                    TestId = "AES_192_CBC_HMAC_SHA_384"
                });

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_256_CBC_HMAC_SHA_512.Algorithm,
                    AuthenticationData = AES_256_CBC_HMAC_SHA_512.A,
                    AuthenticationTag = AES_256_CBC_HMAC_SHA_512.T,
                    Ciphertext = AES_256_CBC_HMAC_SHA_512.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_256_CBC_HMAC_SHA_512.K) { KeyId = "DecryptionKey.AES_256_CBC_HMAC_SHA_512.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_256_CBC_HMAC_SHA_512.K) { KeyId = "EncryptionKey.AES_256_CBC_HMAC_SHA_512.K" },
                    IV = AES_256_CBC_HMAC_SHA_512.IV,
                    Plaintext = AES_256_CBC_HMAC_SHA_512.P,
                    TestId = "AES_256_CBC_HMAC_SHA_512"
                });

                return theoryData;
            }
        }

        public class AuthenticationEncryptionTestParams
        {
            public string Algorithm { get; set; }
            public byte[] AuthenticationData { get; set; }
            public byte[] AuthenticationTag { get; set; }
            public byte[] Ciphertext { get; set; }
            public SecurityKey DecryptionKey { get; set; }
            public SecurityKey EncryptionKey { get; set; }
            public byte[] IV { get; set; }
            public byte[] Plaintext { get; set; }
            public string TestId { get; set; }

            public override string ToString()
            {
                return TestId + ", " + Algorithm + ", " + EncryptionKey.KeyId + ", " + DecryptionKey.KeyId;
            }
        }

        [Fact]
        public void ECDH_ESReferenceTest()
        {
            // Use the data in: public static class ECDH_ES
            // To generate all the parts of required for creating the derived key and compare against reference.

            // 1. Create Derived key using Alice's public key and Bob's Private key
            // 2. Create Derived key using Bob's public key and Alice's Private key

            // Generate Z, then compare
            // Generate ConcatKDF, then compare
        }

        [Theory, MemberData(nameof(KeyWrapTheoryData))]
        public void KeyWrapReferenceTest(KeyWrapTestParams testParams)
        {
            if (testParams.Algorithm.Equals(SecurityAlgorithms.Aes128KW, StringComparison.OrdinalIgnoreCase)
                || testParams.Algorithm.Equals(SecurityAlgorithms.Aes256KW, StringComparison.OrdinalIgnoreCase))
            {
                var keyWrapProvider = CryptoProviderFactory.Default.CreateKeyWrapProvider(testParams.Key, testParams.Algorithm);
                var wrappedKey = keyWrapProvider.WrapKey(testParams.KeyToWrap);
                Assert.True(Utility.AreEqual(wrappedKey, testParams.EncryptedKey), "Utility.AreEqual(wrappedKey, testParams.EncryptedKey)");
                Assert.Equal(Base64UrlEncoder.Encode(wrappedKey), testParams.EncodedEncryptedKey);

                byte[] unwrappedKey = keyWrapProvider.UnwrapKey(wrappedKey);
                Assert.True(Utility.AreEqual(unwrappedKey, testParams.KeyToWrap), "Utility.AreEqual(unwrappedKey, testParams.KeyToWrap)");
            }
            else if (testParams.Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.OrdinalIgnoreCase)
                    || testParams.Algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.OrdinalIgnoreCase))
            {
                var rsaKeyWrapProvider = CryptoProviderFactory.Default.CreateKeyWrapProvider(testParams.Key, testParams.Algorithm);
                byte[] unwrappedKey = rsaKeyWrapProvider.UnwrapKey(testParams.EncryptedKey);
                Assert.True(Utility.AreEqual(unwrappedKey, testParams.KeyToWrap), "Utility.AreEqual(unwrappedKey, testParams.KeyToWrap)");
            }
        }

        public static TheoryData<KeyWrapTestParams> KeyWrapTheoryData
        {
            get
            {
                var theoryData = new TheoryData<KeyWrapTestParams>();

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = AES128_KeyWrap.Algorithm,
                    Key = new SymmetricSecurityKey(Base64UrlEncoder.DecodeBytes(AES128_KeyWrap.K)),
                    KeyToWrap = AES128_KeyWrap.CEK,
                    EncryptedKey = AES128_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = AES128_KeyWrap.EncodedEncryptedKey,
                    TestId = "AES128_KeyWrap"
                });

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = RSAES_OAEP_KeyWrap.Algorithm,
                    Key = RSAES_OAEP_KeyWrap.Key,
                    KeyToWrap = RSAES_OAEP_KeyWrap.CEK,
                    EncryptedKey = RSAES_OAEP_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = RSAES_OAEP_KeyWrap.EncodedEncryptedKey,
                    TestId = "RSA_OAEP_KeyWrap"
                });

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = RSAES_PKCS1_KeyWrap.Algorithm,
                    Key = RSAES_PKCS1_KeyWrap.Key,
                    KeyToWrap = RSAES_PKCS1_KeyWrap.CEK,
                    EncryptedKey = RSAES_PKCS1_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = RSAES_PKCS1_KeyWrap.EncodedEncryptedKey,
                    TestId = "RSAES-PKCS1-v1_5"
                });

                return theoryData;
            }
        }

        public class KeyWrapTestParams
        {
            public string Algorithm { get; set; }
            public SecurityKey Key { get; set; }
            public byte[] KeyToWrap { get; set; }
            public byte[] EncryptedKey { get; set; }
            public string EncodedEncryptedKey { get; set; }
            public string TestId { get; set; }

            public override string ToString()
            {
                return TestId + ", " + Algorithm + ", " + Key.KeyId;
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
