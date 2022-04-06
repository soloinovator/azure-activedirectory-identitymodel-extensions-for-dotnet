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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
#if NET472
    /// <summary>
    /// Provides a Security Key that can be used as Content Encryption Key (CEK) for use with a JWE
    /// </summary>
    public class EcdhKeyExchangeProvider //todo: rename to KeyExchangeProvider, or EcKeyExchangeProvider?
    {
        /// <summary>
        /// Number of bits in the desired output key
        /// </summary>
        public int KeyDataLen { get; set; }

        private ECDiffieHellman _ecdhPublic;
        private ECDiffieHellman _ecdhPrivate;
        private ECParameters _ecParamsPublic;
        private ECParameters _ecParamsPrivate;
        private string _algorithmId;

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the private key.</param>
        /// <param name="publicKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the public key.</param>
        /// <param name="alg">alg header parameter value.</param>
        /// <param name="enc">enc header parameter value.</param>
        /// </summary>
        public EcdhKeyExchangeProvider(ECDsaSecurityKey privateKey, ECDsaSecurityKey publicKey, string alg, string enc)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            SetKeyDataLenAndEncryptionAlgorithm(alg, enc);
            _ecParamsPrivate = privateKey.ECDsa.ExportParameters(true);
            _ecParamsPublic = publicKey.ECDsa.ExportParameters(false);

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(privateKey), $"{nameof(privateKey)}'s curve does not match with {nameof(publicKey)}'s curve.");
            }

            Initialize();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the private key.</param>
        /// <param name="publicKey">The <see cref="JsonWebKey"/> that will be used for cryptographic operations and represents the public key.</param>
        /// <param name="alg">alg header parameter value.</param>
        /// <param name="enc">enc header parameter value.</param>
        /// </summary>
        public EcdhKeyExchangeProvider(ECDsaSecurityKey privateKey, JsonWebKey publicKey, string alg, string enc)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            SetKeyDataLenAndEncryptionAlgorithm(alg, enc);
            _ecParamsPrivate = privateKey.ECDsa.ExportParameters(true);
            _ecParamsPublic = GetEcParamsFromJwk(publicKey);

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(privateKey), $"{nameof(privateKey)}'s curve does not match with {nameof(publicKey)}'s curve.");
            }

            Initialize();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey">The <see cref="JsonWebKey"/> that will be used for cryptographic operations and represents the private key.</param>
        /// <param name="publicKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the public key.</param>
        /// <param name="alg">alg header parameter value.</param>
        /// <param name="enc">enc header parameter value.</param>
        /// </summary>
        public EcdhKeyExchangeProvider(JsonWebKey privateKey, ECDsaSecurityKey publicKey, string alg, string enc)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            SetKeyDataLenAndEncryptionAlgorithm(alg, enc);
            _ecParamsPrivate = GetEcParamsFromJwk(privateKey);
            _ecParamsPublic = publicKey.ECDsa.ExportParameters(false);

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(privateKey), $"{nameof(privateKey)}'s curve does not match with {nameof(publicKey)}'s curve.");
            }

            Initialize();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey">The <see cref="JsonWebKey"/> that will be used for cryptographic operations and represents the private key.</param>
        /// <param name="publicKey">The <see cref="JsonWebKey"/> that will be used for cryptographic operations and represents the public key.</param>
        /// <param name="alg">alg header parameter value.</param>
        /// <param name="enc">enc header parameter value.</param>
        /// </summary>
        public EcdhKeyExchangeProvider(JsonWebKey privateKey, JsonWebKey publicKey, string alg, string enc)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));
            
            ValidateAlgAndEnc(alg, enc);

            SetKeyDataLenAndEncryptionAlgorithm(alg, enc);
            _ecParamsPrivate = GetEcParamsFromJwk(privateKey);
            _ecParamsPublic = GetEcParamsFromJwk(publicKey);

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(privateKey), $"{nameof(privateKey)}'s curve does not match with {nameof(publicKey)}'s curve.");
            }

            Initialize();
        }

        /// <summary>
        /// Generates the KDF
        /// </summary>
        /// <param name="apu">Agreement PartyUInfo (optional). When used, the PartyVInfo value contains information about the producer,
        /// represented as a base64url-encoded string.</param>
        /// <param name="apv">Agreement PartyVInfo (optional). When used, the PartyUInfo value contains information about the recipient,
        /// represented as a base64url-encoded string.</param>
        /// <returns></returns>
        public SecurityKey GenerateKdf(string apu = null, string apv = null)
        {
            //The "apu" and "apv" values MUST be distinct when used (per rfc7518 section 4.6.2) https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2
            if (!string.IsNullOrEmpty(apu)
                && !string.IsNullOrEmpty(apv)
                && apu.Equals(apv, StringComparison.InvariantCulture))
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(apu), $"{nameof(apu)} must be different from {nameof(apv)}.");

            int cekLength = KeyDataLen / 8; // number of octets
            byte[] prepend = new byte[4] { 0, 0, 0, 1 };
            // n is the ceiling of keydatalen / hashlen, see section 5.8.1.1: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
            // hashlen is always 256 for ecdh-es, see: https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2
            //prepend = BitConverter.GetBytes(n); 
            //if (BitConverter.IsLittleEndian)
            //    Array.Reverse(prepend);

            SetAppendBytes(apu, apv, out byte[] append);
            byte[] cek = new byte[cekLength];

            // JWA's spec https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2 specifies SHA256, saml might be different
            byte[] derivedKey = _ecdhPrivate.DeriveKeyFromHash(_ecdhPublic.PublicKey, HashAlgorithmName.SHA256, prepend, append);
            Array.Copy(derivedKey, cek, cekLength);

            return new SymmetricSecurityKey(cek);
        }

        private void SetAppendBytes(string apu, string apv, out byte[] append)
        {
            byte[] encBytes = Encoding.ASCII.GetBytes(_algorithmId); //should it be using Base64UrlEncoder?
            byte[] apuBytes = Base64UrlEncoder.DecodeBytes(string.IsNullOrEmpty(apu) ? string.Empty : apu);
            byte[] apvBytes = Base64UrlEncoder.DecodeBytes(string.IsNullOrEmpty(apv) ? string.Empty : apv);
            byte[] numOctetsEnc = BitConverter.GetBytes(encBytes.Length);
            byte[] numOctetsApu = BitConverter.GetBytes(apuBytes.Length);
            byte[] numOctetsApv = BitConverter.GetBytes(apvBytes.Length);
            byte[] keyDataLengthBytes = BitConverter.GetBytes(KeyDataLen);

            if (BitConverter.IsLittleEndian)
            {
                // these representations need to be big-endian
                Array.Reverse(numOctetsEnc);
                Array.Reverse(numOctetsApu);
                Array.Reverse(numOctetsApv);
                Array.Reverse(keyDataLengthBytes);
            }

            append = Concat(numOctetsEnc, encBytes, numOctetsApu, apuBytes, numOctetsApv, apvBytes, keyDataLengthBytes);
        }

        private void SetKeyDataLenAndEncryptionAlgorithm(string alg, string enc = null)
        {
            if (SecurityAlgorithms.EcdhEs.Equals(alg, StringComparison.InvariantCulture)) // dir or ECDH-ES
            {
                _algorithmId = enc;
                if (SecurityAlgorithms.Aes128Gcm.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 128;
                else if (SecurityAlgorithms.Aes192Gcm.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 192;
                else if (SecurityAlgorithms.Aes256Gcm.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 256;
                else if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 128;
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 192;
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(enc, StringComparison.InvariantCulture))
                    KeyDataLen = 256;
            }
            else
            {
                _algorithmId = alg;

                if (SecurityAlgorithms.EcdhEsA128kw.Equals(alg, StringComparison.InvariantCulture))
                    KeyDataLen = 128;
                else if (SecurityAlgorithms.EcdhEsA192kw.Equals(alg, StringComparison.InvariantCulture))
                    KeyDataLen = 192;
                else if (SecurityAlgorithms.EcdhEsA256kw.Equals(alg, StringComparison.InvariantCulture))
                    KeyDataLen = 256;
            }
        }

        private static void ValidateAlgAndEnc(string alg, string enc)
        {
            if (string.IsNullOrEmpty(alg))
                throw LogHelper.LogArgumentNullException(alg);
            if (string.IsNullOrEmpty(enc))
                throw LogHelper.LogArgumentNullException(enc);

            if (!SupportedAlgorithms.EcdsaWrapAlgorithms.Contains(alg) && !SecurityAlgorithms.EcdhEs.Equals(alg, StringComparison.InvariantCulture))
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(alg), $"{nameof(alg)} is not supported.");

            if (!SupportedAlgorithms.SymmetricEncryptionAlgorithms.Contains(enc))
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(enc), $"{nameof(enc)} is not supported.");
        }

        private void Initialize()
        {
            _ecdhPublic = ECDiffieHellman.Create(_ecParamsPublic);
            _ecdhPrivate = ECDiffieHellman.Create(_ecParamsPrivate);
        }

        private static byte[] Concat(params byte[][] arrays)
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

        internal static ECParameters GetEcParamsFromJwk(JsonWebKey publicKey)
        {
            ECCurve curve = Utility.GetEllipticCurve(publicKey.Crv);
            return new ECParameters()
            {
                Curve = curve,
                Q = new ECPoint()
                {
                    X = Base64UrlEncoder.DecodeBytes(publicKey.X),
                    Y = Base64UrlEncoder.DecodeBytes(publicKey.Y)
                }
            };
        }

        internal string GetEncryptionAlgorithm()
        {
            if (_algorithmId.Equals(SecurityAlgorithms.EcdhEsA128kw, StringComparison.Ordinal))
                return SecurityAlgorithms.Aes128KeyWrap;
            if (_algorithmId.Equals(SecurityAlgorithms.EcdhEsA192kw, StringComparison.Ordinal))
                return SecurityAlgorithms.Aes192KeyWrap;
            if (_algorithmId.Equals(SecurityAlgorithms.EcdhEsA256kw, StringComparison.Ordinal))
                return SecurityAlgorithms.Aes256KeyWrap;
            return _algorithmId;
        }
    }
#endif
}
