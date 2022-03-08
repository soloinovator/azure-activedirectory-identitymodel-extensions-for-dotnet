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
        private ECDiffieHellman _ecdhPublic;
        private ECDiffieHellman _ecdhPrivate;
        private ECParameters _ecParamsPublic;
        private ECParameters _ecParamsPrivate;
        private string _algorithmId;
        private int _keyDataLen;
        private int _i;

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the private key.</param>
        /// <param name="publicKey">The <see cref="ECDsaSecurityKey"/> that will be used for cryptographic operations and represents the public key.</param>
        /// <param name="alg">alg header parameter value</param>
        /// <param name="enc">enc header parameter value (optional)</param>
        /// </summary>
        public EcdhKeyExchangeProvider(ECDsaSecurityKey privateKey, ECDsaSecurityKey publicKey, string alg, string enc = null)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            GetKeyDataLenAndEncryptionAlgorithm(alg, enc);
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
        /// <param name="alg">alg header parameter value</param>
        /// <param name="enc">enc header parameter value (optional)</param>
        /// </summary>
        public EcdhKeyExchangeProvider(ECDsaSecurityKey privateKey, JsonWebKey publicKey, string alg, string enc = null)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            GetKeyDataLenAndEncryptionAlgorithm(alg, enc);
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
        /// <param name="alg">alg header parameter value</param>
        /// <param name="enc">enc header parameter value (optional)</param>
        /// </summary>
        public EcdhKeyExchangeProvider(JsonWebKey privateKey, ECDsaSecurityKey publicKey, string alg, string enc = null)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));

            ValidateAlgAndEnc(alg, enc);

            GetKeyDataLenAndEncryptionAlgorithm(alg, enc);
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
        /// <param name="alg">alg header parameter value</param>
        /// <param name="enc">enc header parameter value (optional)</param>
        /// </summary>
        public EcdhKeyExchangeProvider(JsonWebKey privateKey, JsonWebKey publicKey, string alg, string enc = null)
        {
            if (privateKey == null)
                throw LogHelper.LogArgumentNullException(nameof(privateKey));
            if (publicKey is null)
                throw LogHelper.LogArgumentNullException(nameof(publicKey));
            
            ValidateAlgAndEnc(alg, enc);

            GetKeyDataLenAndEncryptionAlgorithm(alg, enc);
            _ecParamsPrivate = GetEcParamsFromJwk(privateKey);
            _ecParamsPublic = GetEcParamsFromJwk(publicKey);

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(privateKey), $"{nameof(privateKey)}'s curve does not match with {nameof(publicKey)}'s curve.");
            }

            Initialize();
        }

        /// <summary>
        /// Generates the Content Encryption Key
        /// </summary>
        /// <param name="apu">Agreement PartyUInfo (optional). When used, the PartyVInfo value contains information about the producer,
        /// represented as a base64url-encoded string.</param>
        /// <param name="apv">Agreement PartyVInfo (optional). When used, the PartyUInfo value contains information about the recipient,
        /// represented as a base64url-encoded string.</param>
        /// <returns></returns>
        public SecurityKey GenerateCek(string apu, string apv)
        {
            //todo: if values for apu or apv are not present: Datalen is set to 0 and Data is set to the empty octet sequence
            // what is an empty octet sequence? [0] or []?
            if (string.IsNullOrEmpty(apu))
                throw new ArgumentNullException(nameof(apu), "Cannot be null");
            if (string.IsNullOrEmpty(apv))
                throw new ArgumentNullException(nameof(apv), "Cannot be null");

            //The "apu" and "apv" values MUST be distinct when used (per rfc7518 section 4.6.2)
            if (apu.Equals(apv, StringComparison.InvariantCulture))
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(apu), $"{nameof(apu)} must be different from {nameof(apv)}.");

            int cekLength = _keyDataLen / 8; // number of octets
            byte[] prepend = BitConverter.GetBytes(_i++);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(prepend);
            SetAppendBytes(apu, apv, out byte[] append);
            byte[] cek = new byte[cekLength];
            byte[] derivedKey = _ecdhPrivate.DeriveKeyFromHash(_ecdhPublic.PublicKey, HashAlgorithmName.SHA256, prepend, append);
            
            //_ecdh.Value.DeriveKeyFromHmac(otherPartyPublicKey, HashAlgorithmName.SHA256, salt, prepend, append);
            /* 
             * should we include customization here:
             * 1. Use someting different than HashAlgorithmName.SHA256
             * 2. Use DeriveKeyFromHmac or DeriveKeyTls
             */
            Array.Copy(derivedKey, cek, cekLength);

            return new SymmetricSecurityKey(cek);
        }

        private void SetAppendBytes(string apu, string apv, out byte[] append)
        {
            //encBytes if dir it should be the enc header param value, if kw it is the alg header param value
            byte[] encBytes = Encoding.ASCII.GetBytes(_algorithmId); //should it be using Base64UrlEncoder?
            byte[] apuBytes = Base64UrlEncoder.DecodeBytes(apu);
            byte[] apvBytes = Base64UrlEncoder.DecodeBytes(apv);
            byte[] numOctetsEnc = BitConverter.GetBytes(encBytes.Length);
            byte[] numOctetsApu = BitConverter.GetBytes(apuBytes.Length);
            byte[] numOctetsApv = BitConverter.GetBytes(apvBytes.Length);
            byte[] keyDataLengthBytes = BitConverter.GetBytes(_keyDataLen);

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

        private void GetKeyDataLenAndEncryptionAlgorithm(string alg, string enc = null)
        {
            if (SecurityAlgorithms.EcdhEs.Equals(alg, StringComparison.InvariantCulture))
            {
                _algorithmId = enc;
                if (SecurityAlgorithms.Aes128Gcm.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 128;
                else if (SecurityAlgorithms.Aes192Gcm.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 192;
                else if (SecurityAlgorithms.Aes256Gcm.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 256;
                else if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 128;
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 192;
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(enc, StringComparison.InvariantCulture))
                    _keyDataLen = 256;
            }
            else
            {
                _algorithmId = alg;

                if (SecurityAlgorithms.EcdhEsA128kw.Equals(alg, StringComparison.InvariantCulture))
                    _keyDataLen = 128;
                else if (SecurityAlgorithms.EcdhEsA192kw.Equals(alg, StringComparison.InvariantCulture))
                    _keyDataLen = 192;
                else if (SecurityAlgorithms.EcdhEsA256kw.Equals(alg, StringComparison.InvariantCulture))
                    _keyDataLen = 256;
            }
        }

        private static void ValidateAlgAndEnc(string alg, string enc)
        {
            if (string.IsNullOrEmpty(alg))
                throw LogHelper.LogArgumentNullException(alg);
            if (!SupportedAlgorithms.EcdsaWrapAlgorithms.Contains(alg))
            {
                if (SecurityAlgorithms.EcdhEs.Equals(alg, StringComparison.InvariantCulture))
                {
                    if (string.IsNullOrEmpty(enc))
                        throw LogHelper.LogArgumentNullException(nameof(enc));
                    if (!SupportedAlgorithms.SymmetricEncryptionAlgorithms.Contains(enc))
                        throw LogHelper.LogArgumentException<ArgumentException>(nameof(enc), $"{nameof(enc)} is not supported.");
                }
                else
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(alg), $"{nameof(alg)} is not supported.");
            }
        }

        private void Initialize()
        {
            _ecdhPublic = ECDiffieHellman.Create(_ecParamsPublic);
            _ecdhPrivate = ECDiffieHellman.Create(_ecParamsPrivate);
            _i = 1;
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

        private static ECParameters GetEcParamsFromJwk(JsonWebKey publicKey)
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
    }
#endif
}
