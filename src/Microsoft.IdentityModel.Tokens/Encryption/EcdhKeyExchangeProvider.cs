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
    public class EcdhKeyExchangeProvider //todo: rename to KeyExchangeProvider
    {
        /// <summary>
        /// String representing the curve name, ex: P-256, P-384, P-512
        /// </summary>
        public string Crv { get; private set; }

        private ECDiffieHellman _ecdhPublic;
        private ECDiffieHellman _ecdhPrivate;
        private ECParameters _ecParamsPublic;
        private ECParameters _ecParamsPrivate;
        private string _alg;
        private int _keyDataLen;
        private int _i;

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="privateKey"></param>
        /// <param name="publicKey">The <see cref="JsonWebKey"/> that will be used for cryptographic operations.</param>
        /// <param name="alg"></param>
        /// </summary>
        public EcdhKeyExchangeProvider(ECDsaSecurityKey privateKey, JsonWebKey publicKey, string alg)
        {
            if (string.IsNullOrEmpty(alg))
                throw new ArgumentNullException(nameof(alg), "cannot be null");
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey), "cannot be null");
            if (publicKey is null)
                throw new ArgumentNullException(nameof(publicKey), "JsonWebKey jwk cannot be null");
            if (!SupportedAlgorithms.EcdsaWrapAlgorithms.Contains(alg))
                throw new ArgumentException("Invalid alg", nameof(alg));

            if (SecurityAlgorithms.EcdhEsA128kw.Equals(alg, StringComparison.InvariantCultureIgnoreCase))
            {
                _keyDataLen = 128;
                _alg = "A128KW";
            }
            else if (SecurityAlgorithms.EcdhEsA192kw.Equals(alg, StringComparison.InvariantCultureIgnoreCase))
            {
                _keyDataLen = 192;
                _alg = "A192KW";
            }
            else if (SecurityAlgorithms.EcdhEsA256kw.Equals(alg, StringComparison.InvariantCultureIgnoreCase))
            {
                _keyDataLen = 256;
                _alg = "A256KW";
            }


            _ecParamsPrivate = privateKey.ECDsa.ExportParameters(true);

            ECCurve curve = Utility.GetEllipticCurve(publicKey.Crv);
            Crv = publicKey.Crv;

            _ecParamsPublic = new ECParameters()
            {
                Curve = curve,
                Q = new ECPoint()
                {
                    X = Base64UrlEncoder.DecodeBytes(publicKey.X),
                    Y = Base64UrlEncoder.DecodeBytes(publicKey.Y)
                }
            };

            if (_ecParamsPrivate.Curve.Equals(_ecParamsPublic.Curve))
            {
                throw new ArgumentException("curves should match");
            }

            _ecdhPublic = ECDiffieHellman.Create(_ecParamsPublic);
            _ecdhPrivate = ECDiffieHellman.Create(_ecParamsPrivate);
            _i = 1;
        }

        /// <summary>
        /// Generates the Content Encryption Key
        /// </summary>
        /// <param name="apu">Agreement PartyUInfo (optional). When used, the PartyVInfo value contains information about the producer,
        /// represented as a base64url-encoded string.</param>
        /// <param name="apv">Agreement PartyVInfo (optional). When used, the PartyUInfo value contains information about the recipient,
        /// represented as a base64url-encoded string.</param>
        /// <returns></returns>
        public byte[] GenerateCek(string apu, string apv) //todo: alg keydatalen will be properties
        {
            //todo: change into returning a security key instead of bytes
            //todo: default values for apu and apv?
            if (string.IsNullOrEmpty(apu))
                throw new ArgumentNullException(nameof(apu), "Cannot be null");
            if (string.IsNullOrEmpty(apv))
                throw new ArgumentNullException(nameof(apv), "Cannot be null");

            //The "apu" and "apv" values MUST be distinct, when used (per rfc7518 section 4.6.2)
            if (apu.Equals(apv, StringComparison.InvariantCulture))
                throw new ArgumentException("apu and apv need to be different");

            int cekLength = _keyDataLen / 8; // number of octets
            byte[] prepend = BitConverter.GetBytes(_i++);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(prepend);
            SetAppendBytes(apu, apv, out byte[] append);
            byte[] cek = new byte[cekLength];
            byte[] derivedKey = _ecdhPrivate.DeriveKeyFromHash(_ecdhPublic.PublicKey, HashAlgorithmName.SHA256, prepend, append);
            //_ecdh.Value.DeriveKeyFromHmac(otherPartyPublicKey, HashAlgorithmName.SHA256, salt, prepend, append);
            //SecurityKey sk;

            Array.Copy(derivedKey, cek, cekLength);
            return cek;
        }

        private void SetAppendBytes(string apu, string apv, out byte[] append)
        {
            byte[] encBytes = Encoding.ASCII.GetBytes(_alg); //should it be using base64urlEncoder?
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
    }
#endif
}
