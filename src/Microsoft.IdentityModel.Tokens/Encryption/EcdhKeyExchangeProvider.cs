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
    public class EcdhKeyExchangeProvider : IDisposable
    {
        /// <summary>
        /// Represents the public key that can be shared with the other party
        /// </summary>
        public ECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                return _ecdh.Value.PublicKey;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public int KeySize
        {
            get
            {
                return _ecParams.D.Length;
            }
        }

        /// <summary>
        /// String representing the curve name, ex: P-256, P-384, P-512
        /// </summary>
        public string Crv { get; private set; }

        private Lazy<ECDiffieHellman> _ecdh;
        private ECParameters _ecParams;
        private bool _disposed;
        private int _i;

        /// <summary>
        /// Initializes a new instance of <see cref="EcdhKeyExchangeProvider"/> used for CEKs
        /// <param name="jwk">The <see cref="JsonWebKey"/> that will be used for cryptographic operations.</param>
        /// </summary>
        public EcdhKeyExchangeProvider(JsonWebKey jwk)
        {
            if (jwk is null)
                throw new ArgumentNullException(nameof(jwk), "JsonWebKey jwk cannot be null");

            var curve = Utility.GetEllipticCurve(jwk.Crv);
            Crv = jwk.Crv;

            _ecParams = new ECParameters()
            {
                Curve = curve,
                D = Base64UrlEncoder.DecodeBytes(jwk.D), //todo: should be optional
                Q = new ECPoint()
                {
                    X = Base64UrlEncoder.DecodeBytes(jwk.X),
                    Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
                }
            };

            _ecdh = new Lazy<ECDiffieHellman>(CreateECdiffieHellman);
            _i = 1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="includePrivateParameters"></param>
        /// <returns></returns>
        public ECParameters ExportParameters(bool includePrivateParameters)
        {
            return _ecdh.Value.ExportParameters(includePrivateParameters);
        }

        private ECDiffieHellman CreateECdiffieHellman()
        {
            return ECDiffieHellman.Create(_ecParams);
        }

        /// <summary>
        /// Generates the Content Encryption Key
        /// </summary>
        /// <param name="otherPartyPublicKey"></param>
        /// <param name="enc"></param>
        /// <param name="apu">Agreement PartyUInfo (optional). When used, the PartyVInfo value contains information about the producer,
        /// represented as a base64url-encoded string.</param>
        /// <param name="apv">Agreement PartyVInfo (optional). When used, the PartyUInfo value contains information about the recipient,
        /// represented as a base64url-encoded string.</param>
        /// <param name="keyDataLen">The number of bits in the desired output key</param>
        /// <returns></returns>
        public byte[] GenerateCek(ECDiffieHellmanPublicKey otherPartyPublicKey, string enc, string apu, string apv, int keyDataLen)
        {
            //todo: change into returning a security key instead of bytes
            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

            //The "apu" and "apv" values MUST be distinct, when used (per rfc7518 section 4.6.2)
            int cekLength = keyDataLen / 8; // number of octets
            byte[] prepend = BitConverter.GetBytes(_i++);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(prepend);
            SetAppendBytes(enc, apu, apv, keyDataLen, out byte[] append);
            byte[] cek = new byte[cekLength];
            byte[] derivedKey = _ecdh.Value.DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, prepend, append);
            //_ecdh.Value.DeriveKeyFromHmac(otherPartyPublicKey, HashAlgorithmName.SHA256, salt, prepend, append);
            //SecurityKey sk;

            Array.Copy(derivedKey, cek, cekLength);
            return cek;
        }

        private static void SetAppendBytes(string enc, string apu, string apv, int keyDataLen, out byte[] append)
        {
            byte[] encBytes = Encoding.ASCII.GetBytes(enc); //should it be using base64urlEncoder?
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

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _ecdh.Value.Dispose();
                    _disposed = true;
                }

                _disposed = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~EcdhKeyExchangeProvider()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
#endif
}
