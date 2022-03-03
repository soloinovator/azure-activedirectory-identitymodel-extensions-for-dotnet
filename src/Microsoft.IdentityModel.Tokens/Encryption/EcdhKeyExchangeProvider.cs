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

            _ecParams = new ECParameters()
            {
                Curve = GetEllipticCurve(jwk.Crv),
                D = Base64UrlEncoder.DecodeBytes(jwk.D), //should be optional
                Q = new ECPoint()
                {
                    X = Base64UrlEncoder.DecodeBytes(jwk.X),
                    Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
                }
            };

            _i = 1;
            _ecdh = new Lazy<ECDiffieHellman>(CreateECdiffieHellman);
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
        /// <param name="apu"></param>
        /// <param name="apv"></param>
        /// <param name="keyDataLen"></param>
        /// <returns></returns>
        public byte[] GenerateCek(ECDiffieHellmanPublicKey otherPartyPublicKey, string enc, string apu, string apv, int keyDataLen)
        {
            int cekLength = keyDataLen / 8;
            byte[] prepend = BitConverter.GetBytes(_i++);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(prepend);
            SetAppendBytes(enc, apu, apv, keyDataLen, out byte[] append);
            byte[] cek = new byte[cekLength];
            byte[] derivedKey = _ecdh.Value.DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, prepend, append);
            Array.Copy(derivedKey, cek, cekLength);
            return cek;
        }

        private static ECCurve GetEllipticCurve(string crv)
        {
            if (JsonWebKeyECTypes.P256.Equals(crv, StringComparison.InvariantCulture))
                return ECCurve.NamedCurves.nistP256;

            if (JsonWebKeyECTypes.P384.Equals(crv, StringComparison.InvariantCulture))
                return ECCurve.NamedCurves.nistP384;

            if (JsonWebKeyECTypes.P512.Equals(crv, StringComparison.InvariantCulture)
                || JsonWebKeyECTypes.P521.Equals(crv, StringComparison.InvariantCulture))
                return ECCurve.NamedCurves.nistP521;

            throw LogHelper.LogArgumentException<ArgumentException>(nameof(crv), "Curve was not found or is not NIST approved");
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
