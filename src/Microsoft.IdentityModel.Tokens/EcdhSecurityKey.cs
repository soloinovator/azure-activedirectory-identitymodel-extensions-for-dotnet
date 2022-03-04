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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
#if NET472
    /// <summary>
    /// Represents an Ecdh security key.
    /// </summary>
    public class EcdhSecurityKey : AsymmetricSecurityKey
    {
        /*
        public override bool HasPrivateKey => throw new NotImplementedException();

        public override PrivateKeyStatus PrivateKeyStatus => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();
        */
        private bool? _hasPrivateKey;

        private bool _foundPrivateKeyDetermined = false;

        private PrivateKeyStatus _foundPrivateKey;

        private const string _className = "Microsoft.IdentityModel.Tokens.EcdhSecurityKey";

        internal EcdhSecurityKey(JsonWebKey webKey)
            : base(webKey)
        {
            IntializeWithEcParameters(webKey.CreateEcParameters());
            webKey.ConvertedSecurityKey = this;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhSecurityKey"/> class.
        /// </summary>
        /// <param name="ecParameters"><see cref="ECParameters"/></param>
        public EcdhSecurityKey(ECParameters ecParameters)
        {
            IntializeWithEcParameters(ecParameters);
        }

        internal void IntializeWithEcParameters(ECParameters ecParameters)
        {
            // must have a valid Curve and D otherwise the crypto operations fail later
            try
            {
                ecParameters.Curve.Validate();
            }
            catch (CryptographicException ex)
            {
                throw LogHelper.LogException<CryptographicException>(ex.Message, LogHelper.MarkAsNonPII(_className), LogHelper.MarkAsNonPII("Curve"));
            }

            if (ecParameters.D == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10700, LogHelper.MarkAsNonPII(_className), LogHelper.MarkAsNonPII("D"))));

            _hasPrivateKey = true; // ecParameters.D != null, it would throw if not found above
            _foundPrivateKey = PrivateKeyStatus.Exists; //hasPrivateKey.Value ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
            _foundPrivateKeyDetermined = true;
            Parameters = ecParameters;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhSecurityKey"/> class.
        /// </summary>
        /// <param name="ecdh"><see cref="EcdhKeyExchangeProvider"/></param>
        public EcdhSecurityKey(EcdhKeyExchangeProvider ecdh)
        {
            Ecdh = ecdh ?? throw LogHelper.LogArgumentNullException(nameof(ecdh));
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [System.Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
        public override bool HasPrivateKey
        {
            get
            {
                if (_hasPrivateKey == null)
                {
                    try
                    {
                        Parameters.Curve.Validate();
                        if (Parameters.D == null)
                            _hasPrivateKey = false;
                        else
                            _hasPrivateKey = true;
                    }
                    catch (CryptographicException)
                    {
                        _hasPrivateKey = false;
                    }
                }
                return _hasPrivateKey.Value;
            }
        }

        /// <summary>
        /// Gets an enum indicating if a private key exists.
        /// </summary>
        /// <return>'Exists' if private key exists for sure; 'DoesNotExist' if private key doesn't exist for sure; 'Unknown' if we cannot determine.</return>
        public override PrivateKeyStatus PrivateKeyStatus
        {
            get
            {
                if (_foundPrivateKeyDetermined)
                    return _foundPrivateKey;

                _foundPrivateKeyDetermined = true;
                if (Ecdh != null)
                {
                    try
                    {
                        ECParameters parameters = Ecdh.ExportParameters(true);
                        parameters.Validate();
                        if (parameters.D != null)
                            _foundPrivateKey = PrivateKeyStatus.Exists;
                        else
                            _foundPrivateKey = PrivateKeyStatus.DoesNotExist;

                    }
                    catch (Exception)
                    {
                        _foundPrivateKey = PrivateKeyStatus.Unknown;
                        return _foundPrivateKey;
                    }
                }
                else
                {
                    if (Parameters.D != null)
                        _foundPrivateKey = PrivateKeyStatus.Exists;
                    else
                        _foundPrivateKey = PrivateKeyStatus.DoesNotExist;
                }

                return _foundPrivateKey;
            }           
        }

        /// <summary>
        /// Gets ECDH key size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                if (Ecdh != null)
                    return Ecdh.KeySize;
                else
                    return 0;
            }
        }

        /// <summary>
        /// <see cref="ECParameters"/> used to initialize the key.
        /// </summary>
        public ECParameters Parameters { get; private set; }

        /// <summary>
        /// <see cref="EcdhKeyExchangeProvider"/> instance used to initialize the key.
        /// </summary>
        public EcdhKeyExchangeProvider Ecdh { get; private set; }

        /// <summary>
        /// Determines whether the <see cref="EcdhSecurityKey"/> can compute a JWK thumbprint.
        /// </summary>
        /// <returns><c>true</c> if JWK thumbprint can be computed; otherwise, <c>false</c>.</returns>
        /// <remarks>https://datatracker.ietf.org/doc/html/rfc7638</remarks>
        public override bool CanComputeJwkThumbprint()
        {
            try
            {
                if (Ecdh == null)
                    return false;

                Parameters.Validate();
                return true;
            }
            catch(CryptographicException)
            {
                return false;
            }
        }

        /// <summary>
        /// Computes a sha256 hash over the <see cref="EcdhSecurityKey"/>.
        /// </summary>
        /// <returns>A JWK thumbprint.</returns>
        /// <remarks>https://datatracker.ietf.org/doc/html/rfc7638</remarks>
        public override byte[] ComputeJwkThumbprint()
        {
            var ecParameters = Parameters;

            try
            {
                ecParameters.Validate();
            }
            catch(CryptographicException)
            {
                ecParameters = Ecdh.ExportParameters(false);
            }

            var canonicalJwk = $@"{{""{JsonWebKeyParameterNames.Crv}"":""{Base64UrlEncoder.Encode(Ecdh.Crv)}"",""{JsonWebKeyParameterNames.Kty}"":""{JsonWebAlgorithmsKeyTypes.EllipticCurve}"",""{JsonWebKeyParameterNames.X}"":""{Base64UrlEncoder.Encode(ecParameters.Q.X)}"",""{JsonWebKeyParameterNames.Y}"":""{Base64UrlEncoder.Encode(ecParameters.Q.Y)}""}}";
            return Utility.GenerateSha256Hash(canonicalJwk);
        }
    }
#endif
}
