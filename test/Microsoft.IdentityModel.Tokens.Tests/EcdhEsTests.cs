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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

using KEY = Microsoft.IdentityModel.TestUtils.KeyingMaterial;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class EcdhEsTests
    {
        [Theory, MemberData(nameof(CreateEcdhEsTestcases))]
        public void CreateEcdhEsTests(EcdhEsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateEcdhEsTests", theoryData);
            try
            {
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<EcdhEsTheoryData> CreateEcdhEsTestcases
        {
            get
            {
                TheoryData<EcdhEsTheoryData> theoryData = new TheoryData<EcdhEsTheoryData>();
                return theoryData;
            }
        }

        public class EcdhEsTheoryData : TheoryDataBase
        {
            // https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1
            // Two modes, 'dir' and 'key-wrap'
            // 'dir' - header 'alg' value - ECDH-ES.
            //      JWE encrypted key value in protected header is empty.
            // 'key-wrap' 'alg' values - ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW.
            //      Use key agreement to encrypt a emphemeral symmetric key generated for each encryption
            //      The output of the Concat KDF MUST be the length for the algorithm 128,192,256
            // In either case, a new ephemeral public key MUST be generated for each key agreement
            // Header parameters
            // 'epk' - the ephemeral public key created by the originator
            //      contains the minumum JWK parameters (RSA - 'e' and 'n')
            // 'apu' - the agreement PartyUInfo, base64url-encoded (OPTIONAL)
            // 'apv' - the agreement PartyVInfo
            //
            // Two steps to generate a key derivation
            // Secret 'Z' established through the ECDH
            // Concat KDF
            // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
            // see section, 5.8.1.1

            public string Algorithm { get; set; }
            public string Curve { get; set; }
            public JsonWebKey PrivateKeySender { get; set; }
            public JsonWebKey PublicKeySender { get; set; }
            public JsonWebKey PrivateKeyReceiver { get; set; }
            public JsonWebKey PublicKeyReceiver { get; set; }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
