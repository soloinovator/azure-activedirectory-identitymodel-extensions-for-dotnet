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

#if !(NET452 || NET461)

using System;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;


using KEY = Microsoft.IdentityModel.TestUtils.KeyingMaterial;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JweUsingEcdhEsTests
    {
        [Theory, MemberData(nameof(CreateEcdhEsTestcases))]
        public void CreateJweEcdhEsTests(CreateEcdhEsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJweEcdhEsTests", theoryData);
            try
            {
                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

                // Do we need an extension to EncryptingCredentials for: ApuSender, ApvSender
                string jwe = jsonWebTokenHandler.CreateToken(Default.PayloadString, Default.AsymmetricSigningCredentials, theoryData.EncryptingCredentials);
                JsonWebToken jsonWebToken = new JsonWebToken(jwe);
                // we need the ECDSASecurityKey for the receiver to validate, use TokenValidationParameters.TokenDecryptionKey
                TokenValidationResult tokenValidationResult = jsonWebTokenHandler.ValidateToken(jwe, theoryData.TokenValidationParameters);

                // adjusted for theoryData.ExpectedException == tokenValidationResult.Exception
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateEcdhEsTheoryData> CreateEcdhEsTestcases
        {
            get
            {
            
                TheoryData<CreateEcdhEsTheoryData> theoryData = new TheoryData<CreateEcdhEsTheoryData>();
               
                CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("JsonWebKeyP256")
                {
                    EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes128CbcHmacSha256){  JsonWebKey = KeyingMaterial.JsonWebKeyP256_Public },
                    PublicKeyReceiver = KeyingMaterial.JsonWebKeyP256_Public,
                    PublicKeySender = KeyingMaterial.JsonWebKeyP256_Public,
                    PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP256,
                };

                // APU, APV different

                theoryData.Add(testData);

                return theoryData;
            }
        }

    }

    public class CreateEcdhEsTheoryData : TheoryDataBase
    {
        public CreateEcdhEsTheoryData(string testId)
        {
            TestId = testId;
        }

        public string ApuReceiver { get; set; }
        public string ApvReceiver { get; set; }
        public string ApuSender { get; set; }
        public string ApvSender { get; set; }
        public EncryptingCredentials EncryptingCredentials { get; set; }
        public JsonWebKey PrivateKeyReceiver { get; set; }
        public JsonWebKey PublicKeyReceiver { get; set; }
        public JsonWebKey PublicKeySender { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
#endif // !NET45
