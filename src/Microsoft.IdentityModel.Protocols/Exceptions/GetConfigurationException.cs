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
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.Exceptions
{
    /// <summary>
    /// Exception thrown when retrieving the configuration fails.
    /// </summary>
    [Serializable]
    public class GetConfigurationException : InvalidOperationException
    {
        /// <summary>
        /// Initializes a new instance of <see cref="GetConfigurationException"/>
        /// </summary>
        public GetConfigurationException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="GetConfigurationException"/>
        /// </summary>
        /// <param name="message">Message to display.</param>
        public GetConfigurationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="GetConfigurationException"/>
        /// </summary>
        /// <param name="message">Message to display.</param>
        /// <param name="innerException">Inner exception.</param>
        public GetConfigurationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="GetConfigurationException"/>
        /// </summary>
        /// <param name="message">Message to display.</param>
        /// <param name="rawErrorString">The raw error string for retrieving the OpenIdConnectConfiguration.</param>
        /// <param name="innerException">Inner exception.</param>
        private GetConfigurationException(string message, string rawErrorString, Exception innerException)
            : base(message, innerException)
        {
            RawErrorString = rawErrorString;
        }

        /// <summary>
        /// Initializes a new instance of the exception class with a specified error, error codes, correlation id,error message, error uri, status code, and raw error string.
        /// <param name="message">message to display.</param>
        /// <param name="error">The error code string when retrieving the OpenIdConnectConfiguration fails.</param>
        /// <param name="errorCodes">The error codes when retrieving the OpenIdConnectConfiguration fails.</param>
        /// <param name="correlationId">The correlation id when retrieving the OpenIdConnectConfiguration fails.</param>
        /// <param name="errorMessage">The specific error message when retrieving the OpenIdConnectConfiguration fails.</param>
        /// <param name="errorUri">The link to the error lookup page for retrieving the OpenIdConnectConfiguration.</param>
        /// <param name="rawErrorString">The raw error string of the exception returned when retrieving the OpenIdConnectConfiguration fails.</param>
        /// <param name="statusCode">The http status code for retrieving the OpenIdConnectConfiguration.</param>
        /// </summary>
        private GetConfigurationException(string message, string error, string errorCodes, string correlationId, string errorMessage, string errorUri, string rawErrorString, HttpStatusCode statusCode)
            : base(message)
        {
            Error = error;
            ErrorCodes = errorCodes;
            CorrelationId = correlationId;
            ErrorMessage = errorMessage;
            ErrorUri = errorUri;
            RawErrorString = rawErrorString;
            StatusCode = statusCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GetConfigurationException"/> class.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected GetConfigurationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        /// <summary>
        /// Returns an <see cref="GetConfigurationException"/>.
        /// </summary>
        /// <param name="responseContent"> The response content for retrieving the OpenIdConnectConfiguration.</param>
        /// <param name="statusCode"> The status codes for retrieving the OpenIdConnectConfiguration.</param>
        /// <returns>An <see cref="GetConfigurationException"/>.</returns>
        internal static GetConfigurationException CreateGetOidcConfigurationException(HttpStatusCode statusCode, string responseContent)
        {
            if (responseContent.IsNullOrEmpty())
                return new GetConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, statusCode));

            try
            {
                var jsonResponseContext = JObject.Parse(responseContent);
                jsonResponseContext.TryGetValue("error", out var error);
                jsonResponseContext.TryGetValue("error_codes", out var error_codes);
                jsonResponseContext.TryGetValue("correlation_id", out var correlation_Id);
                jsonResponseContext.TryGetValue("error_description", out var error_description);
                jsonResponseContext.TryGetValue("error_uri", out var error_uri);

                return new GetConfigurationException(
                    LogHelper.FormatInvariant(LogMessages.IDX20811, LogHelper.MarkAsNonPII(error), LogHelper.MarkAsNonPII(error_codes), LogHelper.MarkAsNonPII(correlation_Id), error_description, LogHelper.MarkAsNonPII(error_uri), LogHelper.MarkAsNonPII(statusCode), responseContent),
                    error?.Value<string>(),
                    (error_codes == null) ? null : string.Join(",", error_codes.Values().Select(p => p.ToString()).ToArray()),
                    correlation_Id?.Value<string>(),
                    error_description?.Value<string>(),
                    error_uri?.Value<string>(),
                    responseContent,
                    statusCode);
            }
            catch (Exception ex)
            {
                return new GetConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20812, responseContent, ex), responseContent, ex);
            }
        }

        /// <summary>
        /// Gets the correlation id when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string CorrelationId { get; }

        /// <summary>
        /// Gets the error when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string Error { get; }

        /// <summary>
        /// Gets the error codes when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string ErrorCodes { get; }

        /// <summary>
        /// Gets the error message when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Gets the error uri when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string ErrorUri { get; }

        /// <summary>
        /// Gets the raw error string when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public string RawErrorString { get; }

        /// <summary>
        /// Gets the status code when retrieving the OpenIdConnectConfiguration fails.
        /// </summary>
        public HttpStatusCode StatusCode { get; }
    }
}
