﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading;
using Microsoft.Extensions.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains the results of successfully validating a <see cref="SecurityToken"/>.
    /// </summary>
    internal class ValidatedToken
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ValidatedToken"/>.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that was validated.</param>
        /// <param name="tokenHandler">The <see cref="TokenHandler"/> that was used to validate the token.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> used to validate the token.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="securityToken"/>, <paramref name="tokenHandler"/>, or <paramref name="validationParameters"/> is null.</exception>
        public ValidatedToken(
            SecurityToken securityToken,
            TokenHandler tokenHandler,
            ValidationParameters validationParameters)
        {
            SecurityToken = securityToken ?? throw new ArgumentNullException(nameof(securityToken));
            TokenHandler = tokenHandler ?? throw new ArgumentNullException(nameof(tokenHandler));
            ValidationParameters = validationParameters ?? throw new ArgumentNullException(nameof(validationParameters));
        }

        /// <summary>
        /// Logs the validation result.
        /// </summary>
        public void Log(ILogger logger) => Logger.TokenValidationSucceeded(
                logger,
                ValidatedAudience ?? "none",
                ValidatedLifetime,
                ValidatedIssuer,
                ValidatedTokenType,
                ValidatedSigningKey?.KeyId ?? "none",
                ActorValidationResult is not null
            );

        /// <summary>
        /// The <see cref="SecurityToken"/> that was validated.
        /// </summary>
        public SecurityToken SecurityToken { get; }

        /// <summary>
        /// The <see cref="TokenHandler"/> that was used to validate the token.
        /// </summary>
        public TokenHandler TokenHandler { get; }

        /// <summary>
        /// The <see cref="ValidationParameters"/> that were used to validate the token.
        /// </summary>
        public ValidationParameters ValidationParameters { get; }

        #region Validated Properties
        /// <summary>
        /// The result of validating the actor, if any.
        /// </summary>
        public ValidatedToken? ActorValidationResult { get; internal set; }

        /// <summary>
        /// The audience that was validated, if any.
        /// </summary>
        public string? ValidatedAudience { get; internal set; }

        /// <summary>
        /// The issuer that was validated. If present, it contains the source of the validation as well.
        /// </summary>
        public ValidatedIssuer? ValidatedIssuer { get; internal set; }

        /// <summary>
        /// The lifetime that was validated, if any.
        /// </summary>
        public ValidatedLifetime? ValidatedLifetime { get; internal set; }

        /// <summary>
        /// The expiration time of the token that was used to validate the token was not replayed, if any.
        /// </summary>
        public DateTime? ValidatedTokenReplayExpirationTime { get; internal set; }

        /// <summary>
        /// The token type that was validated, if any.
        /// </summary>
        public ValidatedTokenType? ValidatedTokenType { get; internal set; }

        /// <summary>
        /// The <see cref="SecurityKey"/> that was used to validate the token, if any.
        /// </summary>
        public SecurityKey? ValidatedSigningKey { get; internal set; }

        /// <summary>
        /// The validated lifetime of the <see cref="SecurityKey"/> that was used to sign the token, if any.
        /// </summary>
        public ValidatedSigningKeyLifetime? ValidatedSigningKeyLifetime { get; internal set; }
        #endregion

        #region Claims
        // Fields lazily initialized in a thread-safe manner. _claimsIdentity is protected by the _claimsIdentitySyncObj
        // lock, and since null is a valid initialized value, _claimsIdentityInitialized tracks whether or not it's valid.
        // _claims is constructed by reading the data from the ClaimsIdentity and is synchronized using Interlockeds
        // to ensure only one dictionary is published in the face of concurrent access (but if there's a race condition,
        // multiple dictionaries could be constructed, with only one published for all to see). Simiarly, _propertyBag
        // is initalized with Interlocked to ensure only a single instance is published in the face of concurrent use.
        // _claimsIdentityInitialized only ever transitions from false to true, and is volatile to reads/writes are not
        // reordered relative to the other operations. The rest of the objects are not because the .NET memory model
        // guarantees object writes are store releases and that reads won't be introduced.
        private volatile bool _claimsIdentityInitialized;
        private object? _claimsIdentitySyncObj;
        private ClaimsIdentity? _claimsIdentity;
        private Dictionary<string, object>? _claims;

        /// <summary>
        /// The <see cref="Dictionary{String, Object}"/> created from the validated security token.
        /// </summary>
        public IDictionary<string, object> Claims
        {
            get
            {
                if (_claims is null)
                {
                    Interlocked.CompareExchange(ref _claims, TokenUtilities.CreateDictionaryFromClaims(ClaimsIdentity.Claims), null);
                }

                return _claims;
            }
        }

        /// <summary>
        /// The <see cref="ClaimsIdentity"/> created from the validated security token.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity
        {
            get
            {
                if (!_claimsIdentityInitialized)
                {
                    lock (ClaimsIdentitySyncObj)
                    {
                        return ClaimsIdentityNoLocking;
                    }
                }

                return _claimsIdentity!;
            }
            set
            {
                if (value is null)
                    throw new ArgumentNullException(nameof(value), "ClaimsIdentity cannot be set as null.");

                lock (ClaimsIdentitySyncObj)
                {
                    ClaimsIdentityNoLocking = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="_claimsIdentity"/> without synchronization. All accesses must either
        /// be protected or used when the caller knows access is serialized.
        /// </summary>
        internal ClaimsIdentity ClaimsIdentityNoLocking
        {
            get
            {
                if (!_claimsIdentityInitialized)
                {
                    Debug.Assert(_claimsIdentity is null);

                    _claimsIdentity = TokenHandler.CreateClaimsIdentityInternal(SecurityToken, ValidationParameters, ValidatedIssuer?.Issuer);
                    _claimsIdentityInitialized = true;
                }

                return _claimsIdentity!;
            }
            set
            {
                Debug.Assert(value is not null);
                _claimsIdentity = value;
                _claims = null;
                _claimsIdentityInitialized = true;
            }
        }

        /// <summary>Gets the object to use in <see cref="ClaimsIdentity"/> for double-checked locking.</summary>
        private object ClaimsIdentitySyncObj
        {
            get
            {
                object? syncObj = _claimsIdentitySyncObj;
                if (syncObj is null)
                {
                    Interlocked.CompareExchange(ref _claimsIdentitySyncObj, new object(), null);
                    syncObj = _claimsIdentitySyncObj;
                }

                return syncObj;
            }
        }
        #endregion

        #region Logging
        /// <summary>
        /// Internal class used for logging.
        /// </summary>
        private static class Logger
        {
            private static readonly Action<ILogger, string, string, Exception?> s_tokenValidationFailed =
                LoggerMessage.Define<string, string>(
                    LogLevel.Information,
                    LoggingEventId.TokenValidationFailed,
                    "[MsIdentityModel] The token validation was unsuccessful due to: {ValidationFailureType} " +
                    "Error message provided: {ValidationErrorMessage}");

            /// <summary>
            /// Logger for handling failures in token validation.
            /// </summary>
            /// <param name="logger">ILogger.</param>
            /// <param name="validationFailureType">The cause of the failure.</param>
            /// <param name="messageDetail">The message provided as part of the failure.</param>
            public static void TokenValidationFailed(
                ILogger logger,
                ValidationFailureType validationFailureType,
                MessageDetail messageDetail)
            {
                if (logger.IsEnabled(LogLevel.Information))
                {
                    s_tokenValidationFailed(logger, validationFailureType.Name, messageDetail.Message, null);
                }
            }

            private static readonly Action<ILogger, string, ValidatedLifetime?, ValidatedIssuer?, ValidatedTokenType?, string, bool, Exception?> s_tokenValidationSucceeded =
                LoggerMessage.Define<string, ValidatedLifetime?, ValidatedIssuer?, ValidatedTokenType?, string, bool>(
                    LogLevel.Debug,
                    LoggingEventId.TokenValidationSucceeded,
                    "[MsIdentityModel] The token validation was successful. " +
                    "Validated audience: {ValidatedAudience} " +
                    "Validated lifetime: {ValidatedLifetime} " +
                    "Validated issuer: {ValidatedIssuer} " +
                    "Validated token type: {ValidatedTokenType} " +
                    "Validated signing key id: {ValidatedSigningKeyId} " +
                    "Actor was validated: {ActorWasValidated}");

            /// <summary>
            /// Logger for handling successful token validation.
            /// </summary>
            /// <param name="logger">The instance to be used to log.</param>
            /// <param name="validatedAudience">The audience that was validated.</param>
            /// <param name="validatedLifetime">The lifetime that was validated.</param>
            /// <param name="validatedIssuer">The issuer that was validated.</param>
            /// <param name="validatedTokenType">The token type that was validated.</param>
            /// <param name="validatedSigningKeyId">The signing key id that was validated.</param>
            /// <param name="actorWasValidated">Whether the actor was validated.</param>
            public static void TokenValidationSucceeded(
                ILogger logger,
                string validatedAudience,
                ValidatedLifetime? validatedLifetime,
                ValidatedIssuer? validatedIssuer,
                ValidatedTokenType? validatedTokenType,
                string validatedSigningKeyId,
                bool actorWasValidated)
            {
                if (logger.IsEnabled(LogLevel.Debug))
                {
                    s_tokenValidationSucceeded(
                        logger,
                        validatedAudience,
                        validatedLifetime,
                        validatedIssuer,
                        validatedTokenType,
                        validatedSigningKeyId,
                        actorWasValidated,
                        null);
                }
            }
        }
        #endregion
    }
}
#nullable disable
