// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Abstractions
{
    /// <summary>
    /// The default implementation of the <see cref="ITelemetryClient"/> interface which swallows all telemetry signals.
    /// </summary>
    public class NullTelemetryClient : TelemetryClient
    {
        /// <summary>
        /// Singleton instance of <see cref="NullTelemetryClient"/>.
        /// </summary>
        public static NullTelemetryClient Instance { get; } = new NullTelemetryClient();

        private NullTelemetryClient() { }

        /// <inheritdoc />
        public override bool IsEnabled() => false;

        /// <inheritdoc/>
        public override bool IsEnabled(string eventName) => false;

        /// <inheritdoc/>
        public override void Initialize()
        {
            // no-op
        }

        /// <inheritdoc/>
        public override void TrackEvent(EventDetails eventDetails)
        {
            // no-op
        }

        /// <inheritdoc/>
        public override void TrackEvent(
            string eventName,
            Dictionary<string, string> stringProperties = null,
            Dictionary<string, long> longProperties = null,
            Dictionary<string, bool> boolProperties = null,
            Dictionary<string, DateTime> DateTimeProperties = null,
            Dictionary<string, double> doubleProperties = null,
            Dictionary<string, Guid> guidProperties = null,
            Dictionary<string, DataClassification> dataClassificationMapping = null)
        {
            // no-op
        }
    }
}
