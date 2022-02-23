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

namespace Microsoft.IdentityModel.Abstractions
{
    /// <summary>
    /// Interface for Telemetry tracking.
    /// </summary>
    internal interface ITelemetryClient
    {
        /// <summary>
        /// Gets or sets the application or client ID that telemetry is being sent for.
        /// </summary>
        Guid ClientId { get; set; }

        /// <summary>
        /// Perform any necessary bootstrapping for the telemetry client.
        /// </summary>
        /// <remarks>
        /// The expectation is that this should only be called once for the lifetime of the object however the
        /// implementation should be idempotent.
        /// </remarks>
        void Initialize();

        /// <summary>
        /// Checks to see if telemetry is enabled all up.
        /// </summary>
        /// <returns>
        /// Returns <see langword="true"/> if telemetry should be sent; <see langword="false"/> otherwise.
        /// </returns>
        /// <remarks>
        /// This check should be used to gate any resource intensive operations to generate telemetry as well.
        /// </remarks>
        bool IsEnabled();

        /// <summary>
        /// Checks to see if telemetry is enabled for the named event.
        /// </summary>
        /// <param name="eventName">Name of the event to check.</param>
        /// <returns>
        /// Returns <see langword="true"/> if telemetry should be sent for <paramref name="eventName"/>;
        /// <see langword="false"/> otherwise.
        /// </returns>
        /// <remarks>
        /// This check should be used to gate any resource intensive operations to generate telemetry as well.
        /// </remarks>
        bool IsEnabled(string eventName);

        /// <summary>
        /// Tracks an instance of a named event.
        /// </summary>
        /// <param name="eventName">Name of the event to track. Should be unique per scenario.</param>
        /// <param name="eventDimensions">Dimensions of this instance of the event.</param>
        /// <param name="eventMetrics">Metrics of this instance of the event.</param>
        void TrackEvent(
            string eventName,
            Dictionary<string, string> eventDimensions,
            Dictionary<string, double> eventMetrics);
    }
}
