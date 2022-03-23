// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Abstractions
{
    /// <summary>
    /// Details of the telemetry event.
    /// </summary>
    public abstract class EventDetails
    {
        internal Dictionary<string, DataClassification> DataClassificationMapping = new Dictionary<string, DataClassification>();
        internal Dictionary<string, string> PropertyValues = new Dictionary<string, string>();
        internal Dictionary<string, bool> BoolPropertyValues = new Dictionary<string, bool>();
        internal Dictionary<string, DateTime> DateTimePropertyValues = new Dictionary<string, DateTime>();
        internal Dictionary<string, long> LongPropertyValues = new Dictionary<string, long>();
        internal Dictionary<string, double> DoublePropertyValues = new Dictionary<string, double>();
        internal Dictionary<string, Guid> GuidPropertyValues = new Dictionary<string, Guid>();
        internal Dictionary<string, DictionaryTypeEnum> PropertiesKeys = new Dictionary<string, DictionaryTypeEnum>();

        /// <summary>
        /// Name of the telemetry event, should be unique between events.
        /// </summary>
        public abstract string Name { get; set; }

        /// <summary>
        /// Properties which describe the event.
        /// </summary>
        public virtual Dictionary<string, object> Properties
        {
            get
            {
                var currentBag = new Dictionary<string, object>();
                foreach (var kvp in PropertiesKeys)
                {
                    switch (kvp.Value)
                    {
                        case DictionaryTypeEnum.String:
                            currentBag.Add(kvp.Key, PropertyValues[kvp.Key]);
                            break;
                        case DictionaryTypeEnum.Long:
                            currentBag.Add(kvp.Key, LongPropertyValues[kvp.Key]);
                            break;
                        case DictionaryTypeEnum.Double:
                            currentBag.Add(kvp.Key, DoublePropertyValues[kvp.Key]);
                            break;
                        case DictionaryTypeEnum.Bool:
                            currentBag.Add(kvp.Key, BoolPropertyValues[kvp.Key]);
                            break;
                        case DictionaryTypeEnum.DateTime:
                            currentBag.Add(kvp.Key, DateTimePropertyValues[kvp.Key]);
                            break;
                        case DictionaryTypeEnum.Guid:
                            currentBag.Add(kvp.Key, GuidPropertyValues[kvp.Key]);
                            break;
                    }
                }
                return currentBag;
            }
        }

        /// <summary>
        /// Gets the <see cref="DataClassification"/> mapping to keys in <see cref="Properties"/>.
        /// </summary>
        public virtual Dictionary<string, DataClassification> PropertyDataClassification
        {
            get
            {
                return DataClassificationMapping;
            }
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            string value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            PropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.String;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            long value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            LongPropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.Long;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            bool value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            BoolPropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.Bool;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            DateTime value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            DateTimePropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.DateTime;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            double value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            DoublePropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.Double;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Sets a property on the event details.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="dataClassification">Optional parameter which indicates the classification of the data.</param>
        public virtual void SetProperty(
            string key,
            Guid value,
            DataClassification dataClassification = DataClassification.SystemMetadata)
        {
            GuidPropertyValues[key] = value;
            PropertiesKeys[key] = DictionaryTypeEnum.Guid;
            AddDataClassificationIfNecessary(key, dataClassification);
        }

        /// <summary>
        /// Updates the state of the property data classification.
        /// </summary>
        /// <param name="key">Key of the property.</param>
        /// <param name="dataClassification">DataClassification for the property.</param>
        internal void AddDataClassificationIfNecessary(string key, DataClassification dataClassification)
        {
            if (dataClassification != DataClassification.SystemMetadata)
                DataClassificationMapping[key] = dataClassification;
            else
                DataClassificationMapping.Remove(key);
        }

        /// <summary>
        /// Internal enum to help differentiate acceptable dimension types.
        /// </summary>
        internal enum DictionaryTypeEnum
        {
            String = 0,
            Long = 1,
            Double = 2,
            Bool = 3,
            DateTime = 4,
            Guid = 5
        };
    }
}
