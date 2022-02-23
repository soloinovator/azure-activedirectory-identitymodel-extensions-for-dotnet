using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    ///
    /// </summary>
    public interface IClaimsIdentityProvider
    {
        /// <summary>
        /// 
        /// </summary>
        ClaimsIdentity ClaimsIdentity { get; }
    }


    /// <summary>
    ///
    /// </summary>
    public interface IClaimProvider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="claim"></param>
        /// <param name="claimValue"></param>
        /// <returns></returns>
        bool TryGetClaimValue<T> (string claim, out T claimValue);

        /// <summary>
        /// 
        /// </summary>
        IEnumerable<Claim> Claims { get; }

        /// <summary>
        ///
        /// </summary>
        IEnumerable<Claim> ActorClaims { get; }

        /// <summary>
        /// 
        /// </summary>
        IDictionary<string, object> ClaimsIdentityProperties { get; }
    }
}
