// -----------------------------------------------------------------------
// <copyright file="SwtTokenTests.cs" company="GaryMcAllister">
// As per Identity Model
// </copyright>
// -----------------------------------------------------------------------

namespace Thinktecture.IdentityModel.Tests.Swt
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Text;
    using System.Xml;

    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Protocols.WSTrust;
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.IdentityModel.Tokens.Saml11;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Thinktecture.IdentityModel.Tokens;

    /// <summary>
    /// TODO: Update summary.
    /// </summary>
    [TestClass]
    public class SwtTokenTests
    {

        private static string TokenToString(SecurityToken token)
        {
            var sb = new StringBuilder();

            using (var writer = XmlWriter.Create(sb))
            {
                new SimpleWebTokenHandler().WriteToken(writer, token);
            }

            return sb.ToString();
        }

        private List<Claim> Claims()
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.Role, "Administrator"),
                new Claim(ClaimTypes.Role, "Domain Administrator"),
                new Claim(ClaimTypes.Role, "Some,NotVeryNice,EncodedClaim")
            };
        }

        public SimpleWebToken GetToken(out string keyValue)
        {
            var key = Guid.NewGuid().ToByteArray().ToList();
            key.AddRange(Guid.NewGuid().ToByteArray());
            keyValue = Convert.ToBase64String(key.ToArray());

            var descripter = new SecurityTokenDescriptor();
            descripter.Lifetime = new Lifetime(DateTime.Now, DateTime.Now.AddMinutes(5));
            descripter.TokenIssuerName = "http://www.thinktecture.com";
            descripter.SigningCredentials = new HmacSigningCredentials(key.ToArray());
            descripter.Subject = new ClaimsIdentity(this.Claims());
            descripter.AppliesToAddress = "https://www.thinktecture.com/";

            var output = new SimpleWebTokenHandler().CreateToken(descripter) as SimpleWebToken;

            return output;
        }

        [TestMethod]
        public void GetTokenClaimsAsEncodedArrayString()
        {
            string key;
            var token = this.GetToken(out key);
            var builder = new StringBuilder();
            SimpleWebTokenHandler.CreateClaims(token, builder);

            var builderOutput = builder.ToString();
            Assert.AreEqual(builderOutput, "http%3a%2f%2fschemas.microsoft.com%2fws%2f2008%2f06%2fidentity%2fclaims%2frole=Administrator%2cDomain%2bAdministrator%2cSome%252cNotVeryNice%252cEncodedClaim&");
        }

        [TestMethod]
        public void CreateTokenAndParseEncodedMultipleClaims()
        {
            var handler = new SimpleWebTokenHandler();

            string key;
            var token = this.GetToken(out key);
            var tokenString = TokenToString(token);
            var signedToken = handler.ReadToken(new XmlTextReader(new StringReader(tokenString)));
            
            handler.Configuration = new SecurityTokenHandlerConfiguration();

            var registry = new WebTokenIssuerNameRegistry();
            //I think there is currently a bug in this issuer as this really doesn't make sense to me
            registry.AddTrustedIssuer("http://www.thinktecture.com", "TestIssuerName");

            handler.Configuration.IssuerNameRegistry = registry;
            handler.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri("https://www.thinktecture.com/"));

            var tokenResolver = new WebTokenIssuerTokenResolver();
            tokenResolver.AddSigningKey("http://www.thinktecture.com", key);
            handler.Configuration.IssuerTokenResolver = tokenResolver;

            var claims = handler.ValidateToken(signedToken);

            Assert.IsTrue(claims[0].Claims.Count == 3);
            Assert.IsTrue(claims[0].Claims[0].Value == this.Claims()[0].Value);
            Assert.IsTrue(claims[0].Claims[1].Value == this.Claims()[1].Value);
            Assert.IsTrue(claims[0].Claims[2].Value == this.Claims()[2].Value);
        }
    }
}
