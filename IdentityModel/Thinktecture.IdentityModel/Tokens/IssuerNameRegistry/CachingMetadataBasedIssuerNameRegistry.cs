using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Thinktecture.IdentityModel.Diagnostics;

namespace Thinktecture.IdentityModel.Tokens
{
    public class CachingMetadataBasedIssuerNameRegistry : MetadataBasedIssuerNameRegistry
    {
        bool protect = true;
        IMetadataCache cache;
        int cacheDuration;

        const int DefaultCacheDuration = 30;

        public CachingMetadataBasedIssuerNameRegistry()
        {
        }

        public CachingMetadataBasedIssuerNameRegistry(XmlNodeList config)
            : base(config, true)
        {
            LoadCustomConfiguration(config);
        }

        public CachingMetadataBasedIssuerNameRegistry(
            Uri metadataAddress, string issuerName,
            IMetadataCache cache, 
            int cacheDuration = DefaultCacheDuration, 
            bool protect = true,
            bool lazyLoad = false)
            : base(metadataAddress, issuerName, System.ServiceModel.Security.X509CertificateValidationMode.None, true)
        {
            if (cache == null) throw new ArgumentNullException("cache");

            this.protect = protect;
            SetCache(cache);
            this.cacheDuration = cacheDuration;

            if (!lazyLoad)
            {
                this.LoadMetadata();
            }
        }

        private void SetCache(IMetadataCache cache)
        {
            if (protect)
            {
                this.cache = new MachineKeyMetadataCache(cache);
            }
            else
            {
                this.cache = cache;
            }
        }

        byte[] GetMetadataFromSource()
        {
            var stream = base.GetMetadataStream();
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                return ms.ToArray();
            }
        }

        protected override System.IO.Stream GetMetadataStream()
        {
            byte[] bytes = null;

            if (cache.Age.TotalDays < this.cacheDuration)
            {
                // the data is still within the cache duration window
                bytes = this.cache.Load();
            }
            
            if (bytes == null)
            {
                // no data, reload and cache
                bytes = GetMetadataFromSource();
                this.cache.Save(bytes);
            }
           
            // reload cache from source periodically
            SetupCacheReloadTimer(); 
            
            return new MemoryStream(bytes);
        }

        // need to get a rooted ref to timer so it's not GC'd
        static Timer _cacheReloadTimer;

        private void SetupCacheReloadTimer()
        {
            Action loadCache = () =>
            {
                try
                {
                    var bytes = GetMetadataFromSource();
                    if (bytes != null)
                    {
                        this.cache.Save(bytes);
                    }
                }
                catch (Exception ex)
                {
                    Tracing.Error("CachingMetadataBasedIssuerNameRegistry", String.Format("metadata polling: {0}", ex.Message));
                }
            };

            // this will check every day for an updated metadata document
            // reload on background thread
            var timerInterval = (int)TimeSpan.FromDays(1).TotalMilliseconds;
            var cb = new TimerCallback(state =>
            {
                loadCache();
            });
            _cacheReloadTimer = new Timer(
                cb, null,
                timerInterval,
                timerInterval);

            // check to see if we can eager-reload the cache
            // if we're more than half-way to expiration, then reload
            var halfTime = this.cacheDuration / 2;
            var age = cache.Age.TotalDays;
            if (age > halfTime)
            {
                Task.Factory.StartNew(loadCache);
            }
        }

        void LoadCustomConfiguration(XmlNodeList nodeList)
        {
            if (nodeList == null || nodeList.Count == 0)
            {
                throw new ConfigurationErrorsException("No configuration provided.");
            }

            var node = nodeList.Cast<XmlNode>().FirstOrDefault(x => x.LocalName == "metadataCache");
            if (node == null)
            {
                throw new ConfigurationErrorsException("Expected 'metadataCache' element.");
            }

            var elem = node as XmlElement;

            var protect = elem.Attributes["protect"];
            if (protect != null)
            {
                if (protect.Value != "true" && protect.Value != "false")
                {
                    throw new ConfigurationErrorsException("Expected 'protect' to be 'true' or 'false'.");
                }
                this.protect = protect.Value == "true";
            }
            
            var cacheType = elem.Attributes["cacheType"];
            if (cacheType == null || String.IsNullOrWhiteSpace(cacheType.Value))
            {
                throw new ConfigurationErrorsException("Expected 'cacheType' attribute.");
            }

            var cacheDuration = elem.Attributes["cacheDuration"];
            if (cacheDuration == null || String.IsNullOrWhiteSpace(cacheDuration.Value))
            {
                this.cacheDuration = DefaultCacheDuration;
            }
            else
            {
                if (!Int32.TryParse(cacheDuration.Value, out this.cacheDuration))
                {
                    throw new ConfigurationErrorsException("Attribute 'cacheType' not a valid Int32.");
                }
            }

            var type = Type.GetType(cacheType.Value);
            var xmlCtor = type.GetConstructor(new Type[]{typeof(XmlNodeList)});
            IMetadataCache cacheInstance = null;
            if (xmlCtor != null)
            {
                cacheInstance = (IMetadataCache)Activator.CreateInstance(type, elem.ChildNodes);
            }
            else
            {
                cacheInstance = (IMetadataCache)Activator.CreateInstance(type);
            }
            SetCache(cacheInstance);
        }
    }
}