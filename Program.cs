namespace NativeWindowsClientInteractiveAADLoginTool
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;

    internal static class AuthTokenProvider
    {
        private static string CacheFilePath;

        public static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Usage: NativeWindowsClientInteractiveAADLoginTool TenantId ClientId CommaSeparatedScopes TokenCachePath");
                return;
            }

            CacheFilePath = args[3];

            var app = PublicClientApplicationBuilder.Create(args[1])
                .WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                .WithAuthority(AzureCloudInstance.AzurePublic, args[0])
                .Build();

            var tokenCache = app.UserTokenCache;
            tokenCache.SetBeforeAccess(BeforeAccessNotification);
            tokenCache.SetAfterAccess(AfterAccessNotification);

            Console.WriteLine(GetTokenAsync(app, args[2].Split(',')).Result);
        }

        private static async Task<string> GetTokenAsync(IPublicClientApplication app, string[] scopes)
        {
            string accessToken = null;

            try
            {
                var accounts = await app.GetAccountsAsync();
                var account = accounts.FirstOrDefault();
                if (account != null)
                {
                    var result = await app.AcquireTokenSilent(scopes, account).ExecuteAsync();
                    accessToken = result.AccessToken;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unable to get token, exc: {ex}");
            }

            if (accessToken == null)
            {
                try
                {
                    var result = await app.AcquireTokenInteractive(scopes).ExecuteAsync();
                    accessToken = result.AccessToken;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Unable to get token, exc: {ex}");
                }
            }

            return accessToken;
        }

        private static void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            var fileExist = File.Exists(CacheFilePath);
            var msalV3State = fileExist ? ProtectedData.Unprotect(File.ReadAllBytes(CacheFilePath), null, DataProtectionScope.CurrentUser) : null;
            args.TokenCache.DeserializeMsalV3(msalV3State);
        }

        private static void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (args.HasStateChanged)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(CacheFilePath));
                File.WriteAllBytes(CacheFilePath, ProtectedData.Protect(args.TokenCache.SerializeMsalV3(), null, DataProtectionScope.CurrentUser));
            }
        }
    }
}