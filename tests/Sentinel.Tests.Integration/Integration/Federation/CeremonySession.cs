namespace Sentinel.Tests.Integration.Federation;

using Microsoft.Playwright;

/// <summary>In-flight browser ceremony with proper async disposal semantics.</summary>
public sealed class CeremonySession : IAsyncDisposable
{
    public CeremonySession(IBrowserContext context, IPage page, ICDPSession cdp,
        Fapi2BrowserClient client, string codeVerifier)
    {
        Context = context;
        Page = page;
        Cdp = cdp;
        Client = client;
        CodeVerifier = codeVerifier;
    }

    public IBrowserContext Context { get; }
    public IPage Page { get; }
    public ICDPSession Cdp { get; }
    public Fapi2BrowserClient Client { get; }
    public string CodeVerifier { get; }

    /// <summary>Dynamic callback port from the parent fixture.</summary>
    public int CallbackPort => Client.CallbackPort;

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        if (Context is not null)
            await Context.CloseAsync();
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WebAuthnAal3Collection : ICollectionFixture<WebAuthnAal3Fixture>
{
    public const string Name = "WebAuthn AAL3";
}