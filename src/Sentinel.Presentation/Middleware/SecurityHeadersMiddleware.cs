namespace Sentinel.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next, IWebHostEnvironment env)
{
    // CSP for Scalar UI in development — permissive to support CDNs, fonts, and dev tools
    private const string ScalarCsp =
        "default-src 'self' https://localhost https://cdn.jsdelivr.net; " +
        "script-src 'self' https: http://localhost 'unsafe-inline' 'unsafe-eval'; " +
        "style-src 'self' https: 'unsafe-inline'; " +
        "font-src 'self' data: https: http:; " +
        "connect-src https://localhost http://localhost https: http: ws: wss: " +
        "https://cdn.jsdelivr.net https://proxy.scalar.com https://api.scalar.com; " +
        "img-src 'self' https: data: blob:; " +
        "frame-ancestors 'none'";

    private const string DefaultCsp = "default-src 'none'; frame-ancestors 'none'";

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        var isScalarUi = env.IsDevelopment() && context.Request.Path.StartsWithSegments("/scalar");

        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload";
        headers["Content-Security-Policy"] = isScalarUi ? ScalarCsp : DefaultCsp;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
        headers["Cache-Control"] = "no-store";
        headers["Pragma"] = "no-cache";

        headers.Remove("Server");
        headers.Remove("X-Powered-By");

        await next(context);
    }
}

// Extension method for clean registration in Program.cs
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
        => app.UseMiddleware<SecurityHeadersMiddleware>();
}
