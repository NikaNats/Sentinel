namespace Sentinel.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload";
        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
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
