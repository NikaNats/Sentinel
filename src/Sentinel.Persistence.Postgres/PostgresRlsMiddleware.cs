namespace Sentinel.Persistence.Postgres;

public sealed class PostgresRlsMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, PostgresSentinelDbContext db)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            await db.SetCurrentUserAsync(context.RequestAborted);
        }

        await next(context);
    }
}
