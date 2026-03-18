namespace Sentinel.Persistence.SqlServer;

public sealed class SqlServerRlsMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, SqlServerSentinelDbContext db)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            await db.SetCurrentUserAsync(context.RequestAborted);
        }

        await next(context);
    }
}
