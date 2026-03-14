namespace Sentinel.Application.Auth;

public static class Policies
{
    public const string ReadProfile = "ReadProfile";
    public const string RequireAcr3 = "RequireAcr3";
    public const string ElevatedAccess = "ElevatedAccess";
    public const string DocumentRead = "Document:Read";
    public const string DocumentDelete = "Document:Delete";
}
