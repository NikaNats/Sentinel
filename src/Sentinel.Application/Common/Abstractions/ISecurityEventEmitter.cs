namespace Sentinel.Application.Common.Abstractions;

public interface ISecurityEventEmitter
{
    void EmitTokenReplay(string jti, string? sub, string? clientId, string ipHash);
    void EmitAuthFailure(string reason, string? sub, string ipHash);
}
