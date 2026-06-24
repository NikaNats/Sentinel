using System;
using System.Collections.Generic;
using FluentAssertions;
using Sentinel.Domain.Notifications;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class NotificationMessageTests
{
    private readonly NotificationRecipient _recipient = new("recipient@sentinel.ge", "Secure User");
    private const string Subject = "Please verify your security credentials";
    private const string TemplateName = "EmailVerification";

    [Fact(DisplayName = "✅ Notifications: Generic NotificationMessage preserves typed template data")]
    public void GenericConstructor_PreservesTypedTemplateData()
    {
        var data = new MockVerificationData("https://sentinel.local/verify-link-123");

        var sut = new NotificationMessage<MockVerificationData>(_recipient, Subject, TemplateName, data, NotificationType.Email);

        sut.To.Should().Be(_recipient);
        sut.Subject.Should().Be(Subject);
        sut.TemplateName.Should().Be(TemplateName);
        sut.TemplateData.Should().Be(data);
        sut.Type.Should().Be(NotificationType.Email);
    }

    [Fact(DisplayName = "✅ Notifications: AsGeneric successfully casts valid non-generic payload to generic")]
    public void AsGeneric_WithValidType_ReturnsGenericNotificationMessage()
    {
        var data = new MockVerificationData("https://sentinel.local/verify-link-456");
        var nonGeneric = new NotificationMessage(_recipient, Subject, TemplateName, data, NotificationType.Email);

        var sut = nonGeneric.AsGeneric<MockVerificationData>();

        sut.Should().NotBeNull();
        sut.To.Should().Be(_recipient);
        sut.Subject.Should().Be(Subject);
        sut.TemplateName.Should().Be(TemplateName);
        sut.TemplateData.Should().Be(data);
        sut.Type.Should().Be(NotificationType.Email);
    }

    [Fact(DisplayName = "🔴 Notifications: AsGeneric with mismatched type throws InvalidOperationException with details")]
    public void AsGeneric_WithMismatchedType_ThrowsInvalidOperationExceptionWithDetails()
    {
        var data = new MockVerificationData("https://sentinel.local/verify");
        var nonGeneric = new NotificationMessage(_recipient, Subject, TemplateName, data, NotificationType.Email);

        var act = () => nonGeneric.AsGeneric<MockWelcomeData>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"Template data is {nameof(MockVerificationData)}, expected {nameof(MockWelcomeData)}");
    }

    [Fact(DisplayName = "🔴 Notifications: AsGeneric with null payload throws InvalidOperationException")]
    public void AsGeneric_WithNullPayload_ThrowsInvalidOperationException()
    {
        var nonGeneric = new NotificationMessage(_recipient, Subject, TemplateName, null!, NotificationType.Email);

        var act = () => nonGeneric.AsGeneric<MockVerificationData>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("Template data is null, expected MockVerificationData");
    }

    private sealed record MockVerificationData(string VerificationUrl);
    private sealed record MockWelcomeData(string UserDisplayName);
}
