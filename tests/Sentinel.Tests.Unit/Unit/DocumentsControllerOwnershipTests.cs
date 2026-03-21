using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;
using Sentinel.Controllers;
using Sentinel.Presentation.Controllers;

namespace Sentinel.Tests.Unit;

public sealed class DocumentsControllerOwnershipTests
{
    [Fact]
    public async Task GetDocument_WhenSubClaimMissing_ReturnsUnauthorized()
    {
        var store = new Mock<IDocumentStore>();
        var controller = BuildController(store.Object, null);

        var result = await controller.GetDocument(Guid.NewGuid(), CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        store.Verify(x => x.GetByIdAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task GetDocument_PassesSubjectToStoreAndReturnsNotFoundForCrossSubject()
    {
        var store = new Mock<IDocumentStore>();
        var docId = Guid.NewGuid();
        store
            .Setup(x => x.GetByIdAsync(docId, "attacker-sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync((DocumentDto?)null);

        var controller = BuildController(store.Object, "attacker-sub");

        var result = await controller.GetDocument(docId, CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
        store.Verify(x => x.GetByIdAsync(docId, "attacker-sub", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetDocument_WhenStoreReturnsOwnedDocument_ReturnsOk()
    {
        var store = new Mock<IDocumentStore>();
        var docId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var ownedDoc = new DocumentDto(docId, "owner-sub", "t", "c", now, now);

        store
            .Setup(x => x.GetByIdAsync(docId, "owner-sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ownedDoc);

        var controller = BuildController(store.Object, "owner-sub");

        var result = await controller.GetDocument(docId, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Same(ownedDoc, ok.Value);
    }

    private static DocumentsController BuildController(IDocumentStore store, string? sub)
    {
        var controller = new DocumentsController(store, NullLogger<DocumentsController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        if (!string.IsNullOrWhiteSpace(sub))
        {
            controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(
                new ClaimsIdentity([new Claim("sub", sub)], "test"));
        }

        return controller;
    }
}
