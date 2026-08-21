using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class SecurityErrorReporterTests
{
    [Test]
    public async Task ReportAsync_TruncaErrorMessageAlLimiteDeSecurityApi()
    {
        const int maxErrorMessageLength = 300;
        var originalMessage = new string('x', maxErrorMessageLength + 1);
        var handler = new CapturingHttpMessageHandler();
        var reporter = new SecurityErrorReporter(
            new TestHttpClientFactory(handler),
            new TestSecuritySystemTokenProvider(),
            NullLogger<SecurityErrorReporter>.Instance);
        var report = new SecurityErrorReport
        {
            ExceptionType = nameof(InvalidOperationException),
            ErrorMessage = originalMessage,
            Criticality = "critical"
        };

        await reporter.ReportAsync(report);

        using var payload = JsonDocument.Parse(handler.RequestBody!);
        var sentMessage = payload.RootElement.GetProperty("errorMessage").GetString();

        Assert.Multiple(() =>
        {
            Assert.That(sentMessage, Has.Length.EqualTo(maxErrorMessageLength));
            Assert.That(sentMessage, Is.EqualTo(originalMessage[..maxErrorMessageLength]));
            Assert.That(report.ErrorMessage, Is.EqualTo(sentMessage));
        });
    }

    private sealed class CapturingHttpMessageHandler : HttpMessageHandler
    {
        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            return new HttpClient(handler, disposeHandler: false)
            {
                BaseAddress = new Uri("https://security-api.test/api/v1/")
            };
        }
    }

    private sealed class TestSecuritySystemTokenProvider : ISecuritySystemTokenProvider
    {
        public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult("test-token");
        }

        public void InvalidateToken()
        {
        }
    }
}
