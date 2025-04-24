using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace TestServer;

public class ConnectionAcceptor
{
    private const int ListenPort = 8087;

    private Socket? _serverSocket;

    public int? BoundPort => _serverSocket?.LocalEndPoint == null ? null : ((IPEndPoint)_serverSocket?.LocalEndPoint!).Port;

    private readonly X509Certificate2 _targetCertificate;
    private readonly X509Certificate2Collection _intermediateCertificates;
    private readonly X509Certificate2Collection _rootCertificates;

    public ConnectionAcceptor(X509Certificate2 targetCertificate, X509Certificate2Collection intermediateCertificates, X509Certificate2Collection rootCertificates)
    {
        _targetCertificate = targetCertificate;
        _intermediateCertificates = intermediateCertificates;
        _rootCertificates = rootCertificates;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            _serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _serverSocket.Bind(new IPEndPoint(IPAddress.Any, ListenPort));
            _serverSocket.Listen(1000);

            Console.WriteLine($"Listening on port {BoundPort}.");
        }
        catch (Exception e)
        {
            throw new Exception($"Failed to bind and listen on server socket on port {ListenPort}.", e);
        }

        var trust = SslCertificateTrust.CreateForX509Collection(_rootCertificates);

        var sslServerAuthenticationOptions = new SslServerAuthenticationOptions
        {
            ServerCertificate = _targetCertificate,
            ClientCertificateRequired = true,
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ServerCertificateContext = SslStreamCertificateContext.Create(_targetCertificate, _intermediateCertificates, true/*, trust*/)
        };

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var agentSocket = await _serverSocket.AcceptAsync(cancellationToken);
                var remoteEndPoint = agentSocket.RemoteEndPoint;
                Console.WriteLine($"Accepted TCP connection from {remoteEndPoint}.");

                var stream = new NetworkStream(agentSocket, true);
                await using var sslStream = new SslStream(stream, false, ValidateRemoteCertificate, null);

                await sslStream.AuthenticateAsServerAsync(sslServerAuthenticationOptions, cancellationToken);

                Console.WriteLine("Negotiated TLS connection with client.");

                await sslStream.WriteAsync("BYE"u8.ToArray(), cancellationToken);

                Console.WriteLine("Wrote BYE.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Caught exception: {e}");
            }
        }
    }

    private bool ValidateRemoteCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;
}
