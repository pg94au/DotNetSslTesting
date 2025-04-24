using System.Security.Cryptography.X509Certificates;

namespace TestServer;

internal class Program
{
    static async Task Main(string[] args)
    {
        await new Program().RunAsync(CancellationToken.None);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Get our target certificate (the one with a private key).
            var targetCertificate = X509Certificate2.CreateFromPemFile("./certificates.cer", "./certificates.cer");

            // Start with all certificates in the intermediate collection.
            var intermediateCertificates = new X509Certificate2Collection();
            intermediateCertificates.ImportFromPemFile("./certificates.cer");

            // Remove our target certificate from intermediates.
            intermediateCertificates.Remove(targetCertificate);

            // If there are any roots from the intermediate list, put them into a roots collection.
            var rootCertificates = new X509Certificate2Collection();
            rootCertificates.AddRange(intermediateCertificates.Where(c => c.Subject == c.Issuer).ToArray());

            // Remove those roots from the collection of intermediates, and if anything is left those are intermediates.
            intermediateCertificates.RemoveRange(rootCertificates);

            Console.WriteLine("TARGET CERTIFICATE");
            Console.WriteLine($"  Subject: {targetCertificate.Subject}");
            Console.WriteLine($"  Issuer: {targetCertificate.Issuer}");

            Console.WriteLine("INTERMEDIATE CERTIFICATES");
            foreach (var c in intermediateCertificates)
            {
                Console.WriteLine($"   Subject: {c.Subject}");
                Console.WriteLine($"   Issuer: {c.Issuer}");
            }

            Console.WriteLine("ROOT CERTIFICATES");
            foreach (var c in rootCertificates)
            {
                Console.WriteLine($"   Subject: {c.Subject}");
                Console.WriteLine($"   Issuer: {c.Issuer}");
            }

            var connectionAcceptor = new ConnectionAcceptor(targetCertificate, intermediateCertificates, rootCertificates);

            await connectionAcceptor.RunAsync(cancellationToken);
        }
        catch (Exception e)
        {
            Console.WriteLine($"Caught exception: {e}");
        }
    }
}