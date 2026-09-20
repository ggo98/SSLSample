using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    internal class Client
    {
        //private const string Host = "localhost";
        //private const int Port = 5000;
        private const string Host = "cndggo";
        private const int Port = 5001;

        static async Task Main()
        {
            using (var client = new TcpClient())
            {
                await client.ConnectAsync(Host, Port);

                using (var ssl = new SslStream(
                    client.GetStream(),
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: ValidateServerCertificate))
                {
                    await ssl.AuthenticateAsClientAsync(
                        Host,
                        clientCertificates: null,
                        enabledSslProtocols: SslProtocols.Tls12,
                        checkCertificateRevocation: false);

                    Console.WriteLine($"Connected. TLS: {ssl.SslProtocol}, Cipher: {ssl.CipherAlgorithm}");
                    Console.WriteLine("Type messages (empty line to quit):");

                    string line;
                    var buffer = new byte[4096];

                    while (!string.IsNullOrEmpty(line = Console.ReadLine()))
                    {
                        byte[] outBytes = Encoding.UTF8.GetBytes(line);
                        await ssl.WriteAsync(outBytes, 0, outBytes.Length);
                        await ssl.FlushAsync();

                        int read = await ssl.ReadAsync(buffer, 0, buffer.Length);
                        if (read == 0) break;

                        Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, read));
                    }
                }
            }
        }

        static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            //return true;
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"Certificate validation error: {sslPolicyErrors}");

            // === DEV ONLY ===
            // Accept the self-signed test cert. NEVER do this in production;
            // instead compare the thumbprint or install the cert in the
            // Trusted Root store.
            return true;
        }
    }
}