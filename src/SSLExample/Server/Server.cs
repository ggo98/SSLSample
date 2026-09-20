using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    internal class Server
    {
        private const int Port = 5000;

        static async Task Main()
        {
            // Load the server certificate (must include the private key)
            var cert = new X509Certificate2(@"server.pfx", "password");

            //var listener = new TcpListener(IPAddress.Loopback, Port);
            var listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();
            Console.WriteLine($"Server listening on port {Port}...");

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client, cert);   // fire and forget
            }
        }

        static async Task HandleClientAsync(TcpClient client, X509Certificate2 cert)
        {
            using (client)
            using (var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false))
            {
                try
                {
                    // Perform the TLS handshake
                    await ssl.AuthenticateAsServerAsync(
                        cert,
                        clientCertificateRequired: false,
                        enabledSslProtocols: SslProtocols.Tls12,
                        checkCertificateRevocation: false);

                    Console.WriteLine($"Client connected. TLS: {ssl.SslProtocol}, Cipher: {ssl.CipherAlgorithm}");

                    var buffer = new byte[4096];
                    int bytesRead;

                    while ((bytesRead = await ssl.ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.WriteLine($"Received: {message}");

                        byte[] reply = Encoding.UTF8.GetBytes("Echo: " + message);
                        await ssl.WriteAsync(reply, 0, reply.Length);
                        await ssl.FlushAsync();
                    }

                    Console.WriteLine("Client disconnected.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Client error: {ex.Message}");
                }
            }
        }
    }
}
