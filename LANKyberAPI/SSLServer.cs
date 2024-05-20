using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;


namespace LANKyberAPI
{
    public static class SSLServer
    {
        public static bool basicMode = Globals.basicMode;
        public static readonly object _sync = new object();
        public static bool _exit;
        public static bool box = Globals.basicMode;
        public static TcpListener lAPIServer = null;

        public static void Start()
        {
            SetExit(false);
            Logger.Log("Starting API Server...");
            new Thread(new ParameterizedThreadStart(tSSLServerMain)).Start();
            for (int i = 0; i < 10; i++)
            {
                Thread.Sleep(10);
                Application.DoEvents();
            }
        }

        public static void Stop()
        {
            Logger.Log("API Server stopping...");
            if (lAPIServer != null) lAPIServer.Stop();
            SetExit(true);
            Logger.Log("Done.");
        }

        public static void tSSLServerMain(object obj)
        {
            X509Certificate2 cert = null;

            try
            {
                Logger.Log("[SSL] API Server starting...");
                lAPIServer = new TcpListener(IPAddress.Parse(Globals.backendIP),  Convert.ToInt32(Globals.backendPort));
                Logger.Log("[SSL] API Server bound to  " + Globals.backendIP + ":" + Globals.backendPort);
                lAPIServer.Start();

                Logger.Log("[SSL] Loading Cert...");
                cert = new X509Certificate2("Cert/kyber.lan.pfx", "123456");

                Logger.Log("[SSL] API Server listening...");
                TcpClient client;

                while (!GetExit())
                {
                    client = lAPIServer.AcceptTcpClient();
                    Logger.Log("[SSL] Client connected");

                    SslStream sslStream = new SslStream(client.GetStream(), false);
                    sslStream.AuthenticateAsServer(cert, false, SslProtocols.Default | SslProtocols.None | SslProtocols.Ssl2 | SslProtocols.Ssl3 | SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12, false);
                    byte[] data = Helper.ReadContentSSL(sslStream);

                    try
                    {
                        ProcessJSON(Encoding.ASCII.GetString(data), sslStream);
                    }
                    catch
                    {

                    }
                    client.Close();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("SSL", ex);
            }
        }

        public static void ProcessJSON(string data, SslStream s)
        {
            string[] lines = data.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            Logger.Log("[JSON] Request: " + lines[0]);
            string cmd = lines[0].Split(' ')[0];
            string url = lines[0].Split(' ')[1].Split(':')[0];
            if (cmd == "GET")
            {
                if (url.StartsWith("/api/proxies"))
                {
                        string Replay = "";
                        Replay = Proxies.getProxis();
                        byte[] postBytes = Encoding.UTF8.GetBytes(Replay);
                        ReplyWithJSON(s, postBytes);
                }

                if (url.StartsWith("/api/servers?limit=20&page="))
                {
                    string Replay = "";
                    Replay = Servers.getServers();
                    byte[] postBytes = Encoding.UTF8.GetBytes(Replay);
                    ReplyWithJSON(s, postBytes);
                }

                if (url.StartsWith("/static/images/flags/"))
                {
                    ReplyWithBinary(s, GetBinaryFile(url.Replace("/", "\\")));
                }

                if (url.StartsWith("/api/downloads/distributions/stable/dll"))
                {
                    url = url + "/Kyber.dll";
                    ReplyWithBinary(s, GetBinaryFile(url.Replace("/", "\\")));
                }

            }
            if (cmd == "POST")
            {
                int pos = data.IndexOf("\r\n\r\n");
                if (pos != -1)
                {
                    Logger.Log("[JSON] Content: \n" + data.Substring(pos + 4));
                }
            }
        }

        public static void ReplyWithJSON(SslStream s, byte[] c)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("HTTP/1.1 200 OK");
            sb.AppendLine("Date: " + DateTime.Now.ToUniversalTime().ToString("r"));
            sb.AppendLine("Server: Kyber Network");
            sb.AppendLine("Content-Type: application/json; charset=UTF-8");
            sb.AppendLine("Content-Encoding: UTF-8");
            sb.AppendLine("Content-Length: " + c.Length);
            sb.AppendLine("Keep-Alive: timeout=5, max=100");
            sb.AppendLine("Connection: Keep-Alive");
            sb.AppendLine();
            if (basicMode)
            {
                Logger.Log("[JSON] Sending: \n" + sb.ToString());
            }
            byte[] buf = Encoding.ASCII.GetBytes(sb.ToString());
            s.Write(buf, 0, buf.Length);
            s.Write(c, 0, c.Length);
            s.Flush();
        }

        public static void ReplyWithBinary(SslStream s, byte[] b)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("HTTP/1.1 200 OK");
            sb.AppendLine("Date: " + DateTime.Now.ToUniversalTime().ToString("r"));
            sb.AppendLine("Server: Kyber Network");
            sb.AppendLine("Content-Type: application/octet-stream");
            sb.AppendLine("Content-Length: " + b.Length);
            sb.AppendLine("Keep-Alive: timeout=5, max=100");
            sb.AppendLine("Connection: close");
            sb.AppendLine();
            if (basicMode)
            {
                Logger.Log("[BINARY] Sending: \n" + sb.ToString());
            }
            byte[] buf = Encoding.ASCII.GetBytes(sb.ToString());
            s.Write(buf, 0, buf.Length);
            s.Write(b, 0, b.Length);
            s.Flush();
        }

        public static void ReplyWithText(SslStream s, string c)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("HTTP/1.1 200 OK");
            sb.AppendLine("Date: " + DateTime.Now.ToUniversalTime().ToString("r"));
            sb.AppendLine("Server: Kyber Network");
            sb.AppendLine("Content-Type: text/html; charset=UTF-8");
            sb.AppendLine("Content-Encoding: UTF-8");
            sb.AppendLine("Content-Length: " + c.Length);
            sb.AppendLine("Keep-Alive: timeout=5, max=100");
            sb.AppendLine("Connection: close");
            sb.AppendLine();
            sb.Append(c);
            if (basicMode)
            {
                Logger.Log("[TEXT] Sending: \n" + sb.ToString());
            }
            byte[] buf = Encoding.ASCII.GetBytes(sb.ToString());
            s.Write(buf, 0, buf.Length);
            s.Flush();
        }

        public static byte[] GetBinaryFile(string path)
        {
            if (File.Exists("html" + path))
                return File.ReadAllBytes("html" + path);
            Logger.Log("[JSON] Error file not found: " + path);
            return new byte[0];
        }


            public static void SetExit(bool state)
            {
                lock (_sync)
                {
                    _exit = state;
                }
            }

            public static bool GetExit()
            {
                bool result;
                lock (_sync)
                {
                    result = _exit;
                }
                return result;
            }
    }
}
