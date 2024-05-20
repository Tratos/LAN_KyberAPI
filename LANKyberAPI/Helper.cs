using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Diagnostics;
using System.Windows.Forms;
using System.Net;

namespace LANKyberAPI
{
    public static class Helper
    {
        public static byte[] ReadContentSSL(SslStream sslStream)
        {
            MemoryStream res = new MemoryStream();
            byte[] buff = new byte[0x10000];
            sslStream.ReadTimeout = 100;
            int bytesRead;
            try
            {
                while ((bytesRead = sslStream.Read(buff, 0, 0x10000)) > 0)
                    res.Write(buff, 0, bytesRead);
            }
            catch { }
            sslStream.Flush();
            return res.ToArray();
        }
        public static byte[] ReadContentTCP(NetworkStream Stream)
        {
            MemoryStream res = new MemoryStream();
            byte[] buff = new byte[0x10000];
            Stream.ReadTimeout = 100;
            int bytesRead;
            try
            {
                while ((bytesRead = Stream.Read(buff, 0, 0x10000)) > 0)
                    res.Write(buff, 0, bytesRead);
            }
            catch { }
            Stream.Flush();
            return res.ToArray();
        }

        public static string GetLANIP()
        {
            string localIP;
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                localIP = endPoint.Address.ToString();
            }
            return localIP;
        }

        public static string GetWANIP()
        {
            WebRequest hwr = HttpWebRequest.Create(new Uri("http://checkip.dyndns.org"));
            WebResponse wr = hwr.GetResponse();
            Stream stream = wr.GetResponseStream();
            StreamReader streamReader = new StreamReader(stream, Encoding.UTF8);
            string htmlResult = streamReader.ReadToEnd();
            string[] htmlSplit = htmlResult.Split(new string[] { ":", "<" }, StringSplitOptions.RemoveEmptyEntries);
            string IP = htmlSplit[6].Trim();
            stream.Close();
            wr.Close();

            return IP;
        }
    }
}
