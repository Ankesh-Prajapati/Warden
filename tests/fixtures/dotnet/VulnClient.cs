// Deliberately insecure thick-client patterns (test fixture for Warden).
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Collections;
using System.Web.Script.Serialization;

class VulnClient
{
    static void Main()
    {
        // 1. Trust every TLS certificate.
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
        // 2. Force SSL 3.0.
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
    }

    static object LoadState(Stream s)
    {
        // 3. BinaryFormatter deserialization.
        return new BinaryFormatter().Deserialize(s);
    }

    static byte[] Encrypt(byte[] data, byte[] key)
    {
        // 4. DES + 5. ECB mode.
        var des = new DESCryptoServiceProvider();
        des.Mode = CipherMode.ECB;
        return des.CreateEncryptor(key, key).TransformFinalBlock(data, 0, data.Length);
    }

    static void StartServer()
    {
        // 6. .NET Remoting TCP server with full type filter.
        var provider = new BinaryServerFormatterSinkProvider();
        provider.TypeFilterLevel = TypeFilterLevel.Full;
        var props = new Hashtable();
        props["port"] = 9000;
        ChannelServices.RegisterChannel(new TcpServerChannel(props, provider), false);
    }

    static object ParseJson(string json)
    {
        // 7. JavaScriptSerializer with type resolver.
        return new JavaScriptSerializer(new SimpleTypeResolver()).DeserializeObject(json);
    }
}
