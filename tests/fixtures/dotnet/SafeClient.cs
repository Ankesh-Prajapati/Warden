// Secure counterpart: same APIs, used safely (false-positive fixture for Warden).
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

[System.Runtime.Serialization.DataContract]
class Settings { [System.Runtime.Serialization.DataMember] public string Name; }

class SafeClient
{
    static void Main()
    {
        // Real validation: only accept certificates with no policy errors.
        ServicePointManager.ServerCertificateValidationCallback = Validate;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
    }

    static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        return errors == SslPolicyErrors.None;
    }

    static Settings Load(Stream s)
    {
        return (Settings)new DataContractJsonSerializer(typeof(Settings)).ReadObject(s);
    }

    static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            return aes.CreateEncryptor(key, iv).TransformFinalBlock(data, 0, data.Length);
        }
    }
}
