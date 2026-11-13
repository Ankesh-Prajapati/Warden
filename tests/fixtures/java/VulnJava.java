// Deliberately insecure Java patterns (test fixture for Warden).
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.net.ssl.*;
import java.sql.*;
import java.security.cert.X509Certificate;

public class VulnJava {
    // 1. Hardcoded JDBC credentials.
    static final String DB = "jdbc:mysql://db.internal:3306/app?user=root&password=Sup3rS3cret!";

    static Object load(InputStream in) throws Exception {
        // 2. Insecure deserialization.
        return new ObjectInputStream(in).readObject();
    }

    static byte[] enc(byte[] data, Key key) throws Exception {
        // 3. DES + ECB.
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    static byte[] hash(byte[] data) throws Exception {
        // 4. MD5.
        return MessageDigest.getInstance("MD5").digest(data);
    }

    static void trustAll() throws Exception {
        // 5. Trust-all X509TrustManager (empty check methods).
        TrustManager[] tm = new TrustManager[] { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new SecureRandom());
        // 6. Hostname verifier that accepts everything.
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
    }

    static void run(String name) throws Exception {
        // 7. Command execution.
        Runtime.getRuntime().exec("cmd /c echo " + name);
    }
}
