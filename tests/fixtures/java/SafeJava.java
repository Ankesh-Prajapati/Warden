// Secure counterpart (false-positive fixture for Warden).
import java.security.*;
import javax.crypto.*;
import java.sql.*;

public class SafeJava {
    static byte[] enc(byte[] data, Key key, byte[] iv) throws Exception {
        // AES/GCM — authenticated, no ECB.
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    static byte[] hash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static ResultSet find(Connection con, String name) throws Exception {
        // Parameterized query, no concatenation.
        PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
