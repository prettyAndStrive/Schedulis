package azkaban.utils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSAUtils {

    public static byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes) throws Exception {
        int keyByteSize = 256;
        int decryptBlockSize = keyByteSize - 11;
        int nBlock = encryptedBytes.length / keyByteSize;
        ByteArrayOutputStream outbuf = null;

        try {
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(2, privateK);
            outbuf = new ByteArrayOutputStream(nBlock * decryptBlockSize);

            for(int offset = 0; offset < encryptedBytes.length; offset += keyByteSize) {
                int inputLen = encryptedBytes.length - offset;
                if (inputLen > keyByteSize) {
                    inputLen = keyByteSize;
                }

                byte[] decryptedBlock = cipher.doFinal(encryptedBytes, offset, inputLen);
                outbuf.write(decryptedBlock);
            }

            outbuf.flush();
            byte[] var22 = outbuf.toByteArray();
            return var22;
        } catch (Exception var20) {
            throw new Exception("DEENCRYPT ERROR:", var20);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception var19) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", var19);
            }

        }
    }

}
