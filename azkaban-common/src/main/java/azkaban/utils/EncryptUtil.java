package azkaban.utils;


import org.springframework.util.Base64Utils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptUtil {
    private static final String PREFIX = "ffffff02";

    public EncryptUtil() {
    }

    private static byte[] hexStringToBytes(String hexString) {
        if (hexString != null && !hexString.equals("")) {
            hexString = hexString.toUpperCase();
            int length = hexString.length() / 2;
            char[] hexChars = hexString.toCharArray();
            byte[] d = new byte[length];

            for (int i = 0; i < length; ++i) {
                int pos = i * 2;
                d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
            }

            return d;
        } else {
            return null;
        }
    }

    private static String byteToHexString(byte[] b) {
        String a = "";

        for (int i = 0; i < b.length; ++i) {
            String hex = Integer.toHexString(b[i] & 255);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            a = a + hex;
        }

        return a;
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    private static String ReadFileContent(String filePath) {
        File file = new File(filePath);
        BufferedReader reader = null;
        StringBuffer key = new StringBuffer();

        try {
            reader = new BufferedReader(new FileReader(file));
            String tempString = null;

            while ((tempString = reader.readLine()) != null) {
                if (!tempString.startsWith("--")) {
                    key.append(tempString);
                }
            }

            reader.close();
        } catch (IOException var13) {
            var13.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException var12) {
                }
            }

        }

        return key.toString();
    }


    private static String generatePwd(String loginId, String loginPwd) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        StringBuffer result = new StringBuffer();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(loginPwd.getBytes("UTF-8"));
        String salt = "{" + loginId + "}";
        md.update(salt.getBytes("UTF-8"));
        byte[] arr$ = md.digest();
        int len$ = arr$.length;

        for (int i$ = 0; i$ < len$; ++i$) {
            byte b = arr$[i$];
            result.append(String.format("%02x", b));
        }

        return result.toString();
    }

    private static String simpleMd5(String userId, String pwd) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update((userId + pwd).getBytes());
        StringBuffer result = new StringBuffer();
        byte[] arr$ = md.digest();
        int len$ = arr$.length;

        for (int i$ = 0; i$ < len$; ++i$) {
            byte b = arr$[i$];
            result.append(String.format("%02x", b));
        }

        return result.toString();
    }

    public static String decrypt(String appPrivKey, String encStr) throws Exception {
        if (encStr.startsWith("ffffff02")) {
            encStr = encStr.substring("ffffff02".length());
        }

        byte[] encBin = hexStringToBytes(encStr);
        byte[] app = hexStringToBytes(appPrivKey);
        byte[] b = RSAUtils.decrypt(encBin, Base64Utils.decode(app));
        return new String(b);
    }

}
