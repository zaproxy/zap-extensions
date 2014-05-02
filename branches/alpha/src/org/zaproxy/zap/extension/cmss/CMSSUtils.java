package org.zaproxy.zap.extension.cmss;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class CMSSUtils {

    public static InputStream getFileFromUrl(URL url) throws IOException {
        InputStream is = null;
        try {
            is = url.openStream();
            File file = new File(url.getPath());
            FileOutputStream out = new FileOutputStream(file.getName());
        } catch (Exception e) {
        }
        return is;
    }

    public static String checkSumApacheCommons(InputStream is) {
        String checksum = null;
        try {
            checksum = DigestUtils.md5Hex(is);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return checksum;
    }

    public static String checkUrlContentChecksums(URL url) throws IOException {
        return checkSumApacheCommons(getFileFromUrl(url));
    }

    public static String checksum(byte[] octets) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.reset();
        messageDigest.update(octets);
        final byte[] resultByte = messageDigest.digest();
        return new String(Hex.encodeHex(resultByte));
    }
}
