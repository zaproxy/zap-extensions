package org.zaproxy.addon.dev.auth.totp.simpleAuthWithOTP;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;

public class TestTotp {
    // Hardcoded Base32-decoded key: "JBSWY3DPEHPK3PXP" == "Hello!\0\0\0\0"
    // For testing only; use a secure key in production
    private static final byte[] SECRET_KEY = base32Decode("JBSWY3DPEHPK3PXP");

    public static String generateCurrentCode() {
        long timeWindow = Instant.now().getEpochSecond() / 30;
        return generateTOTPCode(SECRET_KEY, timeWindow);
    }

    public static boolean isCodeValid(String code) {
        long currentWindow = Instant.now().getEpochSecond() / 30;
        for (long i = -1; i <= 1; i++) {
            if (generateTOTPCode(SECRET_KEY, currentWindow + i).equals(code)) {
                return true;
            }
        }
        return false;
    }

    private static String generateTOTPCode(byte[] key, long timestep) {
        try {
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (timestep & 0xFF);
                timestep >>= 8;
            }

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % 1_000_000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate TOTP", e);
        }
    }

    // Base32 decoder (minimal, works for uppercase letters and digits)
    private static byte[] base32Decode(String base32) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bitsLeft = 0, count = 0;
        byte[] result = new byte[base32.length() * 5 / 8];

        for (char c : base32.toCharArray()) {
            if (c == '=') break;
            int val = alphabet.indexOf(c);
            if (val == -1) continue;

            buffer <<= 5;
            buffer |= val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result[count++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        byte[] finalResult = new byte[count];
        System.arraycopy(result, 0, finalResult, 0, count);
        return finalResult;
    }
}
