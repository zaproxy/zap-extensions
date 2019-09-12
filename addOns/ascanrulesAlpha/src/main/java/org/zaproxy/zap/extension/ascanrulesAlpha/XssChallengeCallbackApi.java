package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.security.SecureRandom;

public class XssChallengeCallbackApi extends ChallengeCallbackAPI {

    private static final String PREFIX = "x";
    private static final int CHALLENGE_LENGTH = 5;

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    public String generateRandomChallenge(){
        return randomString(CHALLENGE_LENGTH);
    }

    /**
     * Get a randomly built string with exactly lenght chars
     * @param length the number of chars of this string
     * @return a string element containing exactly "lenght" characters
     */
    private String randomString(int length) {
        SecureRandom rand = new SecureRandom();
        StringBuilder result = new StringBuilder(length);
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(rand.nextInt(alphabet.length())));
        }

        return result.toString();
    }
}
