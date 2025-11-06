package org.zaproxy.zap.extension.foxhound.utils;

public class StringUtils {

    public static String limitedSubstring(String s, int start, int end) {
        return s.substring(Integer.min(s.length(), start), Integer.min(s.length(), end));
    }

}
