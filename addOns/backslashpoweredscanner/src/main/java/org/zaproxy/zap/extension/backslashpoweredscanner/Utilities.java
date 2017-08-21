/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.Random;
import org.apache.commons.lang.StringUtils;

public class Utilities {
    static final byte CONFIRMATIONS = 8;
    private static final String CHARSET =
            "0123456789abcdefghijklmnopqrstuvwxyz"; // ABCDEFGHIJKLMNOPQRSTUVWXYZ
    private static final String START_CHARSET = "ghijklmnopqrstuvwxyz";
    static Random rnd = new Random();

    static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(START_CHARSET.charAt(rnd.nextInt(START_CHARSET.length())));
        for (int i = 1; i < len; i++) sb.append(CHARSET.charAt(rnd.nextInt(CHARSET.length())));
        return sb.toString();
    }

    static String generateCanary() {
        return randomString(4 + rnd.nextInt(7)) + Integer.toString(rnd.nextInt(9));
    }

    static boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
        for (String key : doNotBreakAttackGroup.getFingerPrint().keySet()) {
            if (!individualBreakAttack.getFingerPrint().containsKey(key)) {
                return false;
            }
            if (individualBreakAttack.getFingerPrint().containsKey(key)
                    && !individualBreakAttack
                            .getFingerPrint()
                            .get(key)
                            .equals(doNotBreakAttackGroup.getFingerPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    static boolean identical(Attack candidate, Attack attack2) {
        return candidate.getFingerPrint().equals(attack2.getFingerPrint());
    }

    static boolean similarIsh(
            Attack noBreakGroup, Attack breakGroup, Attack noBreak, Attack doBreak) {

        for (String key : noBreakGroup.getFingerPrint().keySet()) {
            Object noBreakVal = noBreakGroup.getFingerPrint().get(key);

            if (key.equals("input_reflections") && noBreakVal.equals(Attack.INCALCULABLE)) {
                continue;
            }

            // if this attribute is inconsistent, make sure it's different this time
            if (!breakGroup.getFingerPrint().containsKey(key)) {
                if (!noBreakVal.equals(doBreak.getFingerPrint().get(key))) {
                    return false;
                }
            } else if (!noBreakVal.equals(breakGroup.getFingerPrint().get(key))) {
                // if it's consistent and different, these responses definitely don't match
                return false;
            }
        }

        for (String key : breakGroup.getFingerPrint().keySet()) {
            if (!noBreakGroup.getFingerPrint().containsKey(key)) {
                // if this attribute is inconsistent, make sure it's different this time
                if (!breakGroup
                        .getFingerPrint()
                        .get(key)
                        .equals(noBreak.getFingerPrint().get(key))) {
                    return false;
                }
            }
        }

        return true;
    }

    static int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        return StringUtils.countMatches(response.toString(), match.toString());
    }
}
