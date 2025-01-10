/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.predefined;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

public class MorseEncoder implements EncodeDecodeProcessor {

    private static final Pattern VALID_CHARS = Pattern.compile("[A-Z0-9 ]*");
    protected static final Map<Character, String> CHARACTER_MAP =
            Map.ofEntries(
                    Map.entry('A', ".-"),
                    Map.entry('B', "-..."),
                    Map.entry('C', "-.-."),
                    Map.entry('D', "-.."),
                    Map.entry('E', "."),
                    Map.entry('F', "..-."),
                    Map.entry('G', "--."),
                    Map.entry('H', "...."),
                    Map.entry('I', ".."),
                    Map.entry('J', ".---"),
                    Map.entry('K', "-.-"),
                    Map.entry('L', ".-.."),
                    Map.entry('M', "--"),
                    Map.entry('N', "-."),
                    Map.entry('O', "---"),
                    Map.entry('P', ".--."),
                    Map.entry('Q', "--.-"),
                    Map.entry('R', ".-."),
                    Map.entry('S', "..."),
                    Map.entry('T', "-"),
                    Map.entry('U', "..-"),
                    Map.entry('V', "...-"),
                    Map.entry('W', ".--"),
                    Map.entry('X', "-..-"),
                    Map.entry('Y', "-.--"),
                    Map.entry('Z', "--.."),

                    // Replace space as slash which is word separator
                    // https://morsecode.world/international/translator.html
                    Map.entry(' ', "/"),
                    Map.entry('1', ".----"),
                    Map.entry('2', "..---"),
                    Map.entry('3', "...--"),
                    Map.entry('4', "....-"),
                    Map.entry('5', "....."),
                    Map.entry('6', "-...."),
                    Map.entry('7', "--..."),
                    Map.entry('8', "---.."),
                    Map.entry('9', "----."),
                    Map.entry('0', "-----"));

    private static final MorseEncoder INSTANCE = new MorseEncoder();

    @Override
    public EncodeDecodeResult process(String value) {
        value = value.toUpperCase(Locale.ROOT);
        if (!VALID_CHARS.matcher(value).matches()) {
            return EncodeDecodeResult.withError(
                    Constant.messages.getString("encoder.predefined.morse.error"));
        }

        StringBuilder out = new StringBuilder(value.length() * 3);
        for (Character c : value.toCharArray()) {
            String outSeq = CHARACTER_MAP.get(c);
            if (outSeq.equals("/")) {
                // This is a word break, remove the previous trailing space
                out.deleteCharAt(out.length() - 1);
                out.append(outSeq);
            } else {
                out.append(outSeq).append(' ');
            }
        }
        return new EncodeDecodeResult(out.toString().trim());
    }

    public static MorseEncoder getSingleton() {
        return INSTANCE;
    }
}
