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

import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

public class MorseDecoder implements EncodeDecodeProcessor {

    private static final Pattern VALID_CHARS = Pattern.compile("[// .-]*");
    private static final Map<String, Character> CHARACTER_MAP =
            MorseEncoder.CHARACTER_MAP.entrySet().stream()
                    .collect(Collectors.toUnmodifiableMap(Map.Entry::getValue, Map.Entry::getKey));

    private static final MorseDecoder INSTANCE = new MorseDecoder();

    @Override
    public EncodeDecodeResult process(String value) {
        if (value.isBlank()) {
            return new EncodeDecodeResult("");
        }
        // Replace em dash with standard hyphen
        value = value.replace("—", "-");
        if (!VALID_CHARS.matcher(value).matches()) {
            return EncodeDecodeResult.withError(
                    Constant.messages.getString("encoder.predefined.morse.error"));
        }

        StringBuilder out = new StringBuilder(value.length() / 2);
        for (String words : value.split("/")) {
            for (String character : words.split(" ")) {
                out.append(CHARACTER_MAP.get(character));
            }
            out.append(' ');
        }
        return new EncodeDecodeResult(out.toString().trim());
    }

    public static MorseDecoder getSingleton() {
        return INSTANCE;
    }
}
