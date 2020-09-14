/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64Decoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64Encoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64UrlDecoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64UrlEncoder;
import org.zaproxy.addon.encoder.processors.predefined.FullUrlDecoder;
import org.zaproxy.addon.encoder.processors.predefined.FullUrlEncoder;
import org.zaproxy.addon.encoder.processors.predefined.HexStringDecoder;
import org.zaproxy.addon.encoder.processors.predefined.HexStringEncoder;
import org.zaproxy.addon.encoder.processors.predefined.HtmlStringDecoder;
import org.zaproxy.addon.encoder.processors.predefined.HtmlStringEncoder;
import org.zaproxy.addon.encoder.processors.predefined.IllegalUTF8With2ByteEncoder;
import org.zaproxy.addon.encoder.processors.predefined.IllegalUTF8With3ByteEncoder;
import org.zaproxy.addon.encoder.processors.predefined.IllegalUTF8With4ByteEncoder;
import org.zaproxy.addon.encoder.processors.predefined.JavaScriptStringDecoder;
import org.zaproxy.addon.encoder.processors.predefined.JavaScriptStringEncoder;
import org.zaproxy.addon.encoder.processors.predefined.Md5Hasher;
import org.zaproxy.addon.encoder.processors.predefined.Sha1Hasher;
import org.zaproxy.addon.encoder.processors.predefined.Sha256Hasher;
import org.zaproxy.addon.encoder.processors.predefined.UnicodeDecoder;
import org.zaproxy.addon.encoder.processors.predefined.UnicodeEncoder;
import org.zaproxy.addon.encoder.processors.predefined.UrlDecoder;
import org.zaproxy.addon.encoder.processors.predefined.UrlEncoder;
import org.zaproxy.addon.encoder.processors.script.ScriptBasedEncodeDecodeProcessor;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class EncodeDecodeProcessors {

    public static final String PREDEFINED_PREFIX = "encoder.predefined.";
    private static List<EncodeDecodeProcessorItem> predefinedProcessors = new ArrayList<>();

    static {
        addPredefined("base64decode", new Base64Decoder());
        addPredefined("base64encode", new Base64Encoder());

        addPredefined("base64urldecode", new Base64UrlDecoder());
        addPredefined("base64urlencode", new Base64UrlEncoder());

        addPredefined("hexdecode", new HexStringDecoder());
        addPredefined("hexencode", new HexStringEncoder());

        addPredefined("htmldecode", new HtmlStringDecoder());
        addPredefined("htmlencode", new HtmlStringEncoder());

        addPredefined("javascriptdecode", new JavaScriptStringDecoder());
        addPredefined("javascriptencode", new JavaScriptStringEncoder());

        addPredefined("unicodedecode", new UnicodeDecoder());
        addPredefined("unicodeencode", new UnicodeEncoder());

        addPredefined("urldecode", new UrlDecoder());
        addPredefined("urlencode", new UrlEncoder());

        addPredefined("fullurldecode", new FullUrlDecoder());
        addPredefined("fullurlencode", new FullUrlEncoder());

        addPredefined("md5hash", new Md5Hasher());
        addPredefined("sha1hash", new Sha1Hasher());
        addPredefined("sha256hash", new Sha256Hasher());

        addPredefined("illegalutf8with2byteencoder", new IllegalUTF8With2ByteEncoder());
        addPredefined("illegalutf8with3byteencoder", new IllegalUTF8With3ByteEncoder());
        addPredefined("illegalutf8with4byteencoder", new IllegalUTF8With4ByteEncoder());
    }

    private Map<String, EncodeDecodeProcessorItem> scriptProcessors = new HashMap<>();

    private static void addPredefined(String id, EncodeDecodeProcessor processor) {
        addPredefined(PREDEFINED_PREFIX + id, PREDEFINED_PREFIX + id, processor);
    }

    private static void addPredefined(String id, String i18nKey, EncodeDecodeProcessor processor) {
        predefinedProcessors.add(
                new EncodeDecodeProcessorItem(id, Constant.messages.getString(i18nKey), processor));
    }

    public List<EncodeDecodeProcessorItem> getProcessorItems() {
        List<EncodeDecodeProcessorItem> processors = new ArrayList<>();
        processors.addAll(getScriptProcessors());
        processors.addAll(predefinedProcessors);

        return processors.stream()
                .sorted(Comparator.comparing(EncodeDecodeProcessorItem::getName))
                .collect(Collectors.toList());
    }

    private List<EncodeDecodeProcessorItem> getScriptProcessors() {
        List<String> encodeDecodeScripts = new ArrayList<>();

        // Insert new
        for (ScriptWrapper scriptWrapper : ExtensionEncoder.getEncodeDecodeScripts()) {
            String scriptName = scriptWrapper.getName();
            encodeDecodeScripts.add(scriptName);
            if (!scriptProcessors.containsKey(scriptName)) {
                scriptProcessors.put(scriptName, createItemFromScriptWrapper(scriptWrapper));
            }
        }

        // Delete not existing
        for (String key : scriptProcessors.keySet()) {
            if (!encodeDecodeScripts.contains(key)) {
                scriptProcessors.remove(key);
            }
        }

        return scriptProcessors.values().stream().collect(Collectors.toList());
    }

    private EncodeDecodeProcessorItem createItemFromScriptWrapper(ScriptWrapper ws) {
        String scriptName = ws.getName();
        ScriptBasedEncodeDecodeProcessor processor =
                new ScriptBasedEncodeDecodeProcessor(ws.getName());
        return new EncodeDecodeProcessorItem(scriptName, scriptName, processor);
    }

    public EncodeDecodeProcessorItem findProcessorItemById(String name) {
        for (EncodeDecodeProcessorItem processor : getProcessorItems()) {
            if (StringUtils.equals(processor.getId(), name)) {
                return processor;
            }
        }
        return null;
    }

    public EncodeDecodeResult process(String processorId, String value) throws Exception {
        EncodeDecodeProcessorItem processor = findProcessorItemById(processorId);
        return processor.getProcessor().process(value);
    }
}
