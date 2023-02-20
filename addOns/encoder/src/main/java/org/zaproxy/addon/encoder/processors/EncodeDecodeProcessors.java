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
import java.util.Objects;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64Decoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64Encoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64UrlDecoder;
import org.zaproxy.addon.encoder.processors.predefined.Base64UrlEncoder;
import org.zaproxy.addon.encoder.processors.predefined.FullHtmlStringEncoder;
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
import org.zaproxy.addon.encoder.processors.predefined.PowerShellEncoder;
import org.zaproxy.addon.encoder.processors.predefined.Sha1Hasher;
import org.zaproxy.addon.encoder.processors.predefined.Sha256Hasher;
import org.zaproxy.addon.encoder.processors.predefined.UnicodeDecoder;
import org.zaproxy.addon.encoder.processors.predefined.UnicodeEncoder;
import org.zaproxy.addon.encoder.processors.predefined.UrlDecoder;
import org.zaproxy.addon.encoder.processors.predefined.UrlEncoder;
import org.zaproxy.addon.encoder.processors.predefined.utility.LowerCase;
import org.zaproxy.addon.encoder.processors.predefined.utility.RemoveWhitespace;
import org.zaproxy.addon.encoder.processors.predefined.utility.Reverse;
import org.zaproxy.addon.encoder.processors.predefined.utility.UpperCase;
import org.zaproxy.addon.encoder.processors.script.ScriptBasedEncodeDecodeProcessor;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class EncodeDecodeProcessors {

    public static final String PREDEFINED_PREFIX = "encoder.predefined.";
    private static List<EncodeDecodeProcessorItem> predefinedProcessors = new ArrayList<>();

    static {
        addPredefined("base64decode", Base64Decoder.getSingleton());
        addPredefined("base64encode", Base64Encoder.getSingleton());

        addPredefined("base64urldecode", Base64UrlDecoder.getSingleton());
        addPredefined("base64urlencode", Base64UrlEncoder.getSingleton());

        addPredefined("hexdecode", HexStringDecoder.getSingleton());
        addPredefined("hexencode", HexStringEncoder.getSingleton());

        addPredefined("htmldecode", HtmlStringDecoder.getSingleton());
        addPredefined("htmlencode", HtmlStringEncoder.getSingleton());
        addPredefined("fullhtmlencode", FullHtmlStringEncoder.getSingleton());

        addPredefined("javascriptdecode", JavaScriptStringDecoder.getSingleton());
        addPredefined("javascriptencode", JavaScriptStringEncoder.getSingleton());

        addPredefined("unicodedecode", UnicodeDecoder.getSingleton());
        addPredefined("unicodeencode", UnicodeEncoder.getSingleton());

        addPredefined("urldecode", UrlDecoder.getSingleton());
        addPredefined("urlencode", UrlEncoder.getSingleton());

        addPredefined("fullurldecode", FullUrlDecoder.getSingleton());
        addPredefined("fullurlencode", FullUrlEncoder.getSingleton());

        addPredefined("md5hash", Md5Hasher.getSingleton());
        addPredefined("sha1hash", Sha1Hasher.getSingleton());
        addPredefined("sha256hash", Sha256Hasher.getSingleton());

        addPredefined("illegalutf8with2byteencoder", IllegalUTF8With2ByteEncoder.getSingleton());
        addPredefined("illegalutf8with3byteencoder", IllegalUTF8With3ByteEncoder.getSingleton());
        addPredefined("illegalutf8with4byteencoder", IllegalUTF8With4ByteEncoder.getSingleton());

        addPredefined("removewhitespace", RemoveWhitespace.getSingleton());
        addPredefined("reverse", Reverse.getSingleton());
        addPredefined("lowercase", LowerCase.getSingleton());
        addPredefined("uppercase", UpperCase.getSingleton());
        addPredefined("powershellencode", PowerShellEncoder.getSingleton());
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
            scriptProcessors.computeIfAbsent(
                    scriptName, k -> createItemFromScriptWrapper(scriptWrapper));
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
            if (Objects.equals(processor.getId(), name)) {
                return processor;
            }
        }
        return null;
    }

    public EncodeDecodeResult process(String processorId, String value) throws Exception {
        EncodeDecodeProcessorItem processor = findProcessorItemById(processorId);
        return processor.getProcessor().process(value);
    }

    public static List<EncodeDecodeProcessorItem> getPredefinedProcessors() {
        return predefinedProcessors;
    }
}
