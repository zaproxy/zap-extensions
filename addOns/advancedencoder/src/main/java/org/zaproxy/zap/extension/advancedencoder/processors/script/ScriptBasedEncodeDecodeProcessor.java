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
package org.zaproxy.zap.extension.advancedencoder.processors.script;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.advancedencoder.ExtensionAdvancedEncoder;
import org.zaproxy.zap.extension.advancedencoder.processors.EncodeDecodeProcessor;
import org.zaproxy.zap.extension.advancedencoder.processors.EncodeDecodeResult;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ScriptBasedEncodeDecodeProcessor implements EncodeDecodeProcessor {

    private static final Logger LOGGER = Logger.getLogger(ScriptBasedEncodeDecodeProcessor.class);

    private String scriptName;

    private String cachedScriptHash = "";
    private EncodeDecodeScript cachedScript;

    public ScriptBasedEncodeDecodeProcessor(String scriptName) {
        if (scriptName == null) throw new IllegalArgumentException("scriptName is null");
        this.scriptName = scriptName;
    }

    private static ScriptWrapper findScriptByName(String scriptName) {
        for (ScriptWrapper scriptWrapper : ExtensionAdvancedEncoder.getEncodeDecodeScripts()) {
            if (StringUtils.equals(scriptWrapper.getName(), scriptName)) {
                return scriptWrapper;
            }
        }
        return null;
    }

    @Override
    public EncodeDecodeResult process(String value) throws Exception {
        ScriptWrapper scriptWrapper = findScriptByName(scriptName);
        if (scriptWrapper == null) {
            LOGGER.debug("Script with name '" + scriptName + "' not found");
            return null;
        }

        if (!scriptWrapper.isEnabled()) {
            LOGGER.debug("Script with name '" + scriptWrapper.getName() + "' not enabled");
            return null;
        }

        try {
            EncodeDecodeScript script = evaluateScript(scriptWrapper);
            if (script != null) {
                LOGGER.debug("Calling encode/decode script " + scriptWrapper.getName());
                return script.process(value);
            } else {
                String errorMsg =
                        Constant.messages.getString(
                                "ascan.scripts.interface.active.error", scriptWrapper.getName());
                ExtensionAdvancedEncoder.getExtensionScript()
                        .handleFailedScriptInterface(scriptWrapper, errorMsg);
                throw new Exception(errorMsg);
            }
        } catch (Exception e) {
            ExtensionAdvancedEncoder.getExtensionScript().handleScriptException(scriptWrapper, e);
            throw e;
        }
    }

    private EncodeDecodeScript evaluateScript(ScriptWrapper scriptWrapper)
            throws javax.script.ScriptException, java.io.IOException {

        String md5AsHex = getMd5HashAsHex(scriptWrapper.getContents());
        if (StringUtils.equals(cachedScriptHash, md5AsHex)) {
            return cachedScript;
        }

        ExtensionScript extensionScript = ExtensionAdvancedEncoder.getExtensionScript();
        if (extensionScript == null) {
            return null;
        }

        EncodeDecodeScript encodeDecodeScript =
                extensionScript.getInterface(scriptWrapper, EncodeDecodeScript.class);
        cachedScriptHash = md5AsHex;
        cachedScript = encodeDecodeScript;
        return encodeDecodeScript;
    }

    private String getMd5HashAsHex(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return new String(Hex.encodeHex(md.digest(value.getBytes())));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
