/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ProcessingException;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/**
 * A {@code HttpFuzzerMessageProcessor} that delegates the processing to a {@code HttpFuzzerProcessorScript}.
 *
 * @see HttpFuzzerMessageProcessor
 * @see HttpFuzzerProcessorScript
 */
public class FuzzerHttpMessageScriptProcessorAdapter implements HttpFuzzerMessageProcessor {

    private final ScriptWrapper scriptWrapper;
    private boolean initialised;
    private HttpFuzzerProcessorScript scriptProcessor;

    public FuzzerHttpMessageScriptProcessorAdapter(ScriptWrapper scriptWrapper) {
        if (scriptWrapper == null) {
            throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
        }
        if (!HttpFuzzerProcessorScript.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
            throw new IllegalArgumentException("Parameter scriptWrapper must wrap a script of type \""
                    + HttpFuzzerProcessorScript.TYPE_NAME + "\".");
        }
        this.scriptWrapper = scriptWrapper;
    }

    @Override
    public String getName() {
        return scriptWrapper.getName();
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) throws ProcessingException {
        if (!initialised) {
            initialise();
            initialised = true;
        }

        if (scriptProcessor == null) {
            throw new ProcessingException("Script '" + scriptWrapper.getName()
                    + "' does not implement the expected interface (HttpFuzzerProcessorScript).");
        }

        try {
            scriptProcessor.processMessage(utils, message);
        } catch (Exception e) {
            // N.B. Catch exception (instead of ScriptException) since Nashorn throws RuntimeException.
            // The same applies to all other script try-catch blocks.
            // For example, when a variable or function is not defined it throws:
            // jdk.nashorn.internal.runtime.ECMAException
            handleScriptException(e);
        }
        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult fuzzResult) throws ProcessingException {
        if (!initialised) {
            initialise();
            initialised = true;
        }

        if (scriptProcessor == null) {
            throw new ProcessingException("Script '" + scriptWrapper.getName()
                    + "' does not implement the expected interface (HttpFuzzerProcessorScript).");
        }

        try {
            return scriptProcessor.processResult(utils, fuzzResult);
        } catch (Exception e) {
            // N.B. Catch exception (instead of ScriptException) since Nashorn throws RuntimeException.
            // The same applies to all other script try-catch blocks.
            // For example, when a variable or function is not defined it throws:
            // jdk.nashorn.internal.runtime.ECMAException
            handleScriptException(e);
        }
        return true;
    }

    private void initialise() throws ProcessingException {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            try {
                scriptProcessor = extensionScript.getInterface(scriptWrapper, HttpFuzzerProcessorScript.class);
            } catch (Exception e) {
                handleScriptException(e);
            }
        }
    }

    private void handleScriptException(Exception cause) throws ProcessingException {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, cause);
            extensionScript.setEnabled(scriptWrapper, false);
        }

        throw new ProcessingException("Failed to process the payload:", cause);
    }

}
