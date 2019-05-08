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
package org.zaproxy.zap.extension.fuzz.payloads.processor;

import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/**
 * A {@code DefaultPayloadProcessor} that delegates the processing of the value of a {@code
 * DefaultPayload} to a {@code DefaultPayloadProcessorScript}.
 *
 * @see DefaultPayload
 * @see DefaultPayloadProcessor
 * @see ScriptStringPayloadProcessor
 */
public class ScriptStringPayloadProcessorAdapter implements DefaultPayloadProcessor {

    private final ScriptWrapper scriptWrapper;
    private boolean initialised;
    private ScriptStringPayloadProcessor scriptProcessor;

    public ScriptStringPayloadProcessorAdapter(ScriptWrapper scriptWrapper) {
        if (scriptWrapper == null) {
            throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
        }
        if (!ScriptStringPayloadProcessor.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
            throw new IllegalArgumentException(
                    "Parameter scriptWrapper must wrap a script of type \""
                            + ScriptStringPayloadProcessor.TYPE_NAME
                            + "\".");
        }
        this.scriptWrapper = scriptWrapper;
    }

    @Override
    public DefaultPayload process(DefaultPayload payload) throws PayloadProcessingException {
        if (!initialised) {
            initialise();
            initialised = true;
        }

        if (scriptProcessor == null) {
            throw new PayloadProcessingException(
                    "Script '"
                            + scriptWrapper.getName()
                            + "' does not implement the expected interface (ScriptStringPayloadProcessor).");
        }

        try {
            String value = scriptProcessor.process(payload.getValue());
            if (value != null) {
                payload.setValue(value);
            }
        } catch (Exception e) {
            // N.B. Catch exception (instead of ScriptException) since Nashorn throws
            // RuntimeException.
            // The same applies to all other script try-catch blocks.
            // For example, when a variable or function is not defined it throws:
            // jdk.nashorn.internal.runtime.ECMAException
            handleScriptException(e);
        }
        return payload;
    }

    private void initialise() throws PayloadProcessingException {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            try {
                scriptProcessor =
                        extensionScript.getInterface(
                                scriptWrapper, ScriptStringPayloadProcessor.class);
            } catch (Exception e) {
                handleScriptException(e);
            }
        }
    }

    private void handleScriptException(Exception cause) throws PayloadProcessingException {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, cause);
            extensionScript.setEnabled(scriptWrapper, false);
        }

        throw new PayloadProcessingException("Failed to process the payload:", cause);
    }

    @Override
    public PayloadProcessor<DefaultPayload> copy() {
        return new ScriptStringPayloadProcessorAdapter(scriptWrapper);
    }
}
