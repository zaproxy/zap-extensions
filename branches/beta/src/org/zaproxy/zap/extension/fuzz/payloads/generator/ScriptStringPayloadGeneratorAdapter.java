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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultStringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code PayloadGenerator} that generates payloads using a script.
 *
 */
public class ScriptStringPayloadGeneratorAdapter implements StringPayloadGenerator {

    private final ScriptWrapper scriptWrapper;

    public ScriptStringPayloadGeneratorAdapter(ScriptWrapper scriptWrapper) {
        if (scriptWrapper == null) {
            throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
        }
        if (!ScriptStringPayloadGenerator.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
            throw new IllegalArgumentException("Parameter scriptWrapper must wrap a script of type \""
                    + ScriptStringPayloadGenerator.TYPE_NAME + "\".");
        }
        this.scriptWrapper = scriptWrapper;
    }

    @Override
    public long getNumberOfPayloads() {
        return UNKNOWN_NUMBER_OF_PAYLOADS;
    }

    @Override
    public ResettableAutoCloseableIterator<StringPayload> iterator() {
        return new ScriptPayloadGeneratorIterator(scriptWrapper);
    }

    @Override
    public ScriptStringPayloadGeneratorAdapter copy() {
        return this;
    }

    private static class ScriptPayloadGeneratorIterator implements ResettableAutoCloseableIterator<StringPayload> {

        private final ScriptWrapper scriptWrapper;
        private boolean initialised;
        private ScriptStringPayloadGenerator scriptPayloadGenerator;

        public ScriptPayloadGeneratorIterator(ScriptWrapper scriptWrapper) {
            this.scriptWrapper = scriptWrapper;
        }

        @Override
        public boolean hasNext() {
            if (!initialised) {
                initialise();
                initialised = true;
            }

            if (scriptPayloadGenerator == null) {
                throw new PayloadGenerationException("Script '" + scriptWrapper.getName()
                        + "' does not implement the expected interface (ScriptStringPayloadGenerator).");
            }
            try {
                return scriptPayloadGenerator.hasNext();
            } catch (Exception e) {
                // N.B. Catch exception (instead of ScriptException) since Nashorn throws RuntimeException.
                // The same applies to all other script try-catch blocks.
                // For example, when a variable or function is not defined it throws:
                // jdk.nashorn.internal.runtime.ECMAException
                handleScriptException(e);
            }

            // Unreachable code, handleScriptException(Exception) throws PayloadGenerationException.
            return false;
        }

        @Override
        public StringPayload next() {
            try {
                return new DefaultStringPayload(scriptPayloadGenerator.next());
            } catch (Exception e) {
                handleScriptException(e);
            }

            // Unreachable code, handleScriptException(Exception) throws PayloadGenerationException.
            return null;
        }

        @Override
        public void remove() {
        }

        @Override
        public void reset() {
            try {
                scriptPayloadGenerator.reset();
            } catch (Exception e) {
                handleScriptException(e);
            }
        }

        @Override
        public void close() throws Exception {
            try {
                scriptPayloadGenerator.close();
            } catch (Exception e) {
                handleScriptException(e);
            }
        }

        private void initialise() throws PayloadGenerationException {
            ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
            if (extensionScript != null) {
                try {
                    scriptPayloadGenerator = extensionScript.getInterface(scriptWrapper, ScriptStringPayloadGenerator.class);
                } catch (Exception e) {
                    handleScriptException(e);
                }
            }
        }

        private void handleScriptException(Exception cause) throws PayloadGenerationException {
            ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
            if (extensionScript != null) {
                extensionScript.setError(scriptWrapper, cause);
                extensionScript.setEnabled(scriptWrapper, false);
            }

            throw new PayloadGenerationException("Failed to generate the payload:", cause);
        }

    }
}
