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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/** A {@code PayloadGenerator} that generates payloads using a script. */
public class ScriptStringPayloadGeneratorAdapter implements StringPayloadGenerator {

    private static final Logger LOGGER =
            LogManager.getLogger(ScriptStringPayloadGeneratorAdapter.class);

    private final ScriptWrapper scriptWrapper;
    private boolean initialised;
    private ScriptStringPayloadGenerator scriptPayloadGenerator;
    private long numberOfPayloads;

    public ScriptStringPayloadGeneratorAdapter(ScriptWrapper scriptWrapper) {
        if (scriptWrapper == null) {
            throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
        }
        if (!ScriptStringPayloadGenerator.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
            throw new IllegalArgumentException(
                    "Parameter scriptWrapper must wrap a script of type \""
                            + ScriptStringPayloadGenerator.TYPE_NAME
                            + "\".");
        }
        this.scriptWrapper = scriptWrapper;
        this.numberOfPayloads = -1;
    }

    public ScriptStringPayloadGeneratorAdapter(
            ScriptWrapper scriptWrapper, ScriptStringPayloadGenerator script) {
        if (scriptWrapper == null) {
            throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
        }
        if (!ScriptStringPayloadGenerator.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
            throw new IllegalArgumentException(
                    "Parameter scriptWrapper must wrap a script of type \""
                            + ScriptStringPayloadGenerator.TYPE_NAME
                            + "\".");
        }
        if (script == null) {
            throw new IllegalArgumentException("Parameter script must not be null.");
        }
        this.scriptWrapper = scriptWrapper;
        this.scriptPayloadGenerator = script;
        this.initialised = true;
        this.numberOfPayloads = -1;
    }

    @Override
    public long getNumberOfPayloads() {
        if (numberOfPayloads >= 0) {
            return numberOfPayloads;
        }

        if (!initialised) {
            try {
                scriptPayloadGenerator = initialiseImpl(scriptWrapper);
            } catch (Exception e) {
                LOGGER.warn("Failed to initialise '{}':", scriptWrapper.getName(), e);
            }
            initialised = true;
        }

        if (scriptPayloadGenerator != null) {
            try {
                numberOfPayloads = scriptPayloadGenerator.getNumberOfPayloads();
                return numberOfPayloads;
            } catch (Exception e) {
                LOGGER.warn(
                        "Failed to obtain number of payloads from script '{}':",
                        scriptWrapper.getName(),
                        e);
            }
        }
        return UNKNOWN_NUMBER_OF_PAYLOADS;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        if (scriptPayloadGenerator != null) {
            ScriptPayloadGeneratorIterator iterator =
                    new ScriptPayloadGeneratorIterator(scriptWrapper, scriptPayloadGenerator);
            // Use the existing script instance just once, otherwise it could be used by multiple
            // iterators at the same time
            scriptPayloadGenerator = null;
            return iterator;
        }
        return new ScriptPayloadGeneratorIterator(scriptWrapper);
    }

    @Override
    public ScriptStringPayloadGeneratorAdapter copy() {
        return new ScriptStringPayloadGeneratorAdapter(scriptWrapper);
    }

    private static class ScriptPayloadGeneratorIterator
            implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final ScriptWrapper scriptWrapper;
        private boolean initialised;
        private ScriptStringPayloadGenerator scriptPayloadGenerator;

        public ScriptPayloadGeneratorIterator(ScriptWrapper scriptWrapper) {
            this.scriptWrapper = scriptWrapper;
        }

        public ScriptPayloadGeneratorIterator(
                ScriptWrapper scriptWrapper, ScriptStringPayloadGenerator scriptPayloadGenerator) {
            this.scriptWrapper = scriptWrapper;
            this.scriptPayloadGenerator = scriptPayloadGenerator;
            this.initialised = true;
        }

        @Override
        public boolean hasNext() {
            if (!initialised) {
                scriptPayloadGenerator = initialise(scriptWrapper);
                initialised = true;
            }

            if (scriptPayloadGenerator == null) {
                throw new PayloadGenerationException(
                        "Script '"
                                + scriptWrapper.getName()
                                + "' does not implement the expected interface (ScriptStringPayloadGenerator).");
            }
            try {
                return scriptPayloadGenerator.hasNext();
            } catch (Exception e) {
                // N.B. Catch exception (instead of ScriptException) since Nashorn throws
                // RuntimeException.
                // The same applies to all other script try-catch blocks.
                // For example, when a variable or function is not defined it throws:
                // jdk.nashorn.internal.runtime.ECMAException
                handleScriptException(scriptWrapper, e);
            }

            // Unreachable code, handleScriptException(Exception) throws PayloadGenerationException.
            return false;
        }

        @Override
        public DefaultPayload next() {
            try {
                return new DefaultPayload(scriptPayloadGenerator.next());
            } catch (Exception e) {
                handleScriptException(scriptWrapper, e);
            }

            // Unreachable code, handleScriptException(Exception) throws PayloadGenerationException.
            return null;
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            try {
                scriptPayloadGenerator.reset();
            } catch (Exception e) {
                handleScriptException(scriptWrapper, e);
            }
        }

        @Override
        public void close() {
            try {
                scriptPayloadGenerator.close();
            } catch (Exception e) {
                handleScriptException(scriptWrapper, e);
            }
        }

        private static ScriptStringPayloadGenerator initialise(ScriptWrapper scriptWrapper)
                throws PayloadGenerationException {
            try {
                return initialiseImpl(scriptWrapper);
            } catch (Exception e) {
                handleScriptException(scriptWrapper, e);
            }
            return null;
        }

        private static void handleScriptException(ScriptWrapper scriptWrapper, Exception cause)
                throws PayloadGenerationException {
            handleScriptExceptionImpl(scriptWrapper, cause);
            throw new PayloadGenerationException("Failed to generate the payload:", cause);
        }
    }

    private static ScriptStringPayloadGenerator initialiseImpl(ScriptWrapper scriptWrapper)
            throws Exception {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            return extensionScript.getInterface(scriptWrapper, ScriptStringPayloadGenerator.class);
        }
        return null;
    }

    private static void handleScriptExceptionImpl(ScriptWrapper scriptWrapper, Exception cause) {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, cause);
            extensionScript.setEnabled(scriptWrapper, false);
        }
    }
}
