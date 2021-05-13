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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.util.Objects;
import java.util.function.Function;
import javax.script.ScriptException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class HttpFuzzerProcessorScriptProxy implements HttpFuzzerProcessorScript {

    private static final Logger LOG = LogManager.getLogger(HttpFuzzerProcessorScriptProxy.class);
    private final ScriptWrapper scriptWrapper;
    private final HttpFuzzerProcessorScript script;

    public static HttpFuzzerProcessorScriptProxy create(ScriptWrapper scriptWrapper)
            throws Exception {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript == null) {
            throw new IllegalStateException("The ExtensionScript is not enabled.");
        }

        HttpFuzzerProcessorScript script =
                extensionScript.getInterface(scriptWrapper, HttpFuzzerProcessorScript.class);
        if (script != null) {
            return new HttpFuzzerProcessorScriptProxy(scriptWrapper, script);
        }

        extensionScript.handleFailedScriptInterface(
                scriptWrapper,
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.scriptProcessor.warnNoInterface.message",
                        scriptWrapper.getName()));
        throw new IllegalArgumentException("The script does not implement the expected interface.");
    }

    private HttpFuzzerProcessorScriptProxy(
            ScriptWrapper scriptWrapper, HttpFuzzerProcessorScript script) {
        this.scriptWrapper = Objects.requireNonNull(scriptWrapper);
        this.script = Objects.requireNonNull(script);
    }

    @Override
    public void processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message)
            throws ScriptException {
        script.processMessage(utils, message);
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult result)
            throws ScriptException {
        return script.processResult(utils, result);
    }

    @Override
    public String[] getRequiredParamsNames() {
        return readScriptParams(
                HttpFuzzerProcessorScript::getRequiredParamsNames, "getRequiredParamsNames");
    }

    private String[] readScriptParams(
            Function<HttpFuzzerProcessorScript, String[]> paramsReader, String methodName) {
        try {
            return paramsReader.apply(script);
        } catch (Exception e) {
            LOG.debug(
                    "An error occurred while calling '{}' on script '{}': {}",
                    methodName,
                    scriptWrapper.getName(),
                    e.getMessage(),
                    e);
        }
        return HttpFuzzerProcessorScript.EMPTY_PARAMS;
    }

    @Override
    public String[] getOptionalParamsNames() {
        return readScriptParams(
                HttpFuzzerProcessorScript::getOptionalParamsNames, "getOptionalParamsNames");
    }
}
