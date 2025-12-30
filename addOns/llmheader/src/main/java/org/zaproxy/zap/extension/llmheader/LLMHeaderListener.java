/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.llmheader;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.network.HttpSenderListener;

public class LLMHeaderListener implements HttpSenderListener {

    private final LLMHeaderOptions options;
    private final ExtensionAlert extAlert;
    private final ExecutorService executor;
    private final Random random;

    public LLMHeaderListener(LLMHeaderOptions options, ExtensionAlert extAlert) {
        this.options = options;
        this.extAlert = extAlert;
        this.executor = Executors.newFixedThreadPool(2);
        this.random = new Random();
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        if (!options.isEnabled())
            return;
        if (initiator != HttpSender.PROXY_INITIATOR
                && initiator != HttpSender.MANUAL_REQUEST_INITIATOR)
            return;

        if (shouldScan()) {
            executor.submit(() -> analyze(msg));
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        // Do nothing
    }

    private boolean shouldScan() {
        int mode = options.getMode();
        if (mode == LLMHeaderOptions.MODE_MANUAL)
            return false;
        if (mode == LLMHeaderOptions.MODE_AUTO_ALL)
            return true;
        if (mode == LLMHeaderOptions.MODE_AUTO_SAMPLE) {
            return random.nextInt(100) < options.getSamplingRate();
        }
        return false;
    }

    private void analyze(HttpMessage msg) {
        HttpHeader header = msg.getRequestHeader();
        Map<String, String> headers = HeaderAnonymizer.anonymize(header, options.isAnonymize());

        List<LLMIssue> issues = GeminiClient.analyze(
                headers,
                options.getBridgeUrl(),
                options.getGeminiKey(),
                options.getGeminiModel());

        if (!issues.isEmpty() && options.isAutoAlert()) {
            AlertBuilder.buildAlerts(extAlert, msg, issues);
        }
    }
}
