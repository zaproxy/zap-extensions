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
package org.zaproxy.addon.llm.services;

import dev.langchain4j.model.chat.listener.ChatModelErrorContext;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.chat.listener.ChatModelRequestContext;
import dev.langchain4j.model.chat.listener.ChatModelResponseContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.OutputPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;

public class LlmResponseHandler implements ChatModelListener {

    private static final Logger LOGGER = LogManager.getLogger(LlmResponseHandler.class);

    private OutputPanel outputPanel;
    private String outputTabName;

    public LlmResponseHandler(String outputTabName) {
        this.outputTabName = outputTabName;
        if (View.isInitialised()) {
            outputPanel = View.getSingleton().getOutputPanel();
        }
    }

    @Override
    public void onRequest(ChatModelRequestContext requestContext) {
        output(
                Constant.messages.getString("llm.output.prefix.request"),
                requestContext.chatRequest().messages().get(0).toString());
    }

    @Override
    public void onResponse(ChatModelResponseContext responseContext) {
        LOGGER.info("Token usage = {} ", responseContext.chatResponse().tokenUsage());
        output(
                Constant.messages.getString("llm.output.prefix.response"),
                responseContext.chatResponse().aiMessage().text());
    }

    @Override
    public void onError(ChatModelErrorContext errorContext) {
        LOGGER.error("LLM Error : {} ", errorContext.error().getMessage());
        output(
                Constant.messages.getString("llm.output.prefix.error"),
                errorContext.error().getMessage());

        setFocus();

        throw new RuntimeException(
                String.format("LLM Error : %s", errorContext.error().getMessage()));
    }

    public void setFocus() {
        if (outputPanel != null) {
            outputPanel.setTabFocus();
            if (outputPanel instanceof TabbedOutputPanel tabbedOutputPanel) {
                tabbedOutputPanel.setSelectedOutputTab(outputTabName);
            }
        }
    }

    private void output(String prefix, String msg) {
        if (outputPanel != null) {
            outputPanel.appendAsync("\n" + prefix + "\n" + msg, outputTabName);
        }
    }
}
