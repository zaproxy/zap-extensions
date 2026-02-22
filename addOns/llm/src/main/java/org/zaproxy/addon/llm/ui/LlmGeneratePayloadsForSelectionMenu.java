/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.llm.actions.LlmZapActionType;
import org.zaproxy.zap.model.DefaultTextHttpMessageLocation;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.view.messagecontainer.SelectableContentMessageContainer;

@SuppressWarnings("serial")
public class LlmGeneratePayloadsForSelectionMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private static final int MAX_BODY_CHARS = 4000;

    private final LlmChatPanelProvider llmChatPanelProvider;
    private final String promptKey;
    private final List<LlmZapActionType> allowedActionTypes;
    private final boolean requireConfirmation;
    private SelectableContentMessageContainer<HttpMessage> lastInvoker;
    private DefaultTextHttpMessageLocation lastSelection;

    public LlmGeneratePayloadsForSelectionMenu(
            LlmChatPanelProvider llmChatPanelProvider,
            String titleKey,
            String promptKey,
            List<LlmZapActionType> allowedActionTypes,
            boolean requireConfirmation) {
        super(Constant.messages.getString(titleKey));
        this.llmChatPanelProvider = llmChatPanelProvider;
        this.promptKey = promptKey;
        this.allowedActionTypes = allowedActionTypes;
        this.requireConfirmation = requireConfirmation;
        addActionListener(e -> performAction());
    }

    @Override
    public boolean isEnableForMessageContainer(
            org.zaproxy.zap.view.messagecontainer.MessageContainer<?> invoker) {
        lastInvoker = null;
        lastSelection = null;

        if (llmChatPanelProvider == null) {
            return false;
        }
        if (!(invoker instanceof SelectableContentMessageContainer<?> selectable)) {
            return false;
        }
        if (!HttpMessage.class.isAssignableFrom(invoker.getMessageClass())) {
            return false;
        }
        @SuppressWarnings("unchecked")
        SelectableContentMessageContainer<HttpMessage> httpInvoker =
                (SelectableContentMessageContainer<HttpMessage>) selectable;

        if (httpInvoker.isEmpty()) {
            setEnabled(false);
            return true;
        }

        MessageLocation selection = httpInvoker.getSelection();
        if (!(selection instanceof DefaultTextHttpMessageLocation textSelection)) {
            setEnabled(false);
            return true;
        }

        if (!HttpMessageLocation.Location.REQUEST_HEADER.equals(textSelection.getLocation())
                && !HttpMessageLocation.Location.REQUEST_BODY.equals(textSelection.getLocation())) {
            return false;
        }

        if (StringUtils.isBlank(textSelection.getValue())) {
            setEnabled(false);
            return true;
        }

        lastInvoker = httpInvoker;
        lastSelection = textSelection;
        setEnabled(true);
        return true;
    }

    private void performAction() {
        if (lastInvoker == null || lastSelection == null) {
            return;
        }

        HttpMessage message = lastInvoker.getMessage();
        if (message == null) {
            return;
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "zap_request_selection");
        payload.put("method", message.getRequestHeader().getMethod());
        payload.put("uri", message.getRequestHeader().getURI().toString());
        if (message.getHistoryRef() != null) {
            payload.put("history_id", message.getHistoryRef().getHistoryId());
        }

        Map<String, Object> selection = new LinkedHashMap<>();
        selection.put("location", toActionLocation(lastSelection.getLocation()));
        selection.put("start", lastSelection.getStart());
        selection.put("end", lastSelection.getEnd());
        selection.put("text", lastSelection.getValue());
        payload.put("selection", selection);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("header", message.getRequestHeader().toString());
        String body = message.getRequestBody().toString();
        if (body.length() > MAX_BODY_CHARS) {
            request.put("body", body.substring(0, MAX_BODY_CHARS));
            request.put("body_truncated", true);
            request.put("body_length", body.length());
        } else {
            request.put("body", body);
            request.put("body_truncated", false);
            request.put("body_length", body.length());
        }
        payload.put("request", request);

        llmChatPanelProvider.focusLlmChat();
        LlmChatPanel panel = llmChatPanelProvider.openNewChatTab();
        if (panel == null) {
            return;
        }
        panel.sendPayloadGenerationRequest(
                payload, promptKey, allowedActionTypes, requireConfirmation);
    }

    private static String toActionLocation(HttpMessageLocation.Location location) {
        if (HttpMessageLocation.Location.REQUEST_HEADER.equals(location)) {
            return "request_header";
        }
        if (HttpMessageLocation.Location.REQUEST_BODY.equals(location)) {
            return "request_body";
        }
        return "unknown";
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("llm.aiassisted.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return false;
    }
}
