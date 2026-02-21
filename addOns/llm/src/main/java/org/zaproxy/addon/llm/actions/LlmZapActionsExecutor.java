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
package org.zaproxy.addon.llm.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.DefaultTextHttpMessageLocation;
import org.zaproxy.zap.model.HttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.network.HttpRequestBody;

public class LlmZapActionsExecutor {

    public record ApplyResult(int appliedCount, List<String> errors) {}

    private static final int MAX_FUZZ_PAYLOADS = 200;
    private static final String EXT_REQUESTER_CLASS =
            "org.zaproxy.addon.requester.ExtensionRequester";
    private static final String EXT_HTTP_FUZZER_CLASS =
            "org.zaproxy.zap.extension.fuzz.httpfuzzer.ExtensionHttpFuzzer";

    public ApplyResult apply(List<LlmZapAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return new ApplyResult(0, List.of());
        }

        int applied = 0;
        List<String> errors = new ArrayList<>();
        for (LlmZapAction action : actions) {
            if (action == null || action.type() == null) {
                continue;
            }

            switch (action.type()) {
                case SET_HISTORY_NOTE -> {
                    HistoryReference href = loadHistoryRef(action.historyId(), errors);
                    if (href == null) {
                        continue;
                    }
                    String note = StringUtils.defaultString(action.note());
                    href.setNote(note);
                    applied++;
                }
                case ADD_HISTORY_TAGS -> {
                    HistoryReference href = loadHistoryRef(action.historyId(), errors);
                    if (href == null) {
                        continue;
                    }
                    if (action.tags() != null) {
                        List<String> existingTags = href.getTags();
                        for (String tag : action.tags()) {
                            String trimmed = StringUtils.trimToEmpty(tag);
                            if (trimmed.isEmpty()) {
                                continue;
                            }
                            if (!existingTags.contains(trimmed)) {
                                href.addTag(trimmed);
                            }
                        }
                    }
                    applied++;
                }
                case OPEN_REQUESTER_DIALOG -> {
                    ApplyResult r = openRequesterWithPayload(action, true);
                    if (!r.errors().isEmpty()) {
                        errors.addAll(r.errors());
                    } else {
                        applied++;
                    }
                }
                case OPEN_REQUESTER_TAB -> {
                    ApplyResult r = openRequesterWithPayload(action, false);
                    if (!r.errors().isEmpty()) {
                        errors.addAll(r.errors());
                    } else {
                        applied++;
                    }
                }
                case OPEN_FUZZER -> {
                    ApplyResult r = openFuzzerWithPayloads(action);
                    if (!r.errors().isEmpty()) {
                        errors.addAll(r.errors());
                    } else {
                        applied++;
                    }
                }
                default -> errors.add("Unsupported action: " + action.type());
            }
        }
        return new ApplyResult(applied, errors);
    }

    private static HistoryReference loadHistoryRef(int historyId, List<String> errors) {
        if (historyId <= 0) {
            errors.add("Missing or invalid history_id: " + historyId);
            return null;
        }
        try {
            return new HistoryReference(historyId);
        } catch (Exception e) {
            errors.add("Failed to load history_id " + historyId + ": " + e.getMessage());
            return null;
        }
    }

    private static HttpMessage loadOrBuildMessage(LlmZapAction action, List<String> errors) {
        if (action.historyId() > 0) {
            HistoryReference href = loadHistoryRef(action.historyId(), errors);
            if (href == null) {
                return null;
            }
            try {
                HttpMessage msg = href.getHttpMessage();
                if (msg == null) {
                    errors.add("No HTTP message available for history_id " + action.historyId());
                    return null;
                }
                return msg.cloneRequest();
            } catch (Exception e) {
                errors.add(
                        "Failed to load HTTP message for history_id "
                                + action.historyId()
                                + ": "
                                + e.getMessage());
                return null;
            }
        }

        LlmZapRequestData request = action.request();
        if (request == null || StringUtils.isBlank(request.header())) {
            errors.add("Missing request data for action " + action.type());
            return null;
        }

        try {
            HttpRequestHeader header = new HttpRequestHeader(request.header());
            HttpRequestBody body = new HttpRequestBody();
            if (request.body() != null) {
                body.setBody(request.body());
            }
            HttpMessage msg = new HttpMessage(header, body);
            return msg;
        } catch (HttpMalformedHeaderException e) {
            errors.add("Invalid request header: " + e.getMessage());
            return null;
        }
    }

    private static String replaceRange(String original, int start, int end, String replacement) {
        int s = Math.max(0, Math.min(start, original.length()));
        int e = Math.max(0, Math.min(end, original.length()));
        if (e < s) {
            int t = s;
            s = e;
            e = t;
        }
        return original.substring(0, s) + StringUtils.defaultString(replacement) + original.substring(e);
    }

    private ApplyResult openRequesterWithPayload(LlmZapAction action, boolean openDialog) {
        List<String> errors = new ArrayList<>();
        HttpMessage msg = loadOrBuildMessage(action, errors);
        if (msg == null) {
            return new ApplyResult(0, errors);
        }

        if (action.location() == null) {
            errors.add("Missing location for action " + action.type());
            return new ApplyResult(0, errors);
        }

        try {
            if (HttpMessageLocation.Location.REQUEST_HEADER.equals(action.location())) {
                String headerStr = msg.getRequestHeader().toString();
                String newHeaderStr =
                        replaceRange(headerStr, action.start(), action.end(), action.payload());
                msg.setRequestHeader(new HttpRequestHeader(newHeaderStr));
            } else if (HttpMessageLocation.Location.REQUEST_BODY.equals(action.location())) {
                String bodyStr = msg.getRequestBody().toString();
                msg.setRequestBody(
                        replaceRange(bodyStr, action.start(), action.end(), action.payload()));
                msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            } else {
                errors.add("Unsupported location for requester action: " + action.location());
                return new ApplyResult(0, errors);
            }
        } catch (HttpMalformedHeaderException e) {
            errors.add("Failed to set request header: " + e.getMessage());
            return new ApplyResult(0, errors);
        } catch (Exception e) {
            errors.add("Failed to apply payload: " + e.getMessage());
            return new ApplyResult(0, errors);
        }

        Object extRequester =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtensionByClassName(EXT_REQUESTER_CLASS);
        if (extRequester == null) {
            errors.add("Requester add-on is not available/enabled.");
            return new ApplyResult(0, errors);
        }

        AtomicReference<Exception> openError = new AtomicReference<>();
        Runnable open =
                () -> {
                    try {
                        if (openDialog) {
                            extRequester
                                    .getClass()
                                    .getMethod("displayMessage", Message.class)
                                    .invoke(extRequester, msg);
                        } else {
                            extRequester
                                    .getClass()
                                    .getMethod("newRequesterPane", HttpMessage.class)
                                    .invoke(extRequester, msg);
                        }
                    } catch (Exception e) {
                        openError.set(e);
                    }
                };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                open.run();
            } else {
                SwingUtilities.invokeAndWait(open);
            }
        } catch (Exception e) {
            openError.set(e);
        }
        if (openError.get() != null) {
            errors.add("Failed to open Requester: " + openError.get().getMessage());
            return new ApplyResult(0, errors);
        }

        return new ApplyResult(1, List.of());
    }

    private ApplyResult openFuzzerWithPayloads(LlmZapAction action) {
        List<String> errors = new ArrayList<>();
        HttpMessage msg = loadOrBuildMessage(action, errors);
        if (msg == null) {
            return new ApplyResult(0, errors);
        }

        if (action.location() == null) {
            errors.add("Missing location for action " + action.type());
            return new ApplyResult(0, errors);
        }

        List<String> payloads =
                action.payloads() != null ? new ArrayList<>(action.payloads()) : new ArrayList<>();
        payloads.removeIf(StringUtils::isBlank);
        if (payloads.isEmpty()) {
            errors.add("No payloads provided for fuzzer action.");
            return new ApplyResult(0, errors);
        }
        if (payloads.size() > MAX_FUZZ_PAYLOADS) {
            payloads = payloads.subList(0, MAX_FUZZ_PAYLOADS);
        }

        String selectedValue = "";
        try {
            if (HttpMessageLocation.Location.REQUEST_HEADER.equals(action.location())) {
                String headerStr = msg.getRequestHeader().toString();
                if (action.start() >= 0
                        && action.end() >= action.start()
                        && action.end() <= headerStr.length()) {
                    selectedValue = headerStr.substring(action.start(), action.end());
                }
            } else if (HttpMessageLocation.Location.REQUEST_BODY.equals(action.location())) {
                String bodyStr = msg.getRequestBody().toString();
                if (action.start() >= 0
                        && action.end() >= action.start()
                        && action.end() <= bodyStr.length()) {
                    selectedValue = bodyStr.substring(action.start(), action.end());
                }
            }
        } catch (Exception ignore) {
            // best-effort
        }
        MessageLocation location =
                new DefaultTextHttpMessageLocation(
                        action.location(),
                        Math.max(0, action.start()),
                        Math.max(0, action.end()),
                        selectedValue);

        Object extHttpFuzzer =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtensionByClassName(EXT_HTTP_FUZZER_CLASS);
        if (extHttpFuzzer == null) {
            errors.add("HTTP Fuzzer add-on is not available/enabled.");
            return new ApplyResult(0, errors);
        }

        final List<String> finalPayloads = payloads;
        AtomicReference<Exception> openError = new AtomicReference<>();
        Runnable open =
                () -> {
                    try {
                        extHttpFuzzer
                                .getClass()
                                .getMethod(
                                        "showFuzzerDialogWithPayloads",
                                        HttpMessage.class,
                                        MessageLocation.class,
                                        List.class)
                                .invoke(extHttpFuzzer, msg, location, finalPayloads);
                    } catch (Exception e) {
                        openError.set(e);
                    }
                };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                open.run();
            } else {
                SwingUtilities.invokeAndWait(open);
            }
        } catch (Exception e) {
            openError.set(e);
        }
        if (openError.get() != null) {
            errors.add("Failed to open Fuzzer: " + openError.get().getMessage());
            return new ApplyResult(0, errors);
        }

        return new ApplyResult(1, List.of());
    }
}
