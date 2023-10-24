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
package org.zaproxy.zap.extension.replacer;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An add-on which provides an easy way to replace strings in requests and responses. TODO Implement
 * for contexts as well
 *
 * @author psiinon
 */
public class ExtensionReplacer extends ExtensionAdaptor implements HttpSenderListener {

    private static final Pattern TOKEN_PATTERN =
            Pattern.compile("(?<=\\{\\{)[A-Z]+[\\|0-9]*(?=\\}\\})");
    private static final Pattern INTEGER_PATTERN = Pattern.compile("^\\d+$");
    private static final String RINT_TOKEN = "RINT";
    private static final String UUID_TOKEN = "UUID";
    private static final String TICKS_TOKEN = "TICKS";

    public static final String NAME = "ExtensionReplacer";

    // The i18n prefix
    protected static final String PREFIX = "replacer";

    private OptionsReplacerPanel optionsReplacerPanel;
    private ReplacerParam params;
    private ZapMenuItem replacerMenuItem;
    private static final Logger LOGGER = LogManager.getLogger(ExtensionReplacer.class);

    public ExtensionReplacer() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(new ReplacerAPI(this));
        extensionHook.addOptionsParamSet(getParams());
        HttpSender.addListener(this);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOptionsReplacerPanel());
            extensionHook.getHookMenu().addToolsMenuItem(getReplacerMenuItem());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        HttpSender.removeListener(this);
    }

    private OptionsReplacerPanel getOptionsReplacerPanel() {
        if (optionsReplacerPanel == null) {
            optionsReplacerPanel = new OptionsReplacerPanel();
        }
        return optionsReplacerPanel;
    }

    public ReplacerParam getParams() {
        if (params == null) {
            params = new ReplacerParam();
        }
        return params;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    private ZapMenuItem getReplacerMenuItem() {
        if (replacerMenuItem == null) {
            replacerMenuItem =
                    new ZapMenuItem(
                            PREFIX + ".topmenu.tools.shortcut",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_R, 0, false));

            replacerMenuItem.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(OptionsReplacerPanel.PANEL_NAME));
        }
        return replacerMenuItem;
    }

    private static boolean contains(String original, String match, Pattern p) {
        if (p != null) {
            return p.matcher(original).find();
        }

        return original.contains(match);
    }

    private static String replace(
            String original, String match, Pattern p, String replacement, boolean tokenProcessing) {
        LOGGER.debug("Static Replacement function.");

        if (tokenProcessing) {
            List<String> tokens = parseReplacementTokens(replacement);

            if (!tokens.isEmpty()) {
                LOGGER.debug("Token replacement(s) detected.");

                for (String token : tokens) {
                    String toReplace = "\\{\\{" + token.replace("|", "\\|") + "\\}\\}";

                    LOGGER.debug("Token replacement: {}", token);

                    if (token.startsWith(RINT_TOKEN)) {
                        int minVal = 0;
                        int maxVal = Integer.MAX_VALUE;

                        String[] repl = token.split("\\|");

                        if (repl.length == 2) {
                            maxVal = parseInt(repl[1], maxVal);
                        } else if (repl.length == 3) {
                            minVal = parseInt(repl[1], minVal);
                            maxVal = parseInt(repl[2], maxVal);
                        }

                        Random rand = new Random();
                        String newValue = String.valueOf(rand.nextInt(maxVal - minVal) + minVal);
                        LOGGER.debug("replacement = replace({},{})", toReplace, newValue);
                        replacement = replacement.replaceFirst(toReplace, newValue);
                    } else if (token.equals(TICKS_TOKEN)) {
                        String ticks = String.valueOf(System.currentTimeMillis());
                        LOGGER.debug("replacement = replace({},{})", toReplace, ticks);
                        replacement = replacement.replaceFirst(toReplace, ticks);
                    } else if (token.equals(UUID_TOKEN)) {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.debug("replacement = replace({}, {})", toReplace, uuid);
                        replacement = replacement.replaceFirst(toReplace, uuid);
                    }
                }
            }
            LOGGER.debug("Pattern is null? {}", (p == null));
            LOGGER.debug("Final replacement: {} => {}", match, replacement);
        }

        if (p != null) {
            return p.matcher(original).replaceAll(replacement);
        }
        return original.replace(match, replacement);
    }

    private static int parseInt(String value, int defaultValue) {
        if (INTEGER_PATTERN.matcher(value).matches()) {
            return Integer.valueOf(value);
        }
        return defaultValue;
    }

    static List<String> parseReplacementTokens(String data) {
        List<String> replacementTokens = new ArrayList<>();
        Matcher m = TOKEN_PATTERN.matcher(data);

        while (m.find()) {
            String key = m.group();
            if (key.equals(TICKS_TOKEN) || key.equals(UUID_TOKEN) || key.startsWith(RINT_TOKEN)) {
                replacementTokens.add(key);
            }
        }

        return replacementTokens;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender httpSender) {
        boolean hostHeaderChanged = false;
        for (ReplacerParamRule rule : this.getParams().getRules()) {
            if (rule.isEnabled()
                    && rule.appliesToInitiator(initiator)
                    && rule.matchesUrl(msg.getRequestHeader().getURI().toString())) {
                Pattern p = null;
                if (rule.isMatchRegex()) {
                    p = Pattern.compile(rule.getMatchString());
                }
                switch (rule.getMatchType()) {
                    case REQ_HEADER:
                        LOGGER.debug(
                                "Add in request header: {} : {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        hostHeaderChanged |=
                                HttpRequestHeader.HOST.equalsIgnoreCase(rule.getMatchString());
                        if (rule.getReplacement().length() == 0) {
                            // Remove the header
                            msg.getRequestHeader().setHeader(rule.getMatchString(), null);
                        } else {
                            msg.getRequestHeader()
                                    .setHeader(rule.getMatchString(), rule.getEscapedReplacement());
                        }
                        break;
                    case REQ_HEADER_STR:
                        LOGGER.debug(
                                "Replace in request header: {} with {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        String header = msg.getRequestHeader().toString();
                        if (contains(header, rule.getMatchString(), p)) {
                            header =
                                    replace(
                                            header,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement(),
                                            rule.isTokenProcessingEnabled());
                            try {
                                List<HttpHeaderField> oldHostHeaders = getHostHeaders(msg);
                                msg.setRequestHeader(new HttpRequestHeader(header));
                                hostHeaderChanged |= !oldHostHeaders.equals(getHostHeaders(msg));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        break;
                    case REQ_BODY_STR:
                        LOGGER.debug(
                                "Add in request body: {} : {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        String body = msg.getRequestBody().toString();
                        if (contains(body, rule.getMatchString(), p)) {
                            body =
                                    replace(
                                            body,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement(),
                                            rule.isTokenProcessingEnabled());
                            msg.getRequestBody().setBody(body);
                            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                        }
                        break;
                    case RESP_HEADER:
                    case RESP_HEADER_STR:
                    case RESP_BODY_STR:
                        // Ignore response rules here
                        LOGGER.debug("Ignore response rule {}", rule.getDescription());
                        break;
                }
            }
        }

        if (hostHeaderChanged) {
            Map<String, Object> properties;
            if (msg.getUserObject() instanceof Map<?, ?>) {
                properties = (Map<String, Object>) msg.getUserObject();
            } else {
                properties = new HashMap<>();
                msg.setUserObject(properties);
            }

            properties.put("host.normalization", Boolean.FALSE);
        }
    }

    private static List<HttpHeaderField> getHostHeaders(HttpMessage msg) {
        return msg.getRequestHeader().getHeaders().stream()
                .filter(e -> HttpRequestHeader.HOST.equalsIgnoreCase(e.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender httpSender) {
        for (ReplacerParamRule rule : this.getParams().getRules()) {
            if (rule.isEnabled()
                    && rule.appliesToInitiator(initiator)
                    && rule.matchesUrl(msg.getRequestHeader().getURI().toString())) {
                Pattern p = null;
                if (rule.isMatchRegex()) {
                    p = Pattern.compile(rule.getMatchString());
                }
                switch (rule.getMatchType()) {
                    case REQ_HEADER:
                    case REQ_HEADER_STR:
                    case REQ_BODY_STR:
                        // Ignore request rules here
                        LOGGER.debug("Ignore request rule {}", rule.getDescription());
                        break;
                    case RESP_HEADER:
                        LOGGER.debug(
                                "Add in response header: {} : {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        if (rule.getReplacement().length() == 0) {
                            // Remove the header
                            msg.getResponseHeader().setHeader(rule.getMatchString(), null);
                        } else {
                            msg.getResponseHeader()
                                    .setHeader(rule.getMatchString(), rule.getEscapedReplacement());
                        }
                        break;
                    case RESP_HEADER_STR:
                        LOGGER.debug(
                                "Replace in response header: {} with {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        String header = msg.getResponseHeader().toString();
                        if (contains(header, rule.getMatchString(), p)) {
                            header =
                                    replace(
                                            header,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement(),
                                            rule.isTokenProcessingEnabled());
                            try {
                                msg.setResponseHeader(new HttpResponseHeader(header));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        break;
                    case RESP_BODY_STR:
                        LOGGER.debug(
                                "Replace in response body: {} with {}",
                                rule.getMatchString(),
                                rule.getReplacement());
                        String body = msg.getResponseBody().toString();
                        if (contains(body, rule.getMatchString(), p)) {
                            body =
                                    replace(
                                            body,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement(),
                                            rule.isTokenProcessingEnabled());
                            msg.getResponseBody().setBody(body);
                            msg.getResponseHeader()
                                    .setContentLength(msg.getResponseBody().length());
                        }
                        break;
                }
            }
        }
    }
}
