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
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
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

    public static final String NAME = "ExtensionReplacer";

    // The i18n prefix
    protected static final String PREFIX = "replacer";

    private OptionsReplacerPanel optionsReplacerPanel;
    private ReplacerParam params;
    private ZapMenuItem replacerMenuItem;
    private static final Logger LOGGER = Logger.getLogger(ExtensionReplacer.class);

    public ExtensionReplacer() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(new ReplacerAPI(this));
        extensionHook.addOptionsParamSet(getParams());
        HttpSender.addListener(this);

        if (getView() != null) {
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

    protected ReplacerParam getParams() {
        if (params == null) {
            params = new ReplacerParam();
        }
        return params;
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
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(OptionsReplacerPanel.PANEL_NAME);
                        }
                    });
        }
        return replacerMenuItem;
    }

    private static boolean contains(String original, String match, Pattern p) {
        if (p != null) {
            return p.matcher(original).find();
        }

        return original.contains(match);
    }

    private static String replace(String original, String match, Pattern p, String replacement) {
        if (p != null) {
            return p.matcher(original).replaceAll(replacement);
        }
        return original.replace(match, replacement);
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender httpSender) {
        for (ReplacerParamRule rule : this.getParams().getRules()) {
            if (rule.isEnabled() && rule.appliesToInitiator(initiator)) {
                Pattern p = null;
                if (rule.isMatchRegex()) {
                    p = Pattern.compile(rule.getMatchString());
                }
                switch (rule.getMatchType()) {
                    case REQ_HEADER:
                        LOGGER.debug(
                                "Add in request header: "
                                        + rule.getMatchString()
                                        + " : "
                                        + rule.getReplacement());
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
                                "Replace in request header: "
                                        + rule.getMatchString()
                                        + " with "
                                        + rule.getReplacement());
                        String header = msg.getRequestHeader().toString();
                        if (contains(header, rule.getMatchString(), p)) {
                            header =
                                    replace(
                                            header,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement());
                            try {
                                msg.setRequestHeader(new HttpRequestHeader(header));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        break;
                    case REQ_BODY_STR:
                        LOGGER.debug(
                                "Add in request body: "
                                        + rule.getMatchString()
                                        + " : "
                                        + rule.getReplacement());
                        String body = msg.getRequestBody().toString();
                        if (contains(body, rule.getMatchString(), p)) {
                            body =
                                    replace(
                                            body,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement());
                            msg.getRequestBody().setBody(body);
                            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                        }
                        break;
                    case RESP_HEADER:
                    case RESP_HEADER_STR:
                    case RESP_BODY_STR:
                        // Ignore response rules here
                        LOGGER.debug("Ignore response rule " + rule.getDescription());
                        break;
                }
            }
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender httpSender) {
        for (ReplacerParamRule rule : this.getParams().getRules()) {
            if (rule.isEnabled() && rule.appliesToInitiator(initiator)) {
                Pattern p = null;
                if (rule.isMatchRegex()) {
                    p = Pattern.compile(rule.getMatchString());
                }
                switch (rule.getMatchType()) {
                    case REQ_HEADER:
                    case REQ_HEADER_STR:
                    case REQ_BODY_STR:
                        // Ignore request rules here
                        LOGGER.debug("Ignore request rule " + rule.getDescription());
                        break;
                    case RESP_HEADER:
                        LOGGER.debug(
                                "Add in response header: "
                                        + rule.getMatchString()
                                        + " : "
                                        + rule.getReplacement());
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
                                "Replace in response header: "
                                        + rule.getMatchString()
                                        + " with "
                                        + rule.getReplacement());
                        String header = msg.getResponseHeader().toString();
                        if (contains(header, rule.getMatchString(), p)) {
                            header =
                                    replace(
                                            header,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement());
                            try {
                                msg.setResponseHeader(new HttpResponseHeader(header));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        break;
                    case RESP_BODY_STR:
                        LOGGER.debug(
                                "Replace in response body: "
                                        + rule.getMatchString()
                                        + " with "
                                        + rule.getReplacement());
                        String body = msg.getResponseBody().toString();
                        if (contains(body, rule.getMatchString(), p)) {
                            body =
                                    replace(
                                            body,
                                            rule.getMatchString(),
                                            p,
                                            rule.getEscapedReplacement());
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
