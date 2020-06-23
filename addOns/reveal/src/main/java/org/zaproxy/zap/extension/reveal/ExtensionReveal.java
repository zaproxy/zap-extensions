/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.reveal;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Iterator;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.OutputDocument;
import net.htmlparser.jericho.Source;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.ZapToggleButton;

public class ExtensionReveal extends ExtensionAdaptor implements ProxyListener {

    private static final Logger logger = Logger.getLogger(ExtensionReveal.class);

    public static final String NAME = "ExtensionReveal";
    public static final int PROXY_LISTENER_ORDER = 10;

    private static final String ATT_DISABLED = "DISABLED";
    private static final String ATT_READONLY = "READONLY";
    private static final String ATT_TYPE = "TYPE";
    private static final String TYPE_HIDDEN = "HIDDEN";

    private boolean reveal;

    private RevealParam revealParam;
    private RevealAPI revealAPI;

    private ZapToggleButton revealButton;
    private JToolBar.Separator toolBarSeparator;

    public ExtensionReveal() {
        super(NAME);
        this.setOrder(18);
    }

    @Override
    public void init() {
        super.init();

        reveal = false;
        revealParam = new RevealParam();

        revealAPI = new RevealAPI(this);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addProxyListener(this);
        extensionHook.addOptionsParamSet(revealParam);

        if (getView() != null) {
            ExtensionHookView extensionHookView = extensionHook.getHookView();
            extensionHookView.addMainToolBarComponent(getRevealButton());
            extensionHookView.addMainToolBarComponent(getToolBarSeparator());
        }

        extensionHook.addApiImplementor(revealAPI);
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        setReveal(revealParam.isReveal());
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    void setReveal(boolean reveal) {
        if (this.reveal == reveal) {
            return;
        }
        this.reveal = reveal;

        revealParam.setReveal(reveal);
        try {
            revealParam.getConfig().save();
        } catch (ConfigurationException e) {
            logger.error(e.getMessage(), e);
        }

        if (revealButton != null) {
            revealButton.setSelected(reveal);
        }
    }

    boolean isReveal() {
        return reveal;
    }

    private JToggleButton getRevealButton() {
        if (revealButton == null) {
            revealButton = new ZapToggleButton();
            revealButton.setIcon(
                    new ImageIcon(
                            ExtensionReveal.class.getResource(
                                    "resources/icons/044.png"))); // 'light off' icon
            revealButton.setToolTipText(Constant.messages.getString("reveal.button.enable"));
            revealButton.setSelectedIcon(
                    new ImageIcon(
                            ExtensionReveal.class.getResource(
                                    "resources/icons/043.png"))); // 'light on' icon
            revealButton.setSelectedToolTipText(
                    Constant.messages.getString("reveal.button.disable"));

            revealButton.addItemListener(
                    new ItemListener() {

                        @Override
                        public void itemStateChanged(ItemEvent e) {
                            setReveal(ItemEvent.SELECTED == e.getStateChange());
                        }
                    });
        }
        return revealButton;
    }

    private JToolBar.Separator getToolBarSeparator() {
        if (toolBarSeparator == null) {
            toolBarSeparator = new JToolBar.Separator();
        }
        return toolBarSeparator;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (reveal) {
            revealFields(msg);
        }
        return true;
    }

    private void revealFields(HttpMessage msg) {
        boolean changed = false;
        String response = msg.getResponseBody().toString();
        Source src = new Source(response);
        OutputDocument outputDocument = new OutputDocument(src);

        List<Element> formElements = src.getAllElements(HTMLElementName.FORM);

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags
            logger.debug("Found " + formElements.size() + " forms");

            for (Element formElement : formElements) {
                List<Element> elements = formElement.getAllElements();

                if (elements != null && elements.size() > 0) {
                    // Loop through all of the elements
                    logger.debug("Found " + elements.size() + " inputs");
                    for (Element element : elements) {
                        Attributes atts = element.getAttributes();

                        if (atts != null && atts.size() > 0) {
                            Iterator<Attribute> iter = atts.iterator();
                            while (iter.hasNext()) {
                                Attribute att = iter.next();
                                if (ATT_DISABLED.equalsIgnoreCase(att.getName())
                                        || ATT_READONLY.equalsIgnoreCase(att.getName())
                                        || (ATT_TYPE.equalsIgnoreCase(att.getName())
                                                && TYPE_HIDDEN.equalsIgnoreCase(att.getValue()))) {
                                    logger.debug(
                                            "Removing "
                                                    + att.getName()
                                                    + ": "
                                                    + response.substring(
                                                            att.getBegin(), att.getEnd()));
                                    outputDocument.remove(att);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (changed) {
            msg.setResponseBody(outputDocument.toString());
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("reveal.desc");
    }
}
