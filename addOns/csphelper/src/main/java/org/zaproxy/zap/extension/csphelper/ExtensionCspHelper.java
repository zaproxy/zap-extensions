/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.csphelper;

import java.awt.CardLayout;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import javax.swing.ImageIcon;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.OutputPanel;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionCspHelper extends ExtensionAdaptor implements ProxyListener {

    public static final String NAME = "ExtensionCspHelper";
    protected static final String PREFIX = "csphelper";
    private static final String RESOURCE = "/org/zaproxy/zap/extension/csphelper/resources";
    private static final ImageIcon ICON =
            new ImageIcon(
                    ExtensionCspHelper.class.getResource(
                            RESOURCE + "/help/contents/images/shield-tick.png"));

    private ZapMenuItem menu;
    private RightClickMsgMenu popupMsgMenu;
    private AbstractPanel statusPanel;
    private OutputPanel outputPanel;

    private Map<String, CSP> policyForSite = new HashMap<String, CSP>();

    private CspHelperAPI api;
    private CspHelper helper;
    private CspHelperPassiveScanner passiveScan;

    private static final Logger LOGGER = Logger.getLogger(ExtensionCspHelper.class);

    /*
       * TODO:
       	Add dialog to display CSP header (read only, but copyable)
    Option to enforce CSP header (currently just uses report-only)
    Add icon to Sites tree when CSP helper on for site (https://github.com/yusukekamiyamane/fugue-icons/blob/master/icons/shield.png)
    Display reports in new tab?
    Much more testing :P
    CH: Integrate with https://csp-evaluator.withgoogle.com/
    CH: CSP-enabled sites from psiinon: addons.mozilla.org login.mozilla.org testpilot.firefox.com
    Salvation lib: https://github.com/shapesecurity/salvation
       */
    public ExtensionCspHelper() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        helper = new CspHelper(this);

        extensionHook.addProxyListener(this);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenu());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());

            ExtensionPassiveScan extensionPassiveScan =
                    (ExtensionPassiveScan)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionPassiveScan.NAME);
            if (extensionPassiveScan != null) {
                passiveScan = new CspHelperPassiveScanner(helper);
                extensionPassiveScan.addPassiveScanner(passiveScan);
            }
        }

        api = new CspHelperAPI(this);
        API.getInstance().registerApiImplementor(api);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        API.getInstance().removeApiImplementor(api);
        ExtensionPassiveScan extensionPassiveScan =
                (ExtensionPassiveScan)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionPassiveScan.NAME);
        if (extensionPassiveScan != null) {
            extensionPassiveScan.removePassiveScanner(passiveScan);
        }

        super.unload();
    }

    public static String siteFromUrl(String url) {
        // Assume http(s):// ...
        String site;
        int ind = url.indexOf("/", url.indexOf("//") + 2);
        if (ind > 0) {
            site = url.substring(0, ind);
        } else {
            site = url;
        }
        if (site.startsWith("//")) {
            site = site.substring(2);
        }
        return site;
    }

    public String getCspHeader(String url) {
        String site = siteFromUrl(url);
        if (isEnabledForSite(site)) {
            return getCspForUrl(site).generate();
        } else {
            return null;
        }
    }

    public boolean isEnabledForSite(String url) {
        String site = siteFromUrl(url);
        CSP csp = this.policyForSite.get(site);
        if (csp != null) {
            return csp.isEnabled();
        } else {
            return false;
        }
    }

    public void enableForSite(String url, boolean enable) {
        String site = siteFromUrl(url);
        if (enable) {
            if (!this.policyForSite.containsKey(site)) {
                LOGGER.debug("CSP enabled for " + site);
                CSP csp = new CSP(site);
                csp.setReportUrl(API.getInstance().getCallBackUrl(api, site));
                this.policyForSite.put(site, csp);
            } else {
                this.policyForSite.get(site).setEnabled(true);
            }
        } else {
            LOGGER.debug("CSP disabled for " + site);
            this.policyForSite.get(site).setEnabled(false);
        }
    }

    public CSP getCspForUrl(String url) {
        return this.policyForSite.get(siteFromUrl(url));
    }

    public static String sha256(String base) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            return "sha256-" + Base64.encodeBytes(hash);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    protected OutputPanel getOutputPanel() {
        if (outputPanel == null) {
            outputPanel = new OutputPanel();
            outputPanel.setFont(FontUtils.getFont("Dialog"));
            outputPanel.setEnabled(false);
            outputPanel.append(Constant.messages.getString(PREFIX + ".panel.msg"));
        }
        return outputPanel;
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            statusPanel.add(getOutputPanel());
        }
        return statusPanel;
    }

    private RightClickMsgMenu getPopupMsgMenu() {
        if (popupMsgMenu == null) {
            popupMsgMenu =
                    new RightClickMsgMenu(
                            this, Constant.messages.getString(PREFIX + ".context.menu"));
        }
        return popupMsgMenu;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
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
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        HttpRequestHeader reqHeader = msg.getRequestHeader();
        String referer = msg.getRequestHeader().getHeader(HttpHeader.REFERER);
        if (isEnabledForSite(reqHeader.getURI().toString())
                || (referer != null && isEnabledForSite(referer))) {
            // Dont cache it
            if (!reqHeader.isEmpty() && reqHeader.isText()) {
                String ifModifed = reqHeader.getHeader(HttpHeader.IF_MODIFIED_SINCE);
                if (ifModifed != null) {
                    reqHeader.setHeader(HttpHeader.IF_MODIFIED_SINCE, null);
                }
                String ifNoneMatch = reqHeader.getHeader(HttpHeader.IF_NONE_MATCH);
                if (ifNoneMatch != null) {
                    reqHeader.setHeader(HttpHeader.IF_NONE_MATCH, null);
                }
            }
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (isEnabledForSite(msg.getRequestHeader().getURI().toString())) {
            // Inject it :)
            // TODO option to use non report only!
            msg.getResponseHeader()
                    .addHeader(
                            "Content-Security-Policy-Report-Only",
                            getCspHeader(msg.getRequestHeader().getURI().toString()));
        }
        return true;
    }
}
