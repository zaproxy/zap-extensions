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
package org.zaproxy.zap.extension.revisit;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.swing.tree.TreeNode;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter.Type;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.model.ParameterParser;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;

/*
 * Revisit a site at any time in the past using the session history
 */
public class ExtensionRevisit extends ExtensionAdaptor implements ProxyListener {

    /*
     * Misc notes:
     *
     * Possible future enhancements:
     * 		The revisited requests end up in the History, which isnt ideal
     * 		Options screen with:
     * 			Footer on/off
     * 			User specified url & form params to ignore
     * 		Right click on history to set start/end date?
     * 		Option to adjust the dates rather than turn off and on?
     *		Switch on/off per context
     */

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionRevisit";
    private static final List<Class<? extends Extension>> DEPENDENCIES;

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "revisit";

    public static final String ICON_RESOURCE = "/resource/icon/16/026.png";
    public static DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionHistory.class);
        dependencies.add(ExtensionAntiCSRF.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private Logger log = Logger.getLogger(this.getClass());

    private Map<String, TimeRange> sites = new HashMap<String, TimeRange>();
    private RevisitDialog revisitDialog;
    private RevisitAPI revisitAPI;

    /** */
    public ExtensionRevisit() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
        revisitAPI = new RevisitAPI(this);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addProxyListener(this);
        extensionHook.addSessionListener(new SessionChangedListenerImpl());

        if (getView() != null) {
            // Register our popup menu item
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new RightClickRevisitMenu(
                                    this,
                                    Constant.messages.getString(PREFIX + ".popup.enable.title"),
                                    true));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new RightClickRevisitMenu(
                                    this,
                                    Constant.messages.getString(PREFIX + ".popup.disable.title"),
                                    false));
        }

        extensionHook.addApiImplementor(revisitAPI);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (revisitDialog != null) {
            revisitDialog.dispose();
            revisitDialog = null;

            removeRevisitIconSiteNodes();
        }
    }

    private void removeRevisitIconSiteNodes() {
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = siteMap.getRoot();
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = root.breadthFirstEnumeration();
        while (en.hasMoreElements()) {
            ((SiteNode) en.nextElement()).removeCustomIcon(ICON_RESOURCE);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        String url = msg.getRequestHeader().getURI().toString();

        TimeRange rs = this.sites.get(getSiteForURL(url));
        if (rs != null) {
            log.debug("Revisiting url: " + url);
            StructuralNode node = null;
            boolean found = false;
            StringBuilder urlsFor404 = new StringBuilder();
            int urlCount = 0;
            try {
                node =
                        SessionStructure.find(
                                Model.getSingleton().getSession().getSessionId(),
                                msg.getRequestHeader().getURI(),
                                msg.getRequestHeader().getMethod(),
                                msg.getRequestBody().toString());
                if (node != null && node.getHistoryReference() != null) {
                    // this will be the last instance, which we dont really want
                    // but it is a quick test, and we can use it as a backstop :)
                    ExtensionHistory extHist =
                            (ExtensionHistory)
                                    Control.getSingleton()
                                            .getExtensionLoader()
                                            .getExtension(ExtensionHistory.NAME);

                    for (int i = 1; i <= node.getHistoryReference().getHistoryId(); i++) {
                        HistoryReference hr = extHist.getHistoryReference(i);
                        if (hr.getHistoryType() == HistoryReference.TYPE_PROXIED
                                && isSimilarRequest(url, hr.getURI().toString())) {
                            if (!url.equals(hr.getURI().toString())) {
                                // We dont perform an exact match above so that we can
                                // record similar urls here :)
                                if (urlCount <= 10) {
                                    // Add to 404 diags
                                    appendMsgToDiags(
                                            hr.getHttpMessage(),
                                            urlsFor404,
                                            Constant.messages.getString("revisit.diags.params"));
                                    urlCount++;
                                }
                                continue;
                            }
                            if (hr.getTimeSentMillis() < rs.getStartTime().getTime()) {
                                // Before specified range
                                log.debug("Before specified range: " + url);
                                if (urlCount <= 10) {
                                    // Add to 404 diags
                                    appendMsgToDiags(
                                            hr.getHttpMessage(),
                                            urlsFor404,
                                            Constant.messages.getString("revisit.diags.before"));
                                    urlCount++;
                                }
                                continue;
                            }
                            if (hr.getTimeSentMillis() < rs.getStartTime().getTime()
                                    || hr.getTimeSentMillis() > rs.getEndTime().getTime()) {
                                // After specified range (so no point continuing)
                                log.debug("After specified range: " + url);
                                // Always add so that they know there was something after the
                                // time they specified
                                appendMsgToDiags(
                                        hr.getHttpMessage(),
                                        urlsFor404,
                                        Constant.messages.getString("revisit.diags.after"));
                                break;
                            }
                            // Reading the full message from the db takes time, so perform
                            // any checks we can without it before getting it
                            HttpMessage msg2 = hr.getHttpMessage();
                            if (this.isSameRequest(msg, msg2)) {
                                log.debug("Returning revisited page: " + url);
                                copyResponse(msg2, msg);
                                found = true;
                                break;
                            } else if (urlCount <= 10) {
                                appendMsgToDiags(
                                        msg2,
                                        urlsFor404,
                                        Constant.messages.getString("revisit.diags.params"));
                                urlCount++;
                            }
                            log.debug("Not the same request: " + url);
                        }
                    }
                }
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
            if (!found) {
                // Display a 404 adding in any useful info we can
                try {
                    msg.setResponseHeader(
                            new HttpResponseHeader(
                                    "HTTP/1.1 404 Not Found"
                                            + HttpHeader.CRLF
                                            + "Server: Apache-Coyote/1.1"
                                            + HttpHeader.CRLF
                                            + "Content-Type: text/html;charset=utf-8"
                                            + HttpHeader.CRLF
                                            + "Content-Language: en"));

                    if (urlsFor404.length() == 0) {
                        msg.setResponseBody(Constant.messages.getString("revisit.404.nohistory"));
                    } else {
                        msg.setResponseBody(
                                Constant.messages.getString(
                                        "revisit.404.history", urlsFor404.toString()));
                    }

                    msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    msg.setTimeSentMillis(new Date().getTime());
                } catch (HttpMalformedHeaderException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        return true;
    }

    private void appendMsgToDiags(HttpMessage msg, StringBuilder sb, String reason) {
        if (msg.getResponseHeader().getHeader("ZAP-Revisit") != null) {
            // A Revisit response, so dont include
            return;
        }
        sb.append(dateFormat.format(new Date(msg.getTimeSentMillis())));
        sb.append(" ");
        sb.append(msg.getRequestHeader().getMethod());
        sb.append(" ");
        sb.append("<a href=\"");
        sb.append(msg.getRequestHeader().getURI());
        sb.append("\">");
        sb.append(msg.getRequestHeader().getURI());
        sb.append("<a> ");
        sb.append(reason);
        sb.append("<br>");
        if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            sb.append("&nbsp;&nbsp;&nbsp;&nbsp;POST Data:");
            String data = msg.getRequestBody().toString();
            if (data.length() > 80) {
                data = data.substring(0, 80) + "...";
            }
            sb.append(data);
            sb.append("<br>");
        }
    }

    private boolean isSimilarRequest(String url1, String url2) {
        // TODO also support user defined url params to ignore?
        int queryIndex = url1.indexOf("?");
        if (queryIndex > 0) {
            url1 = url1.substring(0, queryIndex - 1);
        }
        queryIndex = url2.indexOf("?");
        if (queryIndex > 0) {
            url2 = url2.substring(0, queryIndex - 1);
        }
        return url1.equals(url2);
    }

    private boolean isSameRequest(HttpMessage msg, HttpMessage msg2) {
        if (msg2 == null) {
            return false;
        }
        if (!msg.getRequestHeader().getMethod().equals(msg.getRequestHeader().getMethod())) {
            // Different methods
            return false;
        }
        if (msg.getRequestBody().toString().equals(msg2.getRequestBody().toString())) {
            // Exact match
            return true;
        }
        // Need to normalise and strip out anti CSRF and other user specified tokens
        Session session = Model.getSingleton().getSession();
        ExtensionAntiCSRF extAcsrf =
                (ExtensionAntiCSRF)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAntiCSRF.NAME);
        // Compare the normalised URL params
        ParameterParser upp = session.getUrlParamParser(msg.getRequestHeader().getURI().toString());
        Map<String, String> upMap1 = upp.getParams(msg, Type.url);
        Map<String, String> upMap2 = upp.getParams(msg2, Type.url);
        if (extAcsrf != null) {
            stripOutParams(upMap1, extAcsrf.getAntiCsrfTokenNames());
            stripOutParams(upMap2, extAcsrf.getAntiCsrfTokenNames());
        }
        if (!normalise(upMap1, upp).equals(normalise(upMap2, upp))) {
            return false;
        }
        // Compare the normalised form params
        ParameterParser fpp =
                session.getFormParamParser(msg.getRequestHeader().getURI().toString());
        Map<String, String> fpMap1 = fpp.getParams(msg, Type.form);
        Map<String, String> fpMap2 = fpp.getParams(msg2, Type.form);
        if (extAcsrf != null) {
            stripOutParams(fpMap1, extAcsrf.getAntiCsrfTokenNames());
            stripOutParams(fpMap2, extAcsrf.getAntiCsrfTokenNames());
        }
        if (!normalise(fpMap1, fpp).equals(normalise(fpMap2, fpp))) {
            return false;
        }
        return true;
    }

    private void stripOutParams(Map<String, String> map, List<String> excludes) {
        for (String exc : excludes) {
            map.remove(exc);
        }
    }

    private String normalise(Map<String, String> map, ParameterParser pp) {
        StringBuilder sb = new StringBuilder();
        for (String key : new TreeSet<String>(map.keySet())) {
            sb.append(key);
            sb.append(pp.getDefaultKeyValueSeparator());
            sb.append(map.get(key));
            sb.append(pp.getDefaultKeyValuePairSeparator());
        }
        return sb.toString();
    }

    public static String getSiteForURL(String url) {
        // find the fist slash after http:// or https://
        int sl = url.indexOf("/", 9);
        if (sl > 0) {
            return url.substring(0, sl);
        }
        return url;
    }

    private void copyResponse(HttpMessage fromMsg, HttpMessage toMsg)
            throws HttpMalformedHeaderException {
        toMsg.setResponseHeader(fromMsg.getResponseHeader().toString());
        toMsg.getResponseHeader().addHeader("ZAP-Revisit", "true");
        String body = fromMsg.getResponseBody().toString();
        /* Need to update length and prevent dup lines! */
        String zapDiv =
                "<div id=\"zapRevisitFooter\" "
                        + "style=\"position: fixed;bottom: 0;width: 100%;text-align: center; background:rgba(255,255,255,0.8);\">";
        if (fromMsg.getResponseHeader().isHtml() && body.indexOf(zapDiv) == -1) {
            int bodyIndex = body.toLowerCase().lastIndexOf("</body");
            if (bodyIndex > 0) {
                // Inject the footer
                body =
                        body.substring(0, bodyIndex)
                                + zapDiv
                                + "ZAP Revisit: Page originally generated on "
                                + fromMsg.getResponseHeader().getHeader("Date")
                                + "</div>"
                                + body.substring(bodyIndex);
            }
        }
        toMsg.setResponseBody(body);
        toMsg.getResponseHeader().setContentLength(toMsg.getResponseBody().length());
        toMsg.setTimeSentMillis(new Date().getTime());
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        return true;
    }

    public boolean isEnabledForSite(SiteNode sn) {
        return isEnabledForSite(getSiteForURL(sn.getHierarchicNodeName()));
    }

    public boolean isEnabledForSite(String site) {
        return this.sites.containsKey(site);
    }

    public void displayRevisitDialog(SiteNode sn) {
        if (revisitDialog == null) {
            revisitDialog = new RevisitDialog(this);
        }

        Date startTime = null;
        ExtensionHistory extHist =
                (ExtensionHistory)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.NAME);
        int i = 0;
        while (startTime == null) {
            HistoryReference hr = extHist.getHistoryReference(i);
            if (hr != null) {
                startTime = new Date(hr.getTimeSentMillis());
            }
            i++;
        }
        Date endTime = new Date();

        revisitDialog.init(sn, startTime, endTime);
        revisitDialog.setVisible(true);
    }

    public void setEnabledForSite(String url, Date startTime, Date endTime) {
        String site = ExtensionRevisit.getSiteForURL(url);
        if (!this.sites.containsKey(site)) {
            this.sites.put(site, new TimeRange(startTime, endTime));
            // Dont bother with the icon - theyre using the api anyway ;)
        }
    }

    public void setEnabledForSite(SiteNode sn, Date startTime, Date endTime) {
        String site = ExtensionRevisit.getSiteForURL(sn.getHierarchicNodeName());
        if (!this.sites.containsKey(site)) {
            this.sites.put(site, new TimeRange(startTime, endTime));
            if (View.isInitialised()) {
                sn.addCustomIcon(ICON_RESOURCE, false);
            }
        }
    }

    public void unsetEnabledForSite(String url) {
        String site = ExtensionRevisit.getSiteForURL(url);
        this.sites.remove(site);
        // Dont bother with the icon - theyre using the api anyway ;)
    }

    public void unsetEnabledForSite(SiteNode sn) {
        String site = ExtensionRevisit.getSiteForURL(sn.getHierarchicNodeName());
        if (this.sites.remove(site) != null) {
            sn.removeCustomIcon(ICON_RESOURCE);
        }
    }

    public List<String> getSites() {
        List<String> list = new ArrayList<String>();
        list.addAll(sites.keySet());
        return list;
    }

    private class TimeRange {
        private Date startTime;
        private Date endTime;

        public TimeRange(Date startTime, Date endTime) {
            super();
            this.startTime = startTime;
            this.endTime = endTime;
        }

        public Date getStartTime() {
            return startTime;
        }

        public Date getEndTime() {
            return endTime;
        }
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            if (!sites.isEmpty()) {
                sites = new HashMap<>();
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }
}
