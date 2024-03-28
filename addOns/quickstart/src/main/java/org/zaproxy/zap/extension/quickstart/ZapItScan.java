/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.Stats;

public class ZapItScan {

    private static final Logger LOGGER = LogManager.getLogger(ZapItScan.class);
    private static final int MAX_STR_SIZE = 80;

    private ExtensionQuickStart ext;

    public ZapItScan(ExtensionQuickStart ext) {
        this.ext = ext;
    }

    @SuppressWarnings("unchecked")
    public boolean recon(String url) {
        // Always start a new session so that nothing 'bleeds' through if this is called multiple
        // times
        try {
            Control.getSingleton().newSession();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }

        URL targetURL;
        try {
            targetURL = new URL(url);
            // Validate the actual request-uri of the HTTP message accessed.
            new URI(url, true);
        } catch (MalformedURLException | URIException e) {
            CommandLine.error(
                    Constant.messages.getString("quickstart.cmdline.quickurl.error.invalidUrl"));
            return false;
        }
        Stats.incCounter("stats.quickstart.zapit.basic");
        CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.start", url));

        ZapItRedirectionValidator zirv = new ZapItRedirectionValidator();

        SiteNode node =
                ext.accessNode(
                        targetURL,
                        HttpRequestConfig.builder()
                                .setFollowRedirects(true)
                                .setRedirectionValidator(zirv)
                                .build(),
                        false);

        List<MessageSummary> msgs = zirv.getMessages();
        if (msgs.isEmpty()) {
            CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.req.none"));
        }
        if (node == null) {
            CommandLine.error(Constant.messages.getString("quickstart.cmdline.zapit.fail", url));
            return false;
        }

        // Wait for passive scan to complete
        ExtensionPassiveScan extPscan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan.class);
        while (extPscan.getRecordsToScan() > 0) {
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                // Ignore
            }
        }

        // Try to find tech - use reflection so we do not have to depend on the Wappalyzer extension
        Extension techExt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtensionByClassName(
                                "org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer");

        if (techExt != null) {
            if (techExt.isEnabled()) {
                try {
                    Class<?> techExtClass = techExt.getClass();
                    Method getSitesMethod = techExtClass.getMethod("getSites");
                    Set<String> sites = (Set<String>) getSitesMethod.invoke(techExt);
                    List<String> techList = new ArrayList<>();
                    if (sites != null) {
                        Method getTechModelForSiteMethod =
                                techExtClass.getMethod("getTechModelForSite", String.class);
                        for (String site : sites) {
                            if (url.startsWith(site)) {
                                Object techModel = getTechModelForSiteMethod.invoke(techExt, site);
                                Method getAppsMethod = techModel.getClass().getMethod("getApps");
                                List<?> apps = (List<?>) getAppsMethod.invoke(techModel);
                                for (Object appMatch : apps) {
                                    Method getApplicationMethod =
                                            appMatch.getClass().getMethod("getApplication");
                                    Object app = getApplicationMethod.invoke(appMatch);
                                    String appStr = app.toString();
                                    Method getVersionMethod =
                                            appMatch.getClass().getMethod("getVersion");
                                    String version = (String) getVersionMethod.invoke(appMatch);
                                    if (!StringUtils.isEmpty(version)) {
                                        appStr += " (" + version + ")";
                                    }
                                    techList.add(appStr);
                                }
                            }
                        }
                    }
                    if (techList.isEmpty()) {
                        CommandLine.info(
                                Constant.messages.getString("quickstart.cmdline.zapit.tech.none"));
                    } else {
                        CommandLine.info(
                                Constant.messages.getString("quickstart.cmdline.zapit.tech"));
                        Collections.sort(techList);
                        for (String tech : techList) {
                            CommandLine.info("\t" + tech);
                        }
                    }

                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            } else {
                CommandLine.info(
                        Constant.messages.getString("quickstart.cmdline.zapit.tech.disabled"));
            }
        } else {
            CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.tech.na"));
        }

        // Report alerts
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        List<Alert> alerts = extAlert.getAllAlerts();

        Collections.sort(
                alerts,
                (o1, o2) -> {
                    if (o1.getRisk() == o2.getRisk()) {
                        return o1.getName().compareTo(o2.getName());
                    }
                    return o2.getRisk() - o1.getRisk();
                });

        CommandLine.info(
                Constant.messages.getString("quickstart.cmdline.zapit.alerts", alerts.size()));
        for (Alert alert : alerts) {
            String extra = alert.getEvidence();
            if (StringUtils.isEmpty(extra)) {
                extra = alert.getParam();
            } else {
                // Replace any newlines to keep the display tidier
                extra = extra.replace("\r\n", " ").replace('\n', ' ');
            }
            extra = " : \"" + trim(extra) + "\"";

            CommandLine.info(
                    "\t" + Alert.MSG_RISK[alert.getRisk()] + ": " + alert.getName() + extra);
        }

        // Report root page stats
        HistoryReference href = node.getHistoryReference();
        if (href != null) {
            CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.root"));

            try {
                HttpMessage msg = href.getHttpMessage();
                String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
                if (contentType != null) {
                    CommandLine.info(
                            Constant.messages.getString(
                                    "quickstart.cmdline.zapit.root.ctype", contentType));
                }
                try {
                    Source src = new Source(msg.getResponseBody().toString());
                    CommandLine.info(
                            Constant.messages.getString(
                                    "quickstart.cmdline.zapit.root.htmltags",
                                    src.getAllTags().size()));
                    CommandLine.info(
                            Constant.messages.getString(
                                    "quickstart.cmdline.zapit.root.links",
                                    src.getAllElements(HTMLElementName.A).size()));
                    CommandLine.info(
                            Constant.messages.getString(
                                    "quickstart.cmdline.zapit.root.forms",
                                    src.getAllElements(HTMLElementName.FORM).size()));
                    CommandLine.info(
                            Constant.messages.getString(
                                    "quickstart.cmdline.zapit.root.inputs",
                                    src.getAllElements(HTMLElementName.INPUT).size()));

                } catch (Exception e) {
                    // Might not be HTML
                    LOGGER.debug(e.getMessage(), e);
                }

            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return true;
    }

    private static String trim(String str) {
        if (!StringUtils.isEmpty(str) && str.length() > MAX_STR_SIZE) {
            str = str.substring(0, MAX_STR_SIZE) + "...";
        }
        return str;
    }

    private static class MessageSummary {
        private final String url;
        private final long time;
        private final int code;
        private final long bodySize;
        private final List<String> reqCookies;
        private final List<String> respCookies;

        MessageSummary(HttpMessage msg) {
            this.url = msg.getRequestHeader().getURI().toString();
            this.time = msg.getTimeElapsedMillis();
            this.code = msg.getResponseHeader().getStatusCode();
            this.bodySize = msg.getResponseBody().length();
            this.reqCookies = msg.getRequestHeader().getHeaderValues(HttpHeader.COOKIE);
            this.respCookies =
                    msg.getResponseHeader().getHeaderValues(HttpResponseHeader.SET_COOKIE);
        }

        public String getUrl() {
            return url;
        }

        public long getTime() {
            return time;
        }

        public int getCode() {
            return code;
        }

        public long getBodySize() {
            return bodySize;
        }

        public List<String> getReqCookies() {
            return reqCookies;
        }

        public List<String> getRespCookies() {
            return respCookies;
        }
    }

    private static class ZapItRedirectionValidator implements HttpRedirectionValidator {

        private boolean printedTitle;
        private final List<MessageSummary> messages = new ArrayList<>();

        @Override
        public boolean isValid(URI redirection) {
            return true;
        }

        public List<MessageSummary> getMessages() {
            return messages;
        }

        @Override
        public void notifyMessageReceived(HttpMessage msg) {
            // The MessageSummary is a bit superfluous now, but will be needed for caching the
            // request when we support other sort of reports
            MessageSummary ms = new MessageSummary(msg);
            messages.add(ms);

            if (!printedTitle) {
                CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.req"));
                printedTitle = true;
            }
            CommandLine.info(
                    Constant.messages.getString("quickstart.cmdline.zapit.req.url", ms.getUrl()));
            CommandLine.info(
                    Constant.messages.getString("quickstart.cmdline.zapit.req.time", ms.getTime()));
            CommandLine.info(
                    Constant.messages.getString(
                            "quickstart.cmdline.zapit.req.code",
                            ms.getCode(),
                            HttpStatus.getStatusText(ms.getCode())));
            CommandLine.info(
                    Constant.messages.getString(
                            "quickstart.cmdline.zapit.req.respbody", ms.getBodySize()));

            List<String> reqCookies = ms.getReqCookies();
            if (reqCookies.isEmpty()) {
                CommandLine.info(
                        Constant.messages.getString(
                                "quickstart.cmdline.zapit.req.reqcookies.none"));
            } else {
                CommandLine.info(
                        Constant.messages.getString("quickstart.cmdline.zapit.req.reqcookies"));
                reqCookies.stream()
                        .forEach(
                                c ->
                                        CommandLine.info(
                                                Constant.messages.getString(
                                                        "quickstart.cmdline.zapit.req.reqcookies.cookie",
                                                        trim(c))));
            }

            List<String> respCookies = ms.getRespCookies();
            if (respCookies.isEmpty()) {
                CommandLine.info(
                        Constant.messages.getString(
                                "quickstart.cmdline.zapit.req.respcookies.none"));
            } else {
                CommandLine.info(
                        Constant.messages.getString("quickstart.cmdline.zapit.req.respcookies"));
                respCookies.stream()
                        .forEach(
                                c ->
                                        CommandLine.info(
                                                Constant.messages.getString(
                                                        "quickstart.cmdline.zapit.req.respcookies.cookie",
                                                        trim(c))));
            }
        }
    }
}
