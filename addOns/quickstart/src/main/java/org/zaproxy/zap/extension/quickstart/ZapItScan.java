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

import com.gargoylesoftware.htmlunit.HttpHeader;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.utils.Stats;

public class ZapItScan {

    private static final Logger LOGGER = LogManager.getLogger(ZapItScan.class);

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
        SiteNode node = ext.accessNode(targetURL);

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
                                    techList.add(app.toString());
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
            }
            if (!StringUtils.isEmpty(extra)) {
                if (extra.length() > 80) {
                    // Keep it to a vaguely sensible length
                    extra = extra.substring(0, 80) + "...";
                }
                extra = " : \"" + extra + "\"";
            }

            CommandLine.info(
                    "\t" + Alert.MSG_RISK[alert.getRisk()] + ": " + alert.getName() + extra);
        }

        // Report root page stats
        HistoryReference href = node.getHistoryReference();
        if (href != null) {
            CommandLine.info(Constant.messages.getString("quickstart.cmdline.zapit.root"));
            CommandLine.info(
                    Constant.messages.getString(
                            "quickstart.cmdline.zapit.root.time", href.getRtt()));
            try {
                HttpMessage msg = href.getHttpMessage();
                CommandLine.info(
                        Constant.messages.getString(
                                "quickstart.cmdline.zapit.root.respbody",
                                msg.getResponseBody().length()));
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
}
