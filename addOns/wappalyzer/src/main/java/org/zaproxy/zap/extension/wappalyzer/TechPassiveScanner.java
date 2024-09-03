/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Alert.Builder;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.wappalyzer.AppPattern.Result;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer.Mode;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.utils.Stats;

public class TechPassiveScanner implements PassiveScanner, OptionsChangedListener {

    private static final Logger LOGGER = LogManager.getLogger(TechPassiveScanner.class);
    private static final int PLUGIN_ID = 10004;

    private ApplicationHolder applicationHolder;
    private Map<String, Set<String>> tracker;

    /** The number of requests analysed for each site */
    private Map<String, Integer> siteReqCount;

    private Set<String> visitedSiteIdentifiers;
    private volatile boolean enabled = true;
    private volatile Mode mode = Mode.QUICK;
    private volatile boolean raiseAlerts = true;

    /** Functional interface for looped processing of HttpMessages in different ways. */
    @FunctionalInterface
    private interface CustomProcessor {
        ApplicationMatch process(
                ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source);
    }

    private List<CustomProcessor> messageHeaderProcessors =
            List.of(
                    TechPassiveScanner.this::checkUrlMatches,
                    TechPassiveScanner.this::checkHeadersMatches,
                    TechPassiveScanner.this::checkCookieMatches);

    private List<CustomProcessor> messageBodyProcessors =
            List.of(
                    TechPassiveScanner.this::checkBodyMatches,
                    TechPassiveScanner.this::checkSimpleDomMatches,
                    TechPassiveScanner.this::checkDomElementMatches,
                    TechPassiveScanner.this::checkMetaElementsMatches,
                    TechPassiveScanner.this::checkScriptElementsMatches,
                    TechPassiveScanner.this::checkCssElementsMatches);

    public TechPassiveScanner(ApplicationHolder applicationHolder) {
        super();
        this.applicationHolder = applicationHolder;
        this.reset();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("wappalyzer.scanner");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String siteIdentifier = getSiteIdentifier(msg);

        if (!visitedSiteIdentifiers.add(siteIdentifier)) {
            return;
        }

        long startTime = System.currentTimeMillis();
        String site = getSite(msg);
        tracker.putIfAbsent(site, new HashSet<String>());
        int reqCount = siteReqCount.merge(site, 1, Integer::sum);
        Stats.setHighwaterMark(site, "stats.tech.reqcount.total", reqCount);

        for (Application app : this.getApps()) {
            // Track matched based on site (authority)
            synchronized (tracker) {
                if (tracker.get(site).contains(app.getName())) {
                    // Already exists, so continue
                    LOGGER.debug("\"{}\" already identified on {}", app.getName(), site);
                    continue;
                }
                ApplicationMatch appMatch = checkAppMatches(null, app, msg, source);
                if (appMatch != null) {
                    LOGGER.debug(
                            "Adding \"{}\" to tracker {} identified via {}.",
                            app.getName(),
                            site,
                            msg.getRequestHeader().getURI());
                    addApplicationsToSite(
                            ExtensionWappalyzer.normalizeSite(msg.getRequestHeader().getURI()),
                            appMatch);
                    raiseAlert(msg, appMatch);
                    tracker.get(site).add(app.getName());
                    Stats.setHighwaterMark(site, "stats.tech.reqcount.id", reqCount);
                }
            }
        }

        LOGGER.debug("Analysis took {} ms", System.currentTimeMillis() - startTime);
    }

    private static String getSite(HttpMessage msg) {
        String site = "";
        try {
            site = SessionStructure.getHostName(msg);
        } catch (URIException e) {
            // Ignore - Should never happen
        }
        return site;
    }

    private static String getSiteIdentifier(HttpMessage msg) {
        SiteNode node = getSiteNode(msg);
        if (node != null) {
            return node.getHierarchicNodeName() + "_" + node.getNodeName();
        }
        return msg.getRequestHeader().getURI().toString();
    }

    private static SiteNode getSiteNode(HttpMessage msg) {
        HistoryReference href = msg.getHistoryRef();
        if (href == null) {
            return null;
        }
        return href.getSiteNode();
    }

    private void addApplicationsToSite(String site, ApplicationMatch applicationMatch) {
        applicationHolder.addApplicationsToSite(site, applicationMatch);
        // Add implied apps
        for (String imp : applicationMatch.getApplication().getImplies()) {
            Application ia = applicationHolder.getApplication(imp);
            if (ia != null) {
                addApplicationsToSite(site, new ApplicationMatch(ia));
            }
        }
    }

    private ApplicationMatch checkAppMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {

        for (CustomProcessor cmp : messageHeaderProcessors) {
            appMatch = cmp.process(appMatch, currentApp, msg, source);
            if (!Mode.EXHAUSTIVE.equals(mode) && appMatch != null) {
                return appMatch;
            }
        }

        if (!msg.getResponseHeader().isText()) {
            return appMatch; // Don't check body if not text'ish
        }

        for (CustomProcessor cmp : messageBodyProcessors) {
            appMatch = cmp.process(appMatch, currentApp, msg, source);
            if (!Mode.EXHAUSTIVE.equals(mode) && appMatch != null) {
                return appMatch;
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkCssElementsMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        for (AppPattern appPattern : currentApp.getCss()) {
            if (ResourceIdentificationUtils.isCss(msg)) {
                appMatch =
                        addIfMatches(
                                appMatch, currentApp, appPattern, msg.getResponseBody().toString());
            } else {
                for (Element styleElement : source.getAllElements(HTMLElementName.STYLE)) {
                    appMatch =
                            addIfMatches(
                                    appMatch,
                                    currentApp,
                                    appPattern,
                                    styleElement.getSource().toString());
                }
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkScriptElementsMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        for (Element scriptElement : source.getAllElements(HTMLElementName.SCRIPT)) {
            for (AppPattern appPattern : currentApp.getScript()) {
                String src = scriptElement.getAttributeValue("src");
                if (src != null && !src.isEmpty()) {
                    appMatch = addIfMatches(appMatch, currentApp, appPattern, src);
                }
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkMetaElementsMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        List<Element> metaElements = source.getAllElements(HTMLElementName.META);
        for (Element metaElement : metaElements) {
            for (Map<String, AppPattern> sp : currentApp.getMetas()) {
                for (Map.Entry<String, AppPattern> entry : sp.entrySet()) {
                    String name = metaElement.getAttributeValue("name");
                    String content = metaElement.getAttributeValue("content");
                    if (name != null && content != null && name.equals(entry.getKey())) {
                        AppPattern p = entry.getValue();
                        appMatch = addIfMatches(appMatch, currentApp, p, content);
                    }
                }
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkDomElementMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage message, Source source) {
        if (!message.getResponseHeader().isHtml()) {
            return appMatch;
        }
        Document doc = Jsoup.parse(message.getResponseBody().toString());
        for (Map<String, Map<String, Map<String, AppPattern>>> domSelectorMap :
                currentApp.getDom()) {
            for (Map.Entry<String, Map<String, Map<String, AppPattern>>> selectorMap :
                    domSelectorMap.entrySet()) {
                for (Map.Entry<String, Map<String, AppPattern>> nodeSelectorMap :
                        selectorMap.getValue().entrySet()) {
                    for (Map.Entry<String, AppPattern> value :
                            nodeSelectorMap.getValue().entrySet()) {
                        Elements selectedElements = doc.select(selectorMap.getKey());
                        for (org.jsoup.nodes.Element selectedElement : selectedElements) {
                            if (Objects.equals(value.getKey(), "text")) {
                                AppPattern ap = value.getValue();
                                appMatch =
                                        addIfMatches(
                                                appMatch, currentApp, ap, selectedElement.text());
                            }
                            if (Objects.equals(nodeSelectorMap.getKey(), "attributes")) {
                                AppPattern ap = value.getValue();
                                if (selectedElement.hasAttr(value.getKey())) {
                                    appMatch =
                                            addIfMatches(
                                                    appMatch,
                                                    currentApp,
                                                    ap,
                                                    selectedElement.attr(value.getKey()));
                                }
                            }
                        }
                    }
                }
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkSimpleDomMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        String body = msg.getResponseBody().toString();
        for (String selector : currentApp.getSimpleDom()) {
            appMatch = addIfDomMatches(appMatch, currentApp, selector, body);
        }
        return appMatch;
    }

    private ApplicationMatch checkBodyMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        String body = msg.getResponseBody().toString();
        for (AppPattern p : currentApp.getHtml()) {
            appMatch = addIfMatches(appMatch, currentApp, p, body);
        }
        return appMatch;
    }

    private ApplicationMatch checkHeadersMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        for (Map<String, AppPattern> sp : currentApp.getHeaders()) {
            for (Map.Entry<String, AppPattern> entry : sp.entrySet()) {
                List<String> hasRelevantHeaders =
                        msg.getResponseHeader().getHeaderValues(entry.getKey());
                if (!hasRelevantHeaders.isEmpty()) {
                    if (skipValueCheck(entry)) {
                        AppPattern p = new AppPattern();
                        p.setType("HEADER");
                        p.setPattern(entry.getKey());
                        appMatch = addIfMatches(appMatch, currentApp, p, entry.getKey());
                    } else {
                        String headerValue = msg.getResponseHeader().getHeader(entry.getKey());
                        AppPattern p = entry.getValue();
                        appMatch = addIfMatches(appMatch, currentApp, p, headerValue);
                    }
                }
            }
        }
        return appMatch;
    }

    private ApplicationMatch checkCookieMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        for (Map<String, AppPattern> sp : currentApp.getCookies()) {
            for (Map.Entry<String, AppPattern> entry : sp.entrySet()) {
                for (HtmlParameter cookie : msg.getCookieParams()) {
                    if (entry.getKey().equals(cookie.getName())) {
                        if (skipValueCheck(entry)) {
                            AppPattern p = new AppPattern();
                            p.setType("Cookies");
                            p.setPattern(entry.getKey());
                            appMatch = addIfMatches(appMatch, currentApp, p, cookie.getName());
                        } else {
                            AppPattern p = entry.getValue();
                            appMatch = addIfMatches(appMatch, currentApp, p, cookie.getValue());
                        }
                    }
                }
            }
        }
        return appMatch;
    }

    boolean skipValueCheck(Map.Entry<String, AppPattern> entry) {
        return entry.getValue().getJavaPattern().toString().isEmpty()
                && entry.getValue().getRe2jPattern().toString().isEmpty();
    }

    private ApplicationMatch checkUrlMatches(
            ApplicationMatch appMatch, Application currentApp, HttpMessage msg, Source source) {
        String url = msg.getRequestHeader().getURI().toString();
        for (AppPattern p : currentApp.getUrl()) {
            appMatch = addIfMatches(appMatch, currentApp, p, url);
        }
        return appMatch;
    }

    private static ApplicationMatch addIfDomMatches(
            ApplicationMatch appMatch, Application currentApp, String selector, String content) {
        Document doc = Jsoup.parse(content);
        Elements elements = doc.select(selector);
        if (!elements.isEmpty()) {
            appMatch = getAppMatch(appMatch, currentApp);
        }
        return appMatch;
    }

    private static ApplicationMatch addIfMatches(
            ApplicationMatch appMatch,
            Application currentApp,
            AppPattern appPattern,
            String content) {
        Result result = appPattern.findInString(content);
        if (!result.getVersions().isEmpty() || !result.getEvidence().isEmpty()) {
            appMatch = getAppMatch(appMatch, currentApp);
            // TODO may need to account for the wappalyzer spec in dealing with version info:
            // https://www.wappalyzer.com/docs/specification
            appMatch.addEvidence(result.getEvidence());
            result.getVersions().forEach(appMatch::addVersion);
            LOGGER.debug(
                    "{} matched {}", appPattern.getType(), appMatch.getApplication().getName());
        }
        return appMatch;
    }

    private void raiseAlert(HttpMessage msg, ApplicationMatch appMatch) {
        if (raiseAlerts) {
            LOGGER.debug(
                    "Adding \"{}\" alert for \"{}\"",
                    appMatch.getApplication().getName(),
                    msg.getRequestHeader().getURI());
            ExtensionAlert extAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
            if (extAlert != null) {
                Alert alert =
                        createAlert(msg.getRequestHeader().getURI().toString(), appMatch)
                                .setMessage(msg)
                                .build();
                extAlert.alertFound(alert, msg.getHistoryRef());
            }
        }
    }

    Builder createAlert(String url, ApplicationMatch appMatch) {
        Application app = appMatch.getApplication();

        Builder builder = Alert.builder();
        builder.setPluginId(PLUGIN_ID)
                .setName(Constant.messages.getString("wappalyzer.alert.name.prefix", app.getName()))
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setUri(url)
                .setDescription(getDesc(app))
                .setCweId(200)
                .setWascId(13);
        if (!appMatch.getEvidences().isEmpty()) {
            builder.setEvidence(appMatch.getEvidences().stream().findFirst().get());
        }
        builder.setOtherInfo(getOtherInfo(appMatch));
        if (app.getWebsite() != null && !app.getWebsite().isEmpty()) {
            builder.setReference(app.getWebsite());
        }
        return builder;
    }

    private static String getDesc(Application app) {
        String desc =
                Constant.messages.getString(
                        "wappalyzer.alert.desc",
                        collectionToString(app.getCategories()),
                        app.getName());
        if (app.getDescription() != null && !app.getDescription().isEmpty()) {
            desc =
                    desc
                            + Constant.messages.getString(
                                    "wappalyzer.alert.desc.extended", app.getDescription());
        }
        return desc;
    }

    private static String getOtherInfo(ApplicationMatch appMatch) {
        String cpeInfo = "";
        if (appMatch.getApplication().getCpe() != null
                && !appMatch.getApplication().getCpe().isBlank()) {
            cpeInfo =
                    Constant.messages.getString(
                            "wappalyzer.alert.otherinfo.cpe", appMatch.getApplication().getCpe());
        }
        String versionInfo = "";
        if (appMatch.getVersion() != null && !appMatch.getVersions().isEmpty()) {
            versionInfo =
                    Constant.messages.getString(
                            "wappalyzer.alert.otherinfo.version",
                            collectionToString(appMatch.getVersions()));
        }
        return cpeInfo.isEmpty() ? versionInfo : cpeInfo + '\n' + versionInfo;
    }

    private List<Application> getApps() {
        return applicationHolder.getApplications();
    }

    private static ApplicationMatch getAppMatch(ApplicationMatch appMatch, Application currentApp) {
        if (appMatch == null) {
            appMatch = new ApplicationMatch(currentApp);
        }
        return appMatch;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    void setMode(Mode mode) {
        this.mode = mode;
    }

    void setRaiseAlerts(boolean raiseAlerts) {
        this.raiseAlerts = raiseAlerts;
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        TechDetectParam param = optionsParam.getParamSet(TechDetectParam.class);
        mode = param.getMode();
        raiseAlerts = param.isRaiseAlerts();
    }

    private static String collectionToString(Collection<?> collection) {
        return collection.stream().map(String::valueOf).collect(Collectors.joining(", "));
    }

    public List<Alert> getExampleAlerts() {
        return List.of(
                createAlert("https://example.org/", getAppForExample()).setName(getName()).build());
    }

    private static ApplicationMatch getAppForExample() {
        Application exampleApp = new Application();
        exampleApp.setCategories(List.of("Widgets"));
        exampleApp.setName("Example Software");
        exampleApp.setCpe("cpe:2.3:a:example_vendor:example_software:55.4.3:*:*:*:*:*:*:*");

        ApplicationMatch exampleMatch = new ApplicationMatch(exampleApp);
        exampleMatch.addEvidence("Exampleware");
        exampleMatch.addVersion("55.4.3");
        return exampleMatch;
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/technology-detection/options/#10004";
    }

    void reset() {
        tracker = Collections.synchronizedMap(new TreeMap<>());
        visitedSiteIdentifiers = Collections.synchronizedSet(new HashSet<>());
        siteReqCount = Collections.synchronizedMap(new TreeMap<>());
    }
}
