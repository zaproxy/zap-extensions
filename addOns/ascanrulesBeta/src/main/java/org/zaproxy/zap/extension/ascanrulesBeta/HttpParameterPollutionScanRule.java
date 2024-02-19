/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * TODO note that this should extend AbstractAppParamPlugin rather than find parameters internally
 */
public class HttpParameterPollutionScanRule extends AbstractAppPlugin
        implements CommonActiveScanRuleInfo {
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION);

    private static final Logger LOGGER = LogManager.getLogger(HttpParameterPollutionScanRule.class);
    private final String payload = "%26zap%3Dzaproxy";

    @Override
    public int getId() {
        return 20014;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.sol");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.extrainfo");
    }

    /**
     * Main method of the class. It is executed for each page. Determined whether the page in
     * vulnerable to HPP or not.
     */
    @Override
    public void scan() {

        try {
            LOGGER.debug("Targeting {}", getBaseMsg().getRequestHeader().getURI());

            // pages are not vulnerable if not proved otherwise
            List<String> vulnLinks = new ArrayList<>();

            // We parse the HTML of the response and get all its parameters
            Source s = new Source(getBaseMsg().getResponseBody().toString());
            List<Element> inputTags = s.getAllElements(HTMLElementName.INPUT);
            TreeSet<HtmlParameter> tags = this.getParams(s, inputTags);

            /* If there are input fields, they can potentially be polluted */
            if (!inputTags.isEmpty()) {
                if (!tags.isEmpty()) {

                    // We send the request with the injected payload in the parameters
                    LOGGER.debug("Injecting payload...");
                    HttpMessage newMsg = getNewMsg();
                    newMsg.setGetParams(tags);
                    try {
                        sendAndReceive(newMsg);
                    } catch (IllegalStateException | UnknownHostException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                newMsg.getRequestHeader().getURI());
                        return;
                    }

                    // We check all the links of the response to find our payload
                    s = new Source(newMsg.getResponseBody().toString());
                    List<Element> links = s.getAllElements(HTMLElementName.A);
                    if (!links.isEmpty()) {
                        vulnLinks = this.findPayload(s, inputTags, vulnLinks);

                        // If vulnerable, generates the alert
                        if (!vulnLinks.isEmpty()) {
                            this.generateReport(vulnLinks);
                        }
                    }
                }
            }
            if (vulnLinks.isEmpty()) {
                LOGGER.debug("Page not vulnerable to HPP attacks");
            }
        } catch (URIException e) {
            LOGGER.debug("Failed to send HTTP message, cause: {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * @param s the source code of the targeted page
     * @param inputTags list of input parameters
     * @param vulnLinks empty list of the vulnerable links in the page
     * @return filled list of the vulnerable links in the page
     */
    public List<String> findPayload(Source s, List<Element> inputTags, List<String> vulnLinks) {
        // TODO: we should consider other tags besides <a href=> and <form action=>
        // checks the <a> tags
        List<Element> links = s.getAllElements(HTMLElementName.A);
        for (Element link : links) {
            for (Element tag : inputTags) {
                Map<String, List<String>> map = getUrlParameters(link.getAttributeValue("href"));
                if (map.get(tag.getAttributeValue("name")) != null) {
                    if (map.get(tag.getAttributeValue("name")).contains(this.payload)) {
                        LOGGER.debug(
                                "Found Vulnerable Parameter in a link with the injected payload: {}, {}",
                                tag.getAttributeValue("name"),
                                map.get(tag.getAttributeValue("name")));
                        vulnLinks.add(
                                tag.getAttributeValue("name")
                                        + ", "
                                        + map.get(tag.getAttributeValue("name")));
                    }
                }
            }
        }
        // checks the <form> tags
        links = s.getAllElements(HTMLElementName.FORM);
        for (Element link : links) {
            for (Element tag : inputTags) {
                Map<String, List<String>> map = getUrlParameters(link.getAttributeValue("action"));
                if (map.get(tag.getAttributeValue("name")) != null) {
                    if (map.get(tag.getAttributeValue("name")).contains(this.payload)) {
                        LOGGER.debug(
                                "Found Vulnerable Parameter in a form with the injected payload: {}, {}",
                                tag.getAttributeValue("name"),
                                map.get(tag.getAttributeValue("name")));
                        vulnLinks.add(
                                tag.getAttributeValue("name")
                                        + ", "
                                        + map.get(tag.getAttributeValue("name")));
                    }
                }
            }
        }
        return vulnLinks;
    }

    /**
     * @param s the source code of the targeted page
     * @param inputTags list of input parameters
     * @return the set of url form and input parameters
     */
    public TreeSet<HtmlParameter> getParams(Source s, List<Element> inputTags) {

        // We store all the page fields in a hash map and add the payload
        TreeSet<HtmlParameter> tags = new TreeSet<>();

        for (HtmlParameter p : getBaseMsg().getFormParams()) {
            if (p.getName() != null && p.getValue() != null) {
                tags.add(
                        new HtmlParameter(
                                HtmlParameter.Type.url, p.getName(), p.getValue() + this.payload));
                LOGGER.debug("The following form parameters have been found:");
                LOGGER.debug("Input Tag: {}, {}", p.getName(), p.getValue());
            }
        }
        for (HtmlParameter p : getBaseMsg().getUrlParams()) {
            if (p.getName() != null && p.getValue() != null) {
                tags.add(
                        new HtmlParameter(
                                HtmlParameter.Type.url, p.getName(), p.getValue() + this.payload));
                LOGGER.debug("The following url parameters have been found:");
                LOGGER.debug("Input Tag: {}, {}", p.getName(), p.getValue());
            }
        }
        for (Element element : inputTags) {
            if (element.getAttributeValue("name") != null
                    && element.getAttributeValue("value") != null) {
                tags.add(
                        new HtmlParameter(
                                HtmlParameter.Type.url,
                                element.getAttributeValue("name"),
                                element.getAttributeValue("value") + this.payload));
                LOGGER.debug("The following input parameters have been found:");
                LOGGER.debug(
                        "Input Tag: {}, {}",
                        element.getAttributeValue("name"),
                        element.getAttributeValue("value"));
            }
        }
        return tags;
    }

    /**
     * @param url found in the body of the targeted page
     * @return a hashmap of the query string
     */
    private Map<String, List<String>> getUrlParameters(String url) {
        Map<String, List<String>> params = new HashMap<>();

        if (url != null) {
            String[] urlParts = url.split("\\?");
            if (urlParts.length > 1) {
                String query = urlParts[1];
                for (String param : query.split("&")) {
                    String pair[] = param.split("=");
                    String key;
                    key = pair[0];
                    String value = "";
                    if (pair.length > 1) {
                        value = pair[1];
                    }
                    List<String> values = params.get(key);
                    if (values == null) {
                        values = new ArrayList<>();
                        params.put(key, values);
                    }
                    values.add(value);
                }
            }
        }
        return params;
    }

    /**
     * @param vulnLinks list of the vulnerable links in the page
     */
    public void generateReport(List<String> vulnLinks) {
        String vulnParams = "";
        for (String s : vulnLinks) {
            vulnParams = vulnParams + ", " + s;
        }
        LOGGER.debug("Page vulnerable to HPP attacks");
        buildAlert(vulnParams).setMessage(getBaseMsg()).raise();
    }

    private AlertBuilder buildAlert(String vulnParams) {
        return newAlert().setConfidence(Alert.CONFIDENCE_LOW).setParam(vulnParams);
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 20; // CWE-20: Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("Id").build());
    }
}
