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
package org.zaproxy.zap.extension.domxss;

import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Stack;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.ElementNotInteractableException;
import org.openqa.selenium.NoSuchSessionException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.UnexpectedAlertBehaviour;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.UnreachableBrowserException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

public class DomXssScanRule extends AbstractAppParamPlugin {
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");
    private static final Logger LOGGER = LogManager.getLogger(DomXssScanRule.class);
    private static final int UNLIKELY_INT = 5397;
    private static final String UNLIKELY_STR = String.valueOf(UNLIKELY_INT);

    protected static final String POLYGLOT_ALERT =
            "#jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert("
                    + UNLIKELY_INT
                    + ") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("
                    + UNLIKELY_INT
                    + ")//>\\x3e";
    private static final String HASH_SCRIPT_ALERT = "#<script>alert(" + UNLIKELY_INT + ")</script>";
    private static final String HASH_IMG_ALERT =
            "#<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>";
    private static final String HASH_HASH_ALERT =
            "#abc#<script>alert(" + UNLIKELY_INT + ")</script>";
    protected static final String QUERY_IMG_ALERT =
            "?name=<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>";
    private static final String HASH_HASH_IMG_ALERT =
            "#abc#<img src='random.gif' onerror=alert(" + UNLIKELY_INT + ")";
    protected static final String HASH_JAVASCRIPT_ALERT = "#javascript:alert(" + UNLIKELY_INT + ")";
    protected static final String HASH_ALERT = "#alert(" + UNLIKELY_INT + ")";
    protected static final String QUERY_HASH_IMG_ALERT =
            "?name=abc#<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>";

    private static final String PAYLOAD_1 = "<PAYLOAD_1>";
    private static final String PAYLOAD_0 = "<PAYLOAD_0>";

    // In order of effectiveness vs benchmark apps
    private static final String[] ATTACK_STRINGS = {
        POLYGLOT_ALERT,
        HASH_JAVASCRIPT_ALERT,
        QUERY_HASH_IMG_ALERT,
        HASH_ALERT,
        QUERY_IMG_ALERT,
        HASH_SCRIPT_ALERT,
        HASH_IMG_ALERT,
        HASH_HASH_ALERT,
        HASH_HASH_IMG_ALERT,
    };

    private static final String IMG_ALERT =
            "<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>";
    private static final String SCRIPT_ALERT = "<script>alert(" + UNLIKELY_INT + ")</script>";
    static final String JAVASCRIPT_ALERT = "javascript:alert(" + UNLIKELY_INT + ")";

    private static final String[] PARAM_ATTACK_STRINGS = {
        SCRIPT_ALERT, JAVASCRIPT_ALERT, IMG_ALERT
    };

    /** The name of the rule to obtain the ID of the browser. */
    private static final String RULE_BROWSER_ID = "rules.domxss.browserid";

    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX_HEADLESS;
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_CLNT_01_DOM_XSS));
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static Map<Browser, Stack<WebDriverWrapper>> freeDrivers = new HashMap<>();
    private static List<WebDriverWrapper> takenDrivers = new ArrayList<>();

    private static Thread reaperThread = null;
    private static Object reaperThreadSync = new Object();

    static ExtensionNetwork extensionNetwork;

    static Server proxy = null;
    private static int proxyPort = -1;

    private WebDriverWrapper driver;
    private boolean vulnerable = false;
    private Browser browser;
    private List<String> steps;

    @Override
    public int getId() {
        return 40026;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("domxss.name");
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.BROWSER;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public void init() {
        getProxy();

        try {
            String browserId = this.getConfig().getString(RULE_BROWSER_ID, DEFAULT_BROWSER.getId());
            if (browserId != null && !browserId.isEmpty()) {
                browser = Browser.getBrowserWithIdNoFailSafe(browserId);
            }
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_BROWSER_ID,
                    this.getConfig().getString(RULE_BROWSER_ID));
        }

        if (browser == null) {
            browser = DEFAULT_BROWSER;
        } else if (!isSupportedBrowser(browser)) {
            LOGGER.warn(
                    "Specified browser {} is not supported, defaulting to: {}",
                    browser,
                    DEFAULT_BROWSER);
            browser = DEFAULT_BROWSER;
        }

        LOGGER.debug("Using browser: {}", browser);
        steps = new ArrayList<>();
    }

    private static boolean isSupportedBrowser(Browser browser) {
        return browser == Browser.FIREFOX
                || browser == Browser.FIREFOX_HEADLESS
                || browser == Browser.CHROME
                || browser == Browser.CHROME_HEADLESS;
    }

    Browser getBrowser() {
        return browser;
    }

    /*
     * We use a separate port so that we dont pollute the sites tree
     * and show the requests in the Active Scan tab
     */
    private Server getProxy() {
        if (proxy == null) {
            proxy =
                    extensionNetwork.createHttpProxy(
                            -1,
                            new HttpMessageHandler() {

                                @Override
                                public void handleMessage(
                                        HttpMessageHandlerContext ctx, HttpMessage msg) {
                                    if (isExcluded(msg, getParent().getContext())) {
                                        ctx.close();
                                        return;
                                    }

                                    ctx.overridden();

                                    try {
                                        // Ideally it should check that the message belongs
                                        // to the scanned target before sending
                                        sendAndReceive(msg);
                                    } catch (IOException e) {
                                        LOGGER.debug(e);
                                    }
                                }
                            });
            try {
                proxyPort = proxy.start(Server.ANY_PORT);
            } catch (IOException e) {
                LOGGER.warn("An error occurred while starting the proxy.", e);
            }
        }
        return proxy;
    }

    private static boolean isExcluded(HttpMessage msg, Context context) {
        String uri = msg.getRequestHeader().getURI().toString();
        List<String> exclusions = Model.getSingleton().getSession().getGlobalExcludeURLRegexs();
        for (String regex : exclusions) {
            if (Pattern.matches(regex, uri)) {
                return true;
            }
        }
        if (context != null && context.isExcluded(uri)) {
            return true;
        }
        return false;
    }

    private WebDriver createWebDriver() {
        WebDriver webDriver =
                ExtensionSelenium.getWebDriver(
                        HttpSender.ACTIVE_SCANNER_INITIATOR,
                        browser,
                        "127.0.0.1",
                        proxyPort,
                        capabilities ->
                                capabilities.setCapability(
                                        CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR,
                                        UnexpectedAlertBehaviour.IGNORE),
                        false);

        webDriver.manage().timeouts().pageLoadTimeout(Duration.of(10, ChronoUnit.SECONDS));
        webDriver.manage().timeouts().scriptTimeout(Duration.of(10, ChronoUnit.SECONDS));

        return webDriver;
    }

    private WebDriverWrapper getWebDriver() {
        WebDriverWrapper driver = null;
        try {
            driver = freeDrivers.get(browser).pop();
            if (!driver.getBrowser().equals(browser)) {
                driver.getDriver().quit();
                driver = null;
            }
        } catch (Exception e) {
            // Ignore
        }
        if (driver == null) {
            driver = new WebDriverWrapper(createWebDriver(), browser);
        }
        synchronized (takenDrivers) {
            takenDrivers.add(driver);
        }

        if (reaperThread == null) {
            synchronized (reaperThreadSync) {
                if (reaperThread == null) {
                    reaperThread =
                            new Thread(
                                    () -> {
                                        LOGGER.info("Reaper thread starting");
                                        reaperThread.setName("ZAP-DomXssReaper");
                                        do {
                                            try {
                                                Thread.sleep(5000);
                                            } catch (InterruptedException e) {
                                                // Ignore
                                            }
                                            Date now = new Date();
                                            // concurrent modification exception :(
                                            synchronized (takenDrivers) {
                                                Iterator<WebDriverWrapper> iter =
                                                        takenDrivers.iterator();
                                                while (iter.hasNext()) {
                                                    WebDriverWrapper wrapper = iter.next();
                                                    if ((now.getTime()
                                                                            - wrapper.getLastAccessed()
                                                                                    .getTime())
                                                                    / 1000
                                                            > 10) {
                                                        LOGGER.debug(
                                                                "Driver hung {}",
                                                                wrapper.getDriver().hashCode());
                                                        wrapper.getDriver().quit();
                                                        wrapper.setDriver(createWebDriver());
                                                        LOGGER.debug(
                                                                "New driver {}",
                                                                wrapper.getDriver().hashCode());
                                                    }
                                                }
                                            }
                                        } while (takenDrivers.size() > 0);
                                        LOGGER.info(
                                                "Reaper thread exiting {}", takenDrivers.size());

                                        reaperThread = null;
                                    });
                    reaperThread.start();
                }
            }
        }
        return driver;
    }

    private void returnDriver(WebDriverWrapper driver) {
        synchronized (takenDrivers) {
            try {
                driver.getDriver().switchTo().alert().accept();
            } catch (Exception e) {
                // ignore
            }
            driver.getDriver().get("about:blank");
            if (takenDrivers.remove(driver)) {
                freeDrivers.computeIfAbsent(driver.getBrowser(), k -> new Stack<>()).push(driver);

            } else {
                LOGGER.debug("Driver not in 'taken' list");
            }
        }
    }

    @Override
    public void setTimeFinished() {
        super.setTimeFinished();
        tidyUp();
    }

    static void tidyUp() {
        // Tidy up...
        // Dont kill drivers in the 'taken' list as there may be multiple scans
        WebDriverWrapper driver;
        for (Entry<Browser, Stack<WebDriverWrapper>> map : freeDrivers.entrySet()) {
            while (!map.getValue().isEmpty()) {
                try {
                    driver = map.getValue().pop();
                    driver.getDriver().quit();
                } catch (Exception e) {
                    // Ignore
                }
            }
        }
    }

    private void getHelper(WebDriverWrapper wrapper, String url) {
        this.getHelper(wrapper, url, 3);
    }

    private void getHelper(WebDriverWrapper wrapper, String url, int retry) {
        try {
            Stats.incCounter("domxss.gets.count");
            steps.add(Constant.messages.getString("domxss.step.access", url));
            wrapper.getDriver().get(url);

        } catch (UnhandledAlertException uae) {
            throw uae;
        } catch (NoSuchSessionException enve) {
            // Pause, retry
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                //
            }
            if (retry >= 0) {
                this.getHelper(wrapper, url, retry - 1);
            }
        } catch (UnreachableBrowserException ube) {
            // Pause, retry
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                //
            }
            if (retry >= 0) {
                this.getHelper(wrapper, url, retry - 1);
            }
        } catch (ElementNotInteractableException enve) {
            LOGGER.debug(enve);
        } catch (TimeoutException wde) {
            LOGGER.debug(wde);
        } catch (WebDriverException wde) {
            LOGGER.debug(wde);
        }
    }

    private List<WebElement> findHelper(WebDriverWrapper wrapper, By by) {
        return this.findHelper(wrapper, by, 3);
    }

    private List<WebElement> findHelper(WebDriverWrapper wrapper, By by, int retry) {
        try {
            Stats.incCounter("domxss.gets.count");
            return wrapper.getDriver().findElements(by);

        } catch (UnhandledAlertException uae) {
            throw uae;
        } catch (NoSuchSessionException enve) {
            // Pause, retry
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // Ignore
            }
            if (retry >= 0) {
                return this.findHelper(wrapper, by, retry - 1);
            }
        } catch (UnreachableBrowserException ube) {
            // Pause, retry
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // Ignore
            }
            if (retry >= 0) {
                return this.findHelper(wrapper, by, retry - 1);
            }
        } catch (ElementNotInteractableException enve) {
            LOGGER.debug(enve);
        } catch (TimeoutException wde) {
            LOGGER.debug(wde);
        } catch (WebDriverException wde) {
            LOGGER.debug(wde);
        }
        return new ArrayList<>();
    }

    private String getAlertDialogText() {
        try {
            org.openqa.selenium.Alert alertDialog = driver.getDriver().switchTo().alert();
            String dialogText = alertDialog.getText();
            alertDialog.accept();
            return dialogText;
        } catch (WebDriverException wde) {
            return "";
        }
    }

    private DomAlertInfo scanHelper(String attackVector, String url) {
        if (this.isStop()) {
            return null;
        }
        try {
            getHelper(driver, url);
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText().equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.get1");
                return new DomAlertInfo(url, attackVector);
            }
        }

        List<WebElement> possibleDomXSSTriggers = new ArrayList<>();

        try {
            possibleDomXSSTriggers = findHelper(driver, By.tagName("input"));
            possibleDomXSSTriggers.addAll(findHelper(driver, By.tagName("button")));
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText().equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.input1");
                vulnerable = true;
                return new DomAlertInfo(url, attackVector);
            }
        }

        for (int i = 0; i < possibleDomXSSTriggers.size(); i++) {
            if (this.isStop()) {
                return null;
            }
            WebElement element = possibleDomXSSTriggers.get(i);
            String xpath = getXPath(element);
            String tagName = null;
            String attributeId = null;
            String attributeName = null;
            try {
                // Save for the evidence
                tagName = element.getTagName();
                attributeId = element.getDomAttribute("id");
                attributeName = element.getDomAttribute("name");

                if (tagName.equals("input")) {
                    steps.add(
                            Constant.messages.getString("domxss.step.input", xpath, attackVector));
                    element.sendKeys(attackVector);
                }

                addClickStep(xpath);
                element.click();
            } catch (UnhandledAlertException uae) {
                // Ignore
            } catch (WebDriverException wde) {
                LOGGER.debug(wde);
            } finally {
                if (getAlertDialogText().equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.possibleDomXSSTriggers2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }

            try {
                getHelper(driver, url);
            } catch (UnhandledAlertException uae) {
                // Ignore
            } finally {
                if (getAlertDialogText().equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.get2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
            try {
                possibleDomXSSTriggers = findHelper(driver, By.tagName("input"));
                possibleDomXSSTriggers.addAll(findHelper(driver, By.tagName("button")));
            } catch (UnhandledAlertException uae) {
                // Ignore
            } finally {
                if (getAlertDialogText().equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.possibleDomXSSTriggers3");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
        }
        List<WebElement> allElements = new ArrayList<>();
        try {
            allElements = findHelper(driver, By.tagName("div"));
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText().equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.div1");
                return new DomAlertInfo(url, attackVector);
            }
        }
        for (int i = 0; i < allElements.size(); i++) {
            if (this.isStop()) {
                return null;
            }
            WebElement element = allElements.get(i);
            String xpath = getXPath(element);
            String tagName = null;
            String attributeId = null;
            String attributeName = null;

            try {
                // Save for the evidence
                tagName = element.getTagName();
                attributeId = element.getDomAttribute("id");
                attributeName = element.getDomAttribute("name");

                addClickStep(xpath);
                element.click();
                getHelper(driver, url);
                allElements = findHelper(driver, By.tagName("div"));
            } catch (UnhandledAlertException uae) {
                // Ignore
            } catch (NoSuchSessionException enve) {
                LOGGER.debug(enve);
                // replaceDriver(driver);
            } catch (ElementNotInteractableException enve) {
                LOGGER.debug(enve);
            } catch (TimeoutException wde) {
                LOGGER.debug(wde);
            } catch (WebDriverException wde) {
                LOGGER.debug(wde);
            } finally {
                if (getAlertDialogText().equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.div2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
        }
        return null;
    }

    private void addClickStep(String xpath) {
        steps.add(Constant.messages.getString("domxss.step.click", xpath));
    }

    @Override
    public void scan() {
        Stats.incCounter("domxss.scan.count");
        ArrayList<String> attackVectors = new ArrayList<>();
        int numberOfAttackStrings;

        switch (this.getAttackStrength()) {
            case LOW:
                numberOfAttackStrings = 1;
                break;
            case MEDIUM:
            default:
                numberOfAttackStrings = 3;
                break;
            case HIGH:
                numberOfAttackStrings = 6;
                break;
            case INSANE:
                numberOfAttackStrings = ATTACK_STRINGS.length;
                break;
        }

        for (int i = 0; i < numberOfAttackStrings; i++) {
            attackVectors.add(ATTACK_STRINGS[i]);
        }

        try {
            driver = getWebDriver();
        } catch (Exception e) {
            LOGGER.warn("Skipping scanner, failed to start browser: {}", e.getMessage());
            getParent()
                    .pluginSkipped(
                            this,
                            Constant.messages.getString("domxss.skipped.reason.browsererror"));
            return;
        }

        try {
            for (String attackVector : attackVectors) {
                steps.clear();
                if (scan(
                        attackVector,
                        getBaseMsg().getRequestHeader().getURI().toString() + attackVector)) {
                    if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                        // Only report one issue per URL unless
                        // Alert threshold is LOW
                        break;
                    }
                }
            }
            super.scan();
        } finally {
            this.returnDriver(driver);
        }
    }

    private static String getXPath(WebElement element) {
        StringBuilder strBuilder = new StringBuilder(100);
        try {
            insertXPath(element, strBuilder);
        } catch (Exception e) {
            LOGGER.debug("Failed to obtain full XPath: {}", e.getMessage());
            strBuilder.insert(0, Constant.messages.getString("domxss.step.partial.xpath"));
        }
        return strBuilder.toString();
    }

    private static void insertXPath(WebElement element, StringBuilder path) {
        String tag = element.getTagName();
        if ("html".equalsIgnoreCase(tag)) {
            insertTag(path, tag);
            return;
        }

        WebElement parent = element.findElement(By.xpath(".."));
        List<WebElement> children = parent.findElements(By.tagName(tag));
        if (children.size() != 1) {
            path.insert(0, "]");
            path.insert(0, children.indexOf(element) + 1);
            path.insert(0, "[");
        }

        insertTag(path, tag);
        insertXPath(parent, path);
    }

    private static void insertTag(StringBuilder path, String tag) {
        path.insert(0, tag);
        path.insert(0, "/");
    }

    public boolean scan(String attackVector, String currUrl) {
        return scan(attackVector, "", currUrl);
    }

    private boolean scan(String attackVector, String processedAttackVector, String currUrl) {
        HttpMessage msg = getBaseMsg();

        DomAlertInfo result = scanHelper(attackVector, currUrl);
        if (result != null) {
            StringBuilder otherInfo = new StringBuilder();
            otherInfo.append(Constant.messages.getString("domxss.step.intro")).append('\n');
            steps.replaceAll(e -> e.replace(result.getAttack(), PAYLOAD_0));

            if (contains(steps, PAYLOAD_0)) {
                appendPayloadStep(otherInfo, PAYLOAD_0, result.getAttack());
            }

            if (!processedAttackVector.isEmpty()) {
                steps.replaceAll(e -> e.replace(processedAttackVector, PAYLOAD_1));
                if (contains(steps, PAYLOAD_1)) {
                    appendPayloadStep(otherInfo, PAYLOAD_1, processedAttackVector);
                }
            }
            steps.forEach(e -> otherInfo.append(e).append('\n'));

            buildAlert()
                    .setUri(result.getUrl())
                    .setAttack(result.getAttack())
                    .setOtherInfo(otherInfo.toString())
                    .setMessage(msg)
                    .raise();
            Stats.incCounter("domxss.attack." + attackVector);
            vulnerable = true;
            return true;
        }
        return false;
    }

    private void appendPayloadStep(StringBuilder otherInfo, String payload, String attack) {
        otherInfo
                .append(Constant.messages.getString("domxss.step.payload", payload, attack))
                .append('\n');
    }

    private static boolean contains(List<String> list, String value) {
        return list.stream().anyMatch(e -> e.contains(value));
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public AttackStrength[] getAttackStrengthsSupported() {
        return new AttackStrength[] {
            AttackStrength.LOW, AttackStrength.MEDIUM, AttackStrength.HIGH, AttackStrength.INSANE
        };
    }

    @Override
    public AlertThreshold[] getAlertThresholdsSupported() {
        return new AlertThreshold[] {AlertThreshold.LOW, AlertThreshold.MEDIUM};
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        if (originalParam.getType() != NameValuePair.TYPE_QUERY_STRING) {
            return; // Exit if it isn't a URL param
        }
        if (!vulnerable) {
            super.scan(msg, originalParam);
        }
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String attack) {
        Stats.incCounter("domxss.scan.count");

        for (String attackVector : PARAM_ATTACK_STRINGS) {
            steps.clear();
            TreeSet<HtmlParameter> urlParams = msg.getUrlParams();
            for (HtmlParameter param : urlParams) {
                if (param.getName().equals(paramName)) {
                    param.setValue(attackVector);
                }
            }
            msg.setGetParams(
                    urlParams); // setParameter and setEscapedParameter results in spaces being + vs
            // %20 (or actual space)

            if (scan(
                    attackVector,
                    getEncodedValue(
                            msg.getRequestHeader().getURI().getEscapedQuery(),
                            paramName,
                            attackVector),
                    msg.getRequestHeader().getURI().toString())) {
                if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                    // Only report one issue per URL unless
                    // Alert threshold is LOW
                    break;
                }
            }
        }
    }

    private static String getEncodedValue(String escapedQuery, String paramName, String fallback) {
        var result =
                Stream.of(escapedQuery.split("&")).filter(e -> e.startsWith(paramName)).findFirst();
        if (result.isEmpty()) {
            return fallback;
        }
        return result.get().split("=", 2)[1];
    }

    private AlertBuilder buildAlert() {
        return newAlert().setConfidence(Alert.CONFIDENCE_HIGH);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Collections.singletonList(buildAlert().build());
    }
}
