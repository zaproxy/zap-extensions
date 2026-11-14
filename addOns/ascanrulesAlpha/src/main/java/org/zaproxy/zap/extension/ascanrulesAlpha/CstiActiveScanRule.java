/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import lombok.AccessLevel;
import lombok.Setter;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.support.ui.FluentWait;
import org.openqa.selenium.support.ui.Wait;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

public class CstiActiveScanRule extends AbstractAppPlugin {

    enum EngineConfidence {
        LOW,
        HIGH,
        VERY_HIGH
    }

    private static final Logger LOGGER = LogManager.getLogger(CstiActiveScanRule.class);
    private static final int PLUGIN_ID = 553542;
    private static final String MESSAGE_PREFIX = "ascanalpha.csti.";
    private static final String RULE_BROWSER_ID = "rules.ascanalpha.csti.browserid";
    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX_HEADLESS;
    private static final String URL_CHARSET = "UTF-8";

    private static final AtomicReference<WebDriver> sharedDriver = new AtomicReference<>(null);
    private static final ReentrantLock browserLock = new ReentrantLock();

    private static final Set<String> scannedKeys = ConcurrentHashMap.newKeySet();

    private static final AtomicInteger activeInstances = new AtomicInteger(0);

    private static final AtomicBoolean urlSetReady = new AtomicBoolean(false);

    private final AtomicBoolean destroyCalled = new AtomicBoolean(false);

    @Setter(AccessLevel.PACKAGE)
    private WebDriver testDriver;

    @Setter(AccessLevel.PACKAGE)
    private ExtensionClientIntegration extensionClientIntegration;

    private Browser preferredBrowser = DEFAULT_BROWSER;

    private static final String SNAPSHOT_PAYLOAD =
            "try {"
                    + "  var expected = String(arguments[0] || '');"
                    + "  function count(haystack, needle) {"
                    + "    if (!haystack || !needle) return 0;"
                    + "    var count = 0, index = 0;"
                    + "    while ((index = haystack.indexOf(needle, index)) !== -1) {"
                    + "      count++;"
                    + "      index += needle.length;"
                    + "    }"
                    + "    return count;"
                    + "  }"
                    + "  var text = document.body ? document.body.innerText : '';"
                    + "  var html = document.documentElement ? document.documentElement.outerHTML : '';"
                    + "  return {"
                    + "    textMatches: count(text, expected),"
                    + "    htmlMatches: count(html, expected)"
                    + "  };"
                    + "} catch (e) { return { textMatches: 0, htmlMatches: 0, error: String(e) }; }";
    private static final String FORM_INJECTION_PAYLOAD =
            "try {"
                    + "  var specs = arguments[0] || [];"
                    + "  function dispatchBubbledEvent(el, type) {"
                    + "    try { el.dispatchEvent(new Event(type, { bubbles: true })); } catch (e) {}"
                    + "  }"
                    + "  function findTarget(spec) {"
                    + "    var tag = String(spec.tag || '');"
                    + "    var id = String(spec.id || '');"
                    + "    var name = String(spec.name || '');"
                    + "    if (id) {"
                    + "      var byId = document.getElementById(id);"
                    + "      if (byId) return byId;"
                    + "    }"
                    + "    if (name) {"
                    + "      var loweredTag = tag ? tag.toLowerCase() : '';"
                    + "      var candidates = document.querySelectorAll(loweredTag ? loweredTag + '[name]' : '[name]');"
                    + "      for (var i = 0; i < candidates.length; i++) {"
                    + "        if ((candidates[i].getAttribute('name') || '') === name) return candidates[i];"
                    + "      }"
                    + "    }"
                    + "    return null;"
                    + "  }"
                    + "  function controlType(el) {"
                    + "    return ((el && el.getAttribute && el.getAttribute('type')) || (el && el.type) || '').toLowerCase();"
                    + "  }"
                    + "  function targetValue(el, payload) {"
                    + "    var type = controlType(el);"
                    + "    if (type === 'email') return 'zap+' + payload + '@example.com';"
                    + "    if (type === 'url') return 'https://example.com/?zap=' + payload;"
                    + "    if (type === 'tel') return '+15555550100' + payload;"
                    + "    return payload;"
                    + "  }"
                    + "  function fillerValue(el) {"
                    + "    var tag = (el.tagName || '').toLowerCase();"
                    + "    var type = controlType(el);"
                    + "    if (tag === 'textarea') return 'ZAP';"
                    + "    if (type === 'email') return 'zap@example.com';"
                    + "    if (type === 'url') return 'https://example.com/';"
                    + "    if (type === 'number' || type === 'range') return '1';"
                    + "    if (type === 'date') return '2026-01-01';"
                    + "    if (type === 'datetime-local') return '2026-01-01T00:00';"
                    + "    if (type === 'month') return '2026-01';"
                    + "    if (type === 'week') return '2026-W01';"
                    + "    if (type === 'time') return '00:00';"
                    + "    if (type === 'color') return '#000000';"
                    + "    if (type === 'tel') return '+15555550100';"
                    + "    return 'ZAP';"
                    + "  }"
                    + "  function isEnterSubmitCandidate(el) {"
                    + "    if (!el) return false;"
                    + "    var tag = (el.tagName || '').toLowerCase();"
                    + "    var type = controlType(el);"
                    + "    if (tag !== 'input') return false;"
                    + "    return type === '' || type === 'text' || type === 'search' || type === 'email'"
                    + "        || type === 'url' || type === 'tel' || type === 'password' || type === 'number';"
                    + "  }"
                    + "  function firstEnterSubmitCandidate(form, targets) {"
                    + "    for (var i = 0; i < targets.length; i++) {"
                    + "      if (isEnterSubmitCandidate(targets[i])) return targets[i];"
                    + "    }"
                    + "    if (!form) return null;"
                    + "    var candidates = form.querySelectorAll('input');"
                    + "    for (var j = 0; j < candidates.length; j++) {"
                    + "      if (isEnterSubmitCandidate(candidates[j])) return candidates[j];"
                    + "    }"
                    + "    return null;"
                    + "  }"
                    + "  function firstSubmitter(form) {"
                    + "    if (!form) return null;"
                    + "    return form.querySelector('button[type=\"submit\"], input[type=\"submit\"], button:not([type])');"
                    + "  }"
                    + "  function createEnterEvent(type) {"
                    + "    var event;"
                    + "    var charCode = type === 'keypress' ? 13 : 0;"
                    + "    try {"
                    + "      event = new KeyboardEvent(type, {"
                    + "        bubbles: true,"
                    + "        cancelable: true,"
                    + "        key: 'Enter',"
                    + "        code: 'Enter',"
                    + "        keyCode: 13,"
                    + "        which: 13,"
                    + "        charCode: charCode"
                    + "      });"
                    + "    } catch (e) {"
                    + "      event = document.createEvent('Event');"
                    + "      event.initEvent(type, true, true);"
                    + "    }"
                    + "    [['keyCode', 13], ['which', 13], ['charCode', charCode]].forEach(function(entry) {"
                    + "      try {"
                    + "        Object.defineProperty(event, entry[0], { get: function() { return entry[1]; } });"
                    + "      } catch (e) {}"
                    + "    });"
                    + "    try { Object.defineProperty(event, 'key', { get: function() { return 'Enter'; } }); } catch (e) {}"
                    + "    try { Object.defineProperty(event, 'code', { get: function() { return 'Enter'; } }); } catch (e) {}"
                    + "    return event;"
                    + "  }"
                    + "  function dispatchEnterSequence(el) {"
                    + "    ['keydown', 'keypress', 'keyup'].forEach(function(type) {"
                    + "      try { el.dispatchEvent(createEnterEvent(type)); } catch (e) {}"
                    + "    });"
                    + "  }"
                    + "  function setValue(el, value) {"
                    + "    var tag = (el.tagName || '').toLowerCase();"
                    + "    var type = controlType(el);"
                    + "    if (type === 'checkbox' || type === 'radio') {"
                    + "      el.checked = true;"
                    + "    } else if (tag === 'select') {"
                    + "      for (var i = 0; i < el.options.length; i++) {"
                    + "        if (!el.options[i].disabled && el.options[i].value !== '') {"
                    + "          el.selectedIndex = i;"
                    + "          break;"
                    + "        }"
                    + "      }"
                    + "    } else if ('value' in el) {"
                    + "      el.value = value;"
                    + "    } else {"
                    + "      el.textContent = value;"
                    + "    }"
                    + "  ['input', 'change', 'keyup', 'blur'].forEach(function(type) {"
                    + "      dispatchBubbledEvent(el, type);"
                    + "  });"
                    + "  }"
                    + "  var found = [];"
                    + "  var targetSet = [];"
                    + "  var targetPayloads = [];"
                    + "  for (var s = 0; s < specs.length; s++) {"
                    + "    var target = findTarget(specs[s]);"
                    + "    if (!target) continue;"
                    + "    found.push({ index: Number(specs[s].index), id: target.id || '', name: target.getAttribute('name') || '', tagName: target.tagName });"
                    + "    targetSet.push(target);"
                    + "    targetPayloads.push(String(specs[s].payload || ''));"
                    + "  }"
                    + "  if (!found.length) return { found: false, submitted: false, targets: [] };"
                    + "  var form = targetSet[0].form || targetSet[0].closest('form');"
                    + "  if (form) {"
                    + "    try { form.noValidate = true; } catch (e) {}"
                    + "    var controls = form.querySelectorAll('input, textarea, select');"
                    + "    for (var c = 0; c < controls.length; c++) {"
                    + "      if (targetSet.indexOf(controls[c]) === -1) setValue(controls[c], fillerValue(controls[c]));"
                    + "    }"
                    + "  }"
                    + "  for (var t = 0; t < targetSet.length; t++) {"
                    + "    targetSet[t].focus();"
                    + "    setValue(targetSet[t], targetValue(targetSet[t], targetPayloads[t]));"
                    + "  }"
                    + "  var submitted = false;"
                    + "  if (form && !form.querySelector('input[type=\"file\"]')) {"
                    + "    try {"
                    + "      var formAction = form.action || window.location.href;"
                    + "      if ((new URL(formAction, window.location.href)).origin === window.location.origin) {"
                    + "        var keyboardTarget = firstEnterSubmitCandidate(form, targetSet);"
                    + "        var submitter = firstSubmitter(form);"
                    + "        var submitObserved = false;"
                    + "        var onSubmit = function() { submitObserved = true; };"
                    + "        try { form.addEventListener('submit', onSubmit, true); } catch (e) {}"
                    + "        submitted = true;"
                    + "        setTimeout(function() {"
                    + "          try {"
                    + "            if (keyboardTarget) {"
                    + "              try { keyboardTarget.focus(); } catch (e) {}"
                    + "              dispatchEnterSequence(keyboardTarget);"
                    + "            }"
                    + "            if (!submitObserved) {"
                    + "              if (typeof form.requestSubmit === 'function') {"
                    + "                try {"
                    + "                  if (submitter) {"
                    + "                    form.requestSubmit(submitter);"
                    + "                  } else {"
                    + "                    form.requestSubmit();"
                    + "                  }"
                    + "                  submitObserved = true;"
                    + "                } catch (e) {}"
                    + "              }"
                    + "            }"
                    + "            if (!submitObserved && submitter) {"
                    + "              try {"
                    + "                submitter.click();"
                    + "                submitObserved = true;"
                    + "              } catch (e) {}"
                    + "            }"
                    + "            if (!submitObserved) {"
                    + "              try {"
                    + "                HTMLFormElement.prototype.submit.call(form);"
                    + "                submitObserved = true;"
                    + "              } catch (e) {}"
                    + "            }"
                    + "          } finally {"
                    + "            try { form.removeEventListener('submit', onSubmit, true); } catch (e) {}"
                    + "          }"
                    + "        }, 0);"
                    + "      }"
                    + "    } catch (e) {}"
                    + "  }"
                    + "  return {"
                    + "    found: true,"
                    + "    submitted: submitted,"
                    + "    targets: found"
                    + "  };"
                    + "} catch (e) { return { found: false, error: String(e) }; }";

    private record InputSurface(
            String tag, String id, String name, String inputType, String source) {
        String key() {
            return String.join(
                    "|",
                    nullToEmpty(tag),
                    nullToEmpty(id),
                    nullToEmpty(name),
                    nullToEmpty(inputType),
                    source);
        }

        String probeKey() {
            return String.join(
                    "|",
                    nullToEmpty(tag),
                    nullToEmpty(id),
                    nullToEmpty(name),
                    nullToEmpty(inputType));
        }

        String describe() {
            return String.format(
                    "type=%-14s  tag=%-10s  inputType=%-10s  id=%-20s  name=%-20s  [%s]",
                    source,
                    nullToEmpty(tag),
                    nullToEmpty(inputType),
                    nullToEmpty(id),
                    nullToEmpty(name),
                    source);
        }
    }

    private record LinkSurface(String href, String id, String source) {
        String describe() {
            return String.format(
                    "type=%-14s  tag=%-10s  id=%-20s  href=%s", source, "A", nullToEmpty(id), href);
        }
    }

    private record UrlParameterSurface(String targetUrl, String paramName, String source) {
        String describe() {
            return String.format(
                    "type=%-14s  location=%-12s  param=%s  url=%s",
                    "URL_PARAM", source, paramName, targetUrl);
        }
    }

    private record ReflectionSnapshot(int textMatches, int htmlMatches) {
        boolean exceeds(ReflectionSnapshot other) {
            return textMatches > other.textMatches || htmlMatches > other.htmlMatches;
        }
    }

    private record ProbeResult(
            String vector,
            String source,
            String attackUrl,
            String payload,
            String expectedResult,
            String observedResult,
            String evidence) {}

    private record ProbeSummary(List<String> attempts, List<ProbeResult> confirmed) {}

    private record DomInputProbe(
            InputSurface surface, ClientSideEngineDetector.PayloadDefinition payloadDefinition) {}

    private record SurfaceReport(
            List<InputSurface> inputSurfaces,
            List<LinkSurface> linkSurfaces,
            List<UrlParameterSurface> urlParamSurfaces,
            List<String> inputFindings,
            List<String> linkFindings,
            List<String> urlParamFindings,
            List<String> allFindings) {}

    private static final Duration CSTI_WAIT_TIMEOUT = Duration.ofSeconds(4);
    private static final Duration CSTI_POLL_INTERVAL = Duration.ofMillis(100);
    private static final long DOM_QUIET_MILLIS = 200;

    private static final String PAGE_SETTLED_PAYLOAD =
            "try {"
                    + "  var quietMillis = Number(arguments[0] || 200);"
                    + "  if (!window.__zapCstiWaitState) {"
                    + "    window.__zapCstiWaitState = { lastMutation: Date.now() };"
                    + "    new MutationObserver(function() {"
                    + "      window.__zapCstiWaitState.lastMutation = Date.now();"
                    + "    }).observe(document.documentElement || document, {"
                    + "      subtree: true,"
                    + "      childList: true,"
                    + "      attributes: true,"
                    + "      characterData: true"
                    + "    });"
                    + "  }"
                    + "  var ready = document.readyState === 'complete';"
                    + "  var domQuiet = Date.now() - window.__zapCstiWaitState.lastMutation >= quietMillis;"
                    + "  return ready && domQuiet;"
                    + "} catch (e) {"
                    + "  return document.readyState === 'complete';"
                    + "}";

    public static boolean waitForPageToSettle(WebDriver driver) {
        try {
            Wait<WebDriver> wait =
                    new FluentWait<>(driver)
                            .withTimeout(CSTI_WAIT_TIMEOUT)
                            .pollingEvery(CSTI_POLL_INTERVAL)
                            .ignoring(WebDriverException.class);

            return Boolean.TRUE.equals(
                    wait.until(
                            d ->
                                    Objects.requireNonNull(
                                            ((JavascriptExecutor) d)
                                                    .executeScript(
                                                            PAGE_SETTLED_PAYLOAD,
                                                            DOM_QUIET_MILLIS))));
        } catch (TimeoutException e) {
            LOGGER.debug("CSTI: page did not fully settle within {}", CSTI_WAIT_TIMEOUT);
            return false;
        }
    }

    @Override
    public void init() {
        destroyCalled.set(false);
        preferredBrowser = resolvePreferredBrowser();
        int instances = activeInstances.incrementAndGet();
        LOGGER.debug("CSTI: init() active instance count={}", instances);

        if (urlSetReady.compareAndSet(false, true)) {
            scannedKeys.clear();
            LOGGER.debug("CSTI: scannedKeys cleared for new scan run.");
        }

        initSharedDriver();
    }

    @Override
    public void setTimeFinished() {
        super.setTimeFinished();
        destroy();
    }

    public void destroy() {
        if (!destroyCalled.compareAndSet(false, true)) return;

        browserLock.lock();
        try {
            int remaining = activeInstances.decrementAndGet();
            if (remaining < 0) {
                activeInstances.set(0);
                remaining = 0;
                LOGGER.warn("CSTI: active instance count went negative; reset to 0.");
            }
            if (remaining > 0) {
                LOGGER.debug("CSTI: keeping WebDriver alive, remaining instances={}", remaining);
                return;
            }

            urlSetReady.set(false);

            WebDriver driver = sharedDriver.getAndSet(null);
            if (driver != null) {
                try {
                    driver.quit();
                    LOGGER.info("CSTI: WebDriver closed.");
                } catch (Exception e) {
                    LOGGER.debug("CSTI: error closing WebDriver: {}", e.getMessage());
                }
            }
        } finally {
            browserLock.unlock();
        }
    }

    void initSharedDriver() {
        browserLock.lock();
        try {
            if (testDriver != null) {
                sharedDriver.set(testDriver);
                LOGGER.debug("CSTI: test WebDriver installed.");
                return;
            }

            WebDriver existing = sharedDriver.get();
            if (isDriverUsable(existing)) {
                LOGGER.debug("CSTI: reusing existing shared WebDriver.");
                return;
            }

            if (existing != null) {
                try {
                    existing.quit();
                } catch (Exception ignored) {
                }
                sharedDriver.set(null);
            }

            ExtensionSelenium extSelenium =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);
            if (extSelenium == null) {
                LOGGER.warn("CSTI: Selenium add-on not available – engine detection disabled.");
                return;
            }

            ExtensionNetwork extNetwork =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionNetwork.class);
            if (extNetwork == null) {
                LOGGER.warn("CSTI: Network add-on not available – browser proxying disabled.");
                return;
            }

            ServerInfo proxyServerInfo = extNetwork.getMainProxyServerInfo();
            String proxyAddress = proxyServerInfo.getAddress();
            int proxyPort = proxyServerInfo.getPort();
            try {
                WebDriver driver =
                        ExtensionSelenium.getWebDriver(
                                HttpSender.ACTIVE_SCANNER_INITIATOR,
                                preferredBrowser,
                                proxyAddress,
                                proxyPort,
                                capabilities ->
                                        capabilities.setCapability(
                                                org.openqa.selenium.remote.CapabilityType
                                                        .UNHANDLED_PROMPT_BEHAVIOUR,
                                                org.openqa.selenium.UnexpectedAlertBehaviour
                                                        .IGNORE),
                                false);

                driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(10));
                driver.manage().timeouts().scriptTimeout(Duration.ofSeconds(10));

                sharedDriver.set(driver);
                LOGGER.info(
                        "CSTI: WebDriver started with {} (proxy {}:{}).",
                        preferredBrowser,
                        proxyAddress,
                        proxyPort);
            } catch (Exception e) {
                LOGGER.warn(
                        "CSTI: failed to start {} WebDriver: {}", preferredBrowser, e.getMessage());
            }
        } finally {
            browserLock.unlock();
        }
    }

    private Browser resolvePreferredBrowser() {
        String browserId = null;
        try {
            browserId = getConfig().getString(RULE_BROWSER_ID, DEFAULT_BROWSER.getId());
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_BROWSER_ID,
                    getConfig().getString(RULE_BROWSER_ID));
        }
        return resolvePreferredBrowser(browserId);
    }

    Browser resolvePreferredBrowser(String browserId) {
        if (browserId == null || browserId.isEmpty()) return DEFAULT_BROWSER;
        Browser browser = Browser.getBrowserWithIdNoFailSafe(browserId);
        if (browser == null) return DEFAULT_BROWSER;
        if (!isSupportedBrowser(browser)) {
            LOGGER.warn("Browser {} not supported, defaulting to: {}", browser, DEFAULT_BROWSER);
            return DEFAULT_BROWSER;
        }
        return browser;
    }

    private static boolean isSupportedBrowser(Browser browser) {
        return browser == Browser.FIREFOX
                || browser == Browser.FIREFOX_HEADLESS
                || browser == Browser.CHROME
                || browser == Browser.CHROME_HEADLESS
                || browser == Browser.EDGE
                || browser == Browser.EDGE_HEADLESS;
    }

    @Override
    public void scan() {
        if (isStop()) return;

        HttpMessage msg = getBaseMsg();
        String fullUrl = toEscapedUriString(msg.getRequestHeader().getURI());

        LOGGER.debug("CSTI: scan() entered for {}", fullUrl);

        String dedupKey = deduplicationKey(fullUrl);
        if (!scannedKeys.add(dedupKey)) {
            LOGGER.debug("CSTI: skipping already-scanned page (key={})", dedupKey);
            return;
        }

        ExtensionClientIntegration extClient = resolveClientExtension();
        if (extClient == null) {
            LOGGER.debug("CSTI: Client add-on not available – skipping {}.", fullUrl);
            return;
        }

        SurfaceReport surfaceReport = buildSurfaceReport(msg, fullUrl, extClient);
        if (surfaceReport == null) {
            LOGGER.debug(
                    "CSTI: no usable components for {} (spider + HTML + URL params all empty).",
                    fullUrl);
            return;
        }

        // Phase B – engine detection.
        String canonicalUrl = deduplicationKey(fullUrl);
        ClientSideEngineDetector.DetectionResult engine = detectEngine(canonicalUrl);
        EngineConfidence engineConfidence = scoreEngineDetectionConfidence(engine);

        LOGGER.info(
                "CSTI: {} input(s), {} link(s), {} URL param surface(s) for {}",
                surfaceReport.inputFindings().size(),
                surfaceReport.linkFindings().size(),
                surfaceReport.urlParamFindings().size(),
                fullUrl);
        surfaceReport.allFindings().forEach(f -> LOGGER.info("  {}", f));

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(toZapAlertConfidence(engineConfidence))
                .setName(message("alert.engine.name", getName()))
                .setDescription(
                        buildEngineDetectionReport(
                                surfaceReport.inputFindings(),
                                surfaceReport.linkFindings(),
                                engine,
                                engineConfidence))
                .setMessage(msg)
                .raise();

        ClientSideEngineDetector.PayloadDefinition payloadDefinition =
                ClientSideEngineDetector.getPayloadDefinition(engine.engineName());
        ProbeSummary probeSummary =
                probeForCsti(
                        canonicalUrl,
                        surfaceReport.inputSurfaces(),
                        surfaceReport.urlParamSurfaces(),
                        engine,
                        payloadDefinition);

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(
                        payloadDefinition != null ? Alert.CONFIDENCE_MEDIUM : Alert.CONFIDENCE_LOW)
                .setName(message("alert.payload.name", getName()))
                .setDescription(buildProbeReport(engine, payloadDefinition, probeSummary))
                .setMessage(msg)
                .raise();

        if (!probeSummary.confirmed().isEmpty()) {
            raiseConfirmedCstiAlert(msg, engine, engineConfidence, probeSummary.confirmed().get(0));
        }
    }

    private SurfaceReport buildSurfaceReport(
            HttpMessage msg, String fullUrl, ExtensionClientIntegration extClient) {

        // Phase A – gather injection surfaces.
        List<InputSurface> inputSurfaces = new ArrayList<>();
        List<LinkSurface> linkSurfaces = new ArrayList<>();

        ClientNode node = resolveNode(extClient, fullUrl);
        if (node != null) {
            collectFindings(node, inputSurfaces, linkSurfaces);
            LOGGER.debug(
                    "CSTI: spider yielded {} input(s), {} link(s) for {}",
                    inputSurfaces.size(),
                    linkSurfaces.size(),
                    fullUrl);
        } else {
            LOGGER.debug("CSTI: no client spider node for {}.", fullUrl);
        }

        supplementFromResponseHtml(msg, inputSurfaces);

        List<UrlParameterSurface> urlParamSurfaces =
                collectUrlParameterSurfaces(fullUrl, linkSurfaces);

        List<String> inputFindings = describeInputs(inputSurfaces);
        List<String> linkFindings = describeLinks(linkSurfaces);
        List<String> urlParamFindings = describeUrlParams(urlParamSurfaces);

        List<String> allFindings = new ArrayList<>(inputFindings);
        allFindings.addAll(linkFindings);
        allFindings.addAll(urlParamFindings);

        if (allFindings.isEmpty()) {
            return null;
        }

        return new SurfaceReport(
                inputSurfaces,
                linkSurfaces,
                urlParamSurfaces,
                inputFindings,
                linkFindings,
                urlParamFindings,
                allFindings);
    }

    String deduplicationKey(String fullUrl) {
        String bare = stripQueryAndFragment(fullUrl);
        if (bare == null) return fullUrl;
        int end = bare.length();
        while (end > 1 && bare.charAt(end - 1) == '/') end--;
        return end == bare.length() ? bare : bare.substring(0, end);
    }

    private ClientNode resolveNode(ExtensionClientIntegration extClient, String fullUrl) {
        ClientNode node = lookupClientNode(extClient, fullUrl);
        if (node != null) return node;

        String bare = stripQueryAndFragment(fullUrl);
        if (!bare.equals(fullUrl)) {
            node = lookupClientNode(extClient, bare);
            if (node != null) return node;

            node = lookupClientNode(extClient, bare + "/");
            return node;
        } else if (!fullUrl.endsWith("/")) {
            node = lookupClientNode(extClient, fullUrl + "/");
            return node;
        }

        return null;
    }

    private ClientNode lookupClientNode(ExtensionClientIntegration extClient, String url) {
        try {
            Method getClientNode =
                    extClient
                            .getClass()
                            .getMethod("getClientNode", String.class, boolean.class, boolean.class);
            Object result = getClientNode.invoke(extClient, url, false, false);
            if (result instanceof ClientNode clientNode) {
                return clientNode;
            }
        } catch (ReflectiveOperationException e) {
            LOGGER.debug(
                    "CSTI: public getClientNode(url, visited, storage) unavailable for {} ({})",
                    url,
                    e.getClass().getSimpleName());
        }

        try {
            Field clientTreeField = extClient.getClass().getDeclaredField("clientTree");
            clientTreeField.setAccessible(true);
            Object clientTree = clientTreeField.get(extClient);
            if (clientTree == null) {
                return null;
            }

            Method getNode =
                    clientTree
                            .getClass()
                            .getMethod("getNode", String.class, boolean.class, boolean.class);
            Object result = getNode.invoke(clientTree, url, false, false);
            if (result instanceof ClientNode clientNode) {
                return clientNode;
            }
        } catch (ReflectiveOperationException e) {
            LOGGER.debug(
                    "CSTI: reflective clientTree lookup failed for {} ({})",
                    url,
                    e.getClass().getSimpleName());
        }

        return null;
    }

    private static void supplementFromResponseHtml(
            HttpMessage msg, List<InputSurface> inputSurfaces) {
        String body = msg.getResponseBody().toString();
        if (body == null || body.isBlank()) return;

        Set<String> knownKeys = buildKnownInputKeys(inputSurfaces);
        Source source = new Source(body);

        addInputSurfacesFromSource(source, "input", knownKeys, inputSurfaces);
        addInputSurfacesFromSource(source, "textarea", knownKeys, inputSurfaces);
    }

    private static void addInputSurfacesFromSource(
            Source source,
            String tagName,
            Set<String> knownKeys,
            List<InputSurface> inputSurfaces) {
        int pos = 0;
        Element element;
        while ((element = source.getNextElement(pos, tagName)) != null) {
            pos = element.getEnd();

            String type = element.getAttributeValue("type");
            if (isNonInjectable(type)) continue;

            InputSurface surface =
                    new InputSurface(
                            tagName.toUpperCase(Locale.ROOT),
                            element.getAttributeValue("id"),
                            element.getAttributeValue("name"),
                            type,
                            "HTML_PARSED");
            if (knownKeys.contains(surface.key())) continue;

            inputSurfaces.add(surface);
            knownKeys.add(surface.key());
        }
    }

    private static Set<String> buildKnownInputKeys(List<InputSurface> inputSurfaces) {
        Set<String> known = new HashSet<>();
        inputSurfaces.forEach(surface -> known.add(surface.key()));
        return known;
    }

    private static boolean isNonInjectable(String type) {
        return "hidden".equalsIgnoreCase(type)
                || "submit".equalsIgnoreCase(type)
                || "button".equalsIgnoreCase(type)
                || "image".equalsIgnoreCase(type)
                || "reset".equalsIgnoreCase(type)
                || "file".equalsIgnoreCase(type);
    }

    private static boolean isPayloadTarget(InputSurface surface) {
        if ("TEXTAREA".equalsIgnoreCase(surface.tag())) {
            return true;
        }
        String type = surface.inputType();
        return type == null
                || type.isBlank()
                || "text".equalsIgnoreCase(type)
                || "search".equalsIgnoreCase(type)
                || "email".equalsIgnoreCase(type)
                || "url".equalsIgnoreCase(type)
                || "tel".equalsIgnoreCase(type)
                || "password".equalsIgnoreCase(type);
    }

    private ClientSideEngineDetector.DetectionResult detectEngine(String url) {
        LOGGER.info("CSTI: engine detection starting for {}", url);
        long lockStart = System.nanoTime();
        browserLock.lock();
        try {
            long waitedMs = (System.nanoTime() - lockStart) / 1_000_000;
            if (waitedMs > 0)
                LOGGER.debug("CSTI: waited {} ms for browser lock (url={})", waitedMs, url);

            WebDriver driver = sharedDriver.get();
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: WebDriver not usable for {}, re-initialising.", url);
                initSharedDriver();
                driver = sharedDriver.get();
            }
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: no usable WebDriver after re-init for {}.", url);
                return new ClientSideEngineDetector.DetectionResult("unknown", "");
            }

            ClientSideEngineDetector.DetectionResult result =
                    ClientSideEngineDetector.detect(driver, url);
            LOGGER.info("CSTI: engine detection result for {} -> {}", url, result);
            return result;
        } finally {
            browserLock.unlock();
        }
    }

    private static boolean isDriverUsable(WebDriver driver) {
        if (driver == null) return false;
        try {
            driver.getWindowHandles();
            return true;
        } catch (Exception e) {
            LOGGER.debug(
                    "CSTI: WebDriver unusable ({}): {}",
                    e.getClass().getSimpleName(),
                    e.getMessage());
            return false;
        }
    }

    private ExtensionClientIntegration resolveClientExtension() {
        if (extensionClientIntegration != null) return extensionClientIntegration;
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class);
    }

    private void collectFindings(
            ClientNode node, List<InputSurface> inputSurfaces, List<LinkSurface> linkSurfaces) {
        ClientSideDetails details = node.getUserObject();
        if (details == null) return;

        for (ClientSideComponent component : details.getComponents()) {
            //            if (component.getType() != ClientSideComponent.Type.NODE_ADDED) continue;
            String tag = component.getTagName();
            if (tag == null || tag.isBlank()) continue;

            if (tag.equalsIgnoreCase("input") || tag.equalsIgnoreCase("textarea")) {
                InputSurface surface = describeInput(component);
                if (surface != null) inputSurfaces.add(surface);
            } else if (tag.equalsIgnoreCase("a")) {
                LinkSurface surface = describeLink(component);
                if (surface != null) linkSurfaces.add(surface);
            }
        }
    }

    private static InputSurface describeInput(ClientSideComponent component) {
        String tag = component.getTagName();
        String type = component.getTagType();
        if (isNonInjectable(type)) {
            return null;
        }
        return new InputSurface(
                tag != null ? tag.toUpperCase(Locale.ROOT) : null,
                component.getId(),
                component.getData().get("name"),
                type,
                component.getType().name());
    }

    private static LinkSurface describeLink(ClientSideComponent component) {
        String href = component.getHref();
        if (href == null || !href.contains("?")) return null;
        return new LinkSurface(href, component.getId(), component.getType().name());
    }

    private static List<String> describeInputs(List<InputSurface> inputSurfaces) {
        List<String> findings = new ArrayList<>();
        inputSurfaces.forEach(surface -> findings.add(surface.describe()));
        return findings;
    }

    private static List<String> describeLinks(List<LinkSurface> linkSurfaces) {
        List<String> findings = new ArrayList<>();
        linkSurfaces.forEach(surface -> findings.add(surface.describe()));
        return findings;
    }

    private static List<String> describeUrlParams(List<UrlParameterSurface> urlParamSurfaces) {
        List<String> findings = new ArrayList<>();
        urlParamSurfaces.forEach(surface -> findings.add(surface.describe()));
        return findings;
    }

    private List<UrlParameterSurface> collectUrlParameterSurfaces(
            String fullUrl, List<LinkSurface> linkSurfaces) {
        List<UrlParameterSurface> surfaces = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();

        addUrlParameterSurfaces(fullUrl, "CURRENT_URL", fullUrl, seen, surfaces);
        for (LinkSurface linkSurface : linkSurfaces) {
            String resolvedUrl = resolveLinkUrl(fullUrl, linkSurface.href());
            if (resolvedUrl == null || !isSameOrigin(fullUrl, resolvedUrl)) {
                continue;
            }
            addUrlParameterSurfaces(resolvedUrl, "CLIENT_LINK", linkSurface.href(), seen, surfaces);
        }

        return surfaces;
    }

    private static void addUrlParameterSurfaces(
            String targetUrl,
            String source,
            String rawHref,
            Set<String> seen,
            List<UrlParameterSurface> surfaces) {
        URI uri = parseEscapedUri(targetUrl, rawHref);
        if (uri == null) {
            return;
        }

        String query = uri.getEscapedQuery();
        if (query == null || query.isBlank()) {
            return;
        }

        for (String part : query.split("&")) {
            if (part.isBlank()) {
                continue;
            }
            String paramName =
                    decodeQueryComponent(
                            part.contains("=") ? part.substring(0, part.indexOf('=')) : part);
            if (paramName == null || paramName.isBlank()) {
                continue;
            }
            String key = targetUrl + "|" + paramName;
            if (seen.add(key)) {
                surfaces.add(new UrlParameterSurface(targetUrl, paramName, source));
            }
        }
    }

    private ProbeSummary probeForCsti(
            String pageUrl,
            List<InputSurface> inputSurfaces,
            List<UrlParameterSurface> urlParamSurfaces,
            ClientSideEngineDetector.DetectionResult engine,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition) {

        List<String> attempts = new ArrayList<>();
        if (!engine.detected()) {
            attempts.add("Skipped: no client-side engine was detected.");
            return new ProbeSummary(attempts, List.of());
        }

        if (payloadDefinition == null) {
            attempts.add(
                    "Skipped: no payload profile is registered for engine '"
                            + engine.engineName()
                            + "'.");
            return new ProbeSummary(attempts, List.of());
        }

        long lockStart = System.nanoTime();
        browserLock.lock();
        try {
            long waitedMs = (System.nanoTime() - lockStart) / 1_000_000;
            if (waitedMs > 0) {
                LOGGER.debug(
                        "CSTI: waited {} ms for browser lock (payload probe {})",
                        waitedMs,
                        pageUrl);
            }

            WebDriver driver = sharedDriver.get();
            if (!isDriverUsable(driver)) {
                initSharedDriver();
                driver = sharedDriver.get();
            }
            if (!isDriverUsable(driver)) {
                attempts.add("Skipped: no usable WebDriver available for payload probing.");
                return new ProbeSummary(attempts, List.of());
            }

            // Filter out URL parameters that belong to other pages (CLIENT_LINK).
            // Only keep the ones that belong to the current page itself (CURRENT_URL).
            List<UrlParameterSurface> ownPageUrlParams =
                    urlParamSurfaces.stream()
                            .filter(s -> !"CLIENT_LINK".equals(s.source()))
                            .toList();

            ProbeResult urlProbe =
                    probeUrlParameters(driver, ownPageUrlParams, payloadDefinition, attempts);
            if (urlProbe != null) {
                return new ProbeSummary(attempts, List.of(urlProbe));
            }

            List<ProbeResult> inputProbes =
                    probeDomInputs(
                            driver,
                            pageUrl,
                            deduplicateInputSurfacesForProbe(inputSurfaces),
                            payloadDefinition,
                            attempts);
            return new ProbeSummary(attempts, inputProbes);
        } finally {
            browserLock.unlock();
        }
    }

    private static List<InputSurface> deduplicateInputSurfacesForProbe(
            List<InputSurface> inputSurfaces) {
        List<InputSurface> deduplicated = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (InputSurface surface : inputSurfaces) {
            if (seen.add(probeDedupKey(surface))) {
                deduplicated.add(surface);
            }
        }
        return deduplicated;
    }

    private static String probeDedupKey(InputSurface surface) {
        String tag = nullToEmpty(surface.tag());
        String inputType = nullToEmpty(surface.inputType());
        if (!nullToEmpty(surface.id()).isBlank()) {
            return String.join("|", tag, "id", nullToEmpty(surface.id()), inputType);
        }
        if (!nullToEmpty(surface.name()).isBlank()) {
            return String.join("|", tag, "name", nullToEmpty(surface.name()), inputType);
        }
        return surface.probeKey();
    }

    private ProbeResult probeUrlParameters(
            WebDriver driver,
            List<UrlParameterSurface> urlParamSurfaces,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition,
            List<String> attempts) {

        int tested = 0;
        int maxProbes = getMaxProbeCount();
        for (UrlParameterSurface surface : urlParamSurfaces) {
            if (tested++ >= maxProbes || isStop()) {
                break;
            }
            ReflectionSnapshot baseline =
                    loadAndSnapshot(
                            driver, surface.targetUrl(), payloadDefinition.expectedResult());
            if (baseline == null) {
                attempts.add(
                        formatProbeAttempt(
                                "URL param [" + surface.paramName() + "] via " + surface.source(),
                                "skipped",
                                false,
                                "baseline capture failed"));
                continue;
            }

            String attackUrl =
                    replaceParameterValue(
                            surface.targetUrl(), surface.paramName(), payloadDefinition.payload());
            if (attackUrl == null) {
                attempts.add(
                        formatProbeAttempt(
                                "URL param [" + surface.paramName() + "] via " + surface.source(),
                                "skipped",
                                false,
                                "attack URL could not be built"));
                continue;
            }

            ReflectionSnapshot attacked =
                    loadAndSnapshot(driver, attackUrl, payloadDefinition.expectedResult());
            if (attacked == null) {
                attempts.add(
                        formatProbeAttempt(
                                "URL param [" + surface.paramName() + "] via " + surface.source(),
                                "skipped",
                                false,
                                "attack page load failed"));
                continue;
            }

            boolean matched = attacked.exceeds(baseline);
            String observedResult =
                    matched ? payloadDefinition.expectedResult() : message("value.notObserved");
            String evidence = reflectionEvidence(baseline, attacked);
            attempts.add(
                    formatProbeAttempt(
                            "URL param [" + surface.paramName() + "] via " + surface.source(),
                            observedResult,
                            matched,
                            null));

            if (matched) {
                return new ProbeResult(
                        "url-parameter",
                        surface.paramName(),
                        attackUrl,
                        payloadDefinition.payload(),
                        payloadDefinition.expectedResult(),
                        observedResult,
                        evidence);
            }
        }
        return null;
    }

    private static ReflectionSnapshot waitForSnapshotChange(
            WebDriver driver, String expectedResult, ReflectionSnapshot baseline) {

        AtomicReference<ReflectionSnapshot> lastSnapshot = new AtomicReference<>();

        try {
            Wait<WebDriver> wait =
                    new FluentWait<>(driver)
                            .withTimeout(CSTI_WAIT_TIMEOUT)
                            .pollingEvery(CSTI_POLL_INTERVAL)
                            .ignoring(WebDriverException.class);

            return wait.until(
                    d -> {
                        ReflectionSnapshot snapshot =
                                captureSnapshot((JavascriptExecutor) d, expectedResult);

                        if (snapshot != null) {
                            lastSnapshot.set(snapshot);
                        }

                        return snapshot != null && snapshot.exceeds(baseline) ? snapshot : null;
                    });
        } catch (TimeoutException e) {
            return lastSnapshot.get();
        }
    }

    private List<ProbeResult> probeDomInputs(
            WebDriver driver,
            String pageUrl,
            List<InputSurface> inputSurfaces,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition,
            List<String> attempts) {

        if (payloadDefinition.supportsUniqueOperands()) {
            return probeDomInputsWithUniquePayloads(
                    driver, pageUrl, inputSurfaces, payloadDefinition, attempts);
        }

        return probeDomInputsIndividually(
                driver, pageUrl, inputSurfaces, payloadDefinition, attempts);
    }

    private List<ProbeResult> probeDomInputsWithUniquePayloads(
            WebDriver driver,
            String pageUrl,
            List<InputSurface> inputSurfaces,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition,
            List<String> attempts) {

        int maxProbes = getMaxProbeCount();
        List<DomInputProbe> probes = new ArrayList<>();
        for (InputSurface surface : inputSurfaces) {
            if (probes.size() >= maxProbes || isStop()) {
                break;
            }
            if (!isPayloadTarget(surface)) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "input type is not suitable for template payloads"));
                continue;
            }
            probes.add(
                    new DomInputProbe(
                            surface, payloadDefinition.withOperand(11111 + probes.size())));
        }

        if (probes.isEmpty()) {
            return List.of();
        }

        JavascriptExecutor js = (JavascriptExecutor) driver;
        try {
            driver.get(pageUrl);
            waitForPageToSettle(driver);
        } catch (Exception e) {
            attempts.add(
                    formatProbeAttempt("DOM input batch", "skipped", false, "page load failed"));
            return List.of();
        }

        Map<DomInputProbe, ReflectionSnapshot> baselines = new LinkedHashMap<>();
        for (DomInputProbe probe : probes) {
            ReflectionSnapshot baseline =
                    captureSnapshot(js, probe.payloadDefinition().expectedResult());
            if (baseline == null) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + probe.surface().describe() + "]",
                                "skipped",
                                false,
                                "baseline capture failed"));
            } else {
                baselines.put(probe, baseline);
            }
        }

        if (baselines.isEmpty()) {
            return List.of();
        }

        Object result;
        try {
            result = js.executeScript(FORM_INJECTION_PAYLOAD, buildInjectionSpecs(probes));
            waitForPageToSettle(driver);
        } catch (Exception e) {
            attempts.add(
                    formatProbeAttempt(
                            "DOM input batch",
                            "skipped",
                            false,
                            "injection script failed" + formatProbeError(e.getMessage())));
            return List.of();
        }

        if (!(result instanceof Map<?, ?> data) || !Boolean.TRUE.equals(data.get("found"))) {
            String error =
                    result instanceof Map<?, ?> dataMap
                            ? safeProbeError(dataMap.get("error"))
                            : null;
            attempts.add(
                    formatProbeAttempt(
                            "DOM input batch",
                            "skipped",
                            false,
                            error != null
                                    ? "injection error" + formatProbeError(error)
                                    : "no target inputs found"));
            return List.of();
        }

        Set<Integer> foundIndexes = targetIndexes(data.get("targets"));
        boolean submitted = Boolean.TRUE.equals(data.get("submitted"));
        List<ProbeResult> confirmed = new ArrayList<>();
        for (int i = 0; i < probes.size(); i++) {
            DomInputProbe probe = probes.get(i);
            if (!baselines.containsKey(probe)) {
                continue;
            }
            if (!foundIndexes.contains(i)) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + probe.surface().describe() + "]",
                                "skipped",
                                false,
                                "target not found"));
                continue;
            }

            ClientSideEngineDetector.PayloadDefinition actualPayload = probe.payloadDefinition();
            ReflectionSnapshot attacked =
                    waitForSnapshotChange(
                            driver, actualPayload.expectedResult(), baselines.get(probe));
            if (attacked == null) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + probe.surface().describe() + "]",
                                "skipped",
                                false,
                                "attack snapshot failed"));
                continue;
            }

            ReflectionSnapshot baseline = baselines.get(probe);
            boolean matched = attacked.exceeds(baseline);
            String observedResult =
                    matched ? actualPayload.expectedResult() : message("value.notObserved");
            String evidence = reflectionEvidence(baseline, attacked);
            attempts.add(
                    formatProbeAttempt(
                            "Input [" + probe.surface().describe() + "]",
                            observedResult,
                            matched,
                            submitted
                                    ? "form submitted; unique operand payload"
                                    : "unique operand payload"));

            if (matched) {
                confirmed.add(
                        new ProbeResult(
                                "dom-input",
                                probe.surface().describe(),
                                pageUrl,
                                actualPayload.payload(),
                                actualPayload.expectedResult(),
                                observedResult,
                                evidence));
            }
        }

        return confirmed;
    }

    private List<ProbeResult> probeDomInputsIndividually(
            WebDriver driver,
            String pageUrl,
            List<InputSurface> inputSurfaces,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition,
            List<String> attempts) {

        int tested = 0;
        int maxProbes = getMaxProbeCount();
        JavascriptExecutor js = (JavascriptExecutor) driver;

        for (InputSurface surface : inputSurfaces) {
            if (tested++ >= maxProbes || isStop()) {
                break;
            }
            if (!isPayloadTarget(surface)) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "input type is not suitable for template payloads"));
                continue;
            }

            try {
                driver.get(pageUrl);
                waitForPageToSettle(driver);
            } catch (Exception e) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "page load failed"));
                continue;
            }

            ReflectionSnapshot baseline = captureSnapshot(js, payloadDefinition.expectedResult());
            if (baseline == null) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "baseline capture failed"));
                continue;
            }

            Object result;
            try {
                result =
                        js.executeScript(
                                FORM_INJECTION_PAYLOAD,
                                buildInjectionSpecs(
                                        List.of(new DomInputProbe(surface, payloadDefinition))));
                waitForPageToSettle(driver);
            } catch (Exception e) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "injection script failed" + formatProbeError(e.getMessage())));
                continue;
            }

            if (!(result instanceof Map<?, ?> data) || !Boolean.TRUE.equals(data.get("found"))) {
                String error =
                        result instanceof Map<?, ?> dataMap
                                ? safeProbeError(dataMap.get("error"))
                                : null;
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                error != null
                                        ? "injection error" + formatProbeError(error)
                                        : "target not found"));
                continue;
            }

            boolean submitted = Boolean.TRUE.equals(data.get("submitted"));

            ReflectionSnapshot attacked =
                    waitForSnapshotChange(driver, payloadDefinition.expectedResult(), baseline);
            if (attacked == null) {
                attempts.add(
                        formatProbeAttempt(
                                "Input [" + surface.describe() + "]",
                                "skipped",
                                false,
                                "attack snapshot failed"));
                continue;
            }

            boolean matched = attacked.exceeds(baseline);
            String observedResult =
                    matched ? payloadDefinition.expectedResult() : message("value.notObserved");
            String evidence = reflectionEvidence(baseline, attacked);
            attempts.add(
                    formatProbeAttempt(
                            "Input [" + surface.describe() + "]",
                            observedResult,
                            matched,
                            submitted
                                    ? "form submitted; other form fields filled"
                                    : "other form fields filled"));

            if (matched) {
                return List.of(
                        new ProbeResult(
                                "dom-input",
                                surface.describe(),
                                pageUrl,
                                payloadDefinition.payload(),
                                payloadDefinition.expectedResult(),
                                observedResult,
                                evidence));
            }
        }

        return List.of();
    }

    private static String safeProbeError(Object raw) {
        if (raw instanceof String text && !text.isBlank()) {
            return text;
        }
        return null;
    }

    private static String formatProbeError(String error) {
        if (error == null || error.isBlank()) {
            return "";
        }
        return message("probe.error", error);
    }

    private static List<Map<String, Object>> buildInjectionSpecs(List<DomInputProbe> probes) {
        List<Map<String, Object>> specs = new ArrayList<>();
        for (int i = 0; i < probes.size(); i++) {
            DomInputProbe probe = probes.get(i);
            Map<String, Object> spec = new LinkedHashMap<>();
            spec.put("index", i);
            spec.put("tag", probe.surface().tag());
            spec.put("id", probe.surface().id());
            spec.put("name", probe.surface().name());
            spec.put("payload", probe.payloadDefinition().payload());
            specs.add(spec);
        }
        return specs;
    }

    private static Set<Integer> targetIndexes(Object rawTargets) {
        Set<Integer> indexes = new HashSet<>();
        if (!(rawTargets instanceof List<?> targets)) {
            return indexes;
        }
        for (Object target : targets) {
            if (target instanceof Map<?, ?> map) {
                Object index = map.get("index");
                if (index instanceof Number number) {
                    indexes.add(number.intValue());
                } else if (index instanceof String text) {
                    try {
                        indexes.add(Integer.parseInt(text));
                    } catch (NumberFormatException ignore) {
                        // Ignore malformed script results.
                    }
                }
            }
        }
        return indexes;
    }

    private static String reflectionEvidence(
            ReflectionSnapshot baseline, ReflectionSnapshot attacked) {
        return message(
                "evidence.reflection",
                baseline.textMatches(),
                baseline.htmlMatches(),
                attacked.textMatches(),
                attacked.htmlMatches());
    }

    private static String formatProbeAttempt(
            String target, String observedResult, boolean matched, String note) {
        if (note != null && !note.isBlank()) {
            return message("probe.attempt.withNote", target, observedResult, yesNo(matched), note);
        }
        return message("probe.attempt", target, observedResult, yesNo(matched));
    }

    private static ReflectionSnapshot loadAndSnapshot(
            WebDriver driver, String targetUrl, String expectedResult) {
        try {
            driver.get(targetUrl);
            waitForPageToSettle(driver);
            return captureSnapshot((JavascriptExecutor) driver, expectedResult);
        } catch (Exception e) {
            LOGGER.debug(
                    "CSTI: failed loading '{}' during payload probe ({})",
                    targetUrl,
                    e.getMessage());
            return null;
        }
    }

    private static ReflectionSnapshot captureSnapshot(
            JavascriptExecutor js, String expectedResult) {
        try {
            Object raw = js.executeScript(SNAPSHOT_PAYLOAD, expectedResult);
            if (raw instanceof Map<?, ?> map) {
                return new ReflectionSnapshot(
                        toInt(map.get("textMatches")), toInt(map.get("htmlMatches")));
            }
        } catch (Exception e) {
            LOGGER.debug("CSTI: failed to capture reflection snapshot ({})", e.getMessage());
        }
        return null;
    }

    private static int toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ignore) {
                return 0;
            }
        }
        return 0;
    }

    private int getMaxProbeCount() {
        return switch (getAttackStrength()) {
            case LOW -> 2;
            case MEDIUM -> 4;
            case HIGH -> 8;
            case INSANE -> 12;
            default -> 4;
        };
    }

    static String replaceParameterValue(String targetUrl, String paramName, String payload) {
        URI uri = parseEscapedUri(targetUrl, targetUrl);
        if (uri == null) {
            return null;
        }

        String query = uri.getEscapedQuery();
        if (query == null || query.isBlank()) {
            return null;
        }

        List<String> parts = new ArrayList<>();
        boolean replaced = false;
        for (String part : query.split("&", -1)) {
            if (part.isEmpty()) {
                parts.add(part);
                continue;
            }
            int equalsIndex = part.indexOf('=');
            String rawName = equalsIndex >= 0 ? part.substring(0, equalsIndex) : part;
            String decodedName = decodeQueryComponent(rawName);
            if (paramName.equals(decodedName)) {
                parts.add(rawName + "=" + encodeQueryComponent(payload));
                replaced = true;
            } else {
                parts.add(part);
            }
        }

        if (!replaced) {
            return null;
        }

        try {
            String fragment = uri.getEscapedFragment();
            uri.setEscapedQuery(String.join("&", parts));
            uri.setEscapedFragment(fragment);
            return toEscapedUriString(uri);
        } catch (URIException e) {
            LOGGER.debug(
                    "CSTI: unable to update candidate URL '{}' ({})", targetUrl, e.getMessage());
            return null;
        }
    }

    private static String decodeQueryComponent(String value) {
        if (value == null) {
            return null;
        }
        try {
            return URIUtil.decode(value, URL_CHARSET);
        } catch (URIException e) {
            return value;
        }
    }

    private static String encodeQueryComponent(String value) {
        try {
            return URIUtil.encodeWithinQuery(value, URL_CHARSET);
        } catch (URIException e) {
            return value;
        }
    }

    private static String resolveLinkUrl(String pageUrl, String href) {
        try {
            return toEscapedUriString(new URI(new URI(pageUrl, true), href, true));
        } catch (URIException e) {
            return null;
        }
    }

    private static boolean isSameOrigin(String left, String right) {
        URI leftUri = parseEscapedUri(left, left);
        URI rightUri = parseEscapedUri(right, right);
        if (leftUri == null || rightUri == null) {
            return false;
        }

        try {
            return nullToEmpty(leftUri.getScheme())
                            .equalsIgnoreCase(nullToEmpty(rightUri.getScheme()))
                    && nullToEmpty(leftUri.getHost())
                            .equalsIgnoreCase(nullToEmpty(rightUri.getHost()))
                    && effectivePort(leftUri) == effectivePort(rightUri);
        } catch (URIException e) {
            return false;
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static URI parseEscapedUri(String url, String rawValue) {
        if (url == null) {
            return null;
        }
        try {
            return new URI(url, true);
        } catch (URIException e) {
            LOGGER.debug("CSTI: unable to parse candidate URL '{}' ({})", rawValue, e.getMessage());
            return null;
        }
    }

    private static String toEscapedUriString(URI uri) {
        String fragment = uri.getEscapedFragment();
        if (fragment == null) {
            return uri.getEscapedURI();
        }
        return uri.getEscapedURI() + "#" + fragment;
    }

    static EngineConfidence scoreEngineDetectionConfidence(
            ClientSideEngineDetector.DetectionResult engine) {

        boolean hasGlobal = engine.detected();
        boolean hasActivity = engine.hasActiveCalls();
        boolean hasTagEvidence = engine.hasTagEvidence();

        // Heuristic 3 is only applicable if the detected engine has known tag/script markers.
        boolean heuristic3Applicable =
                hasGlobal && ClientSideEngineDetector.isTagHeuristicApplicable(engine.engineName());

        if (hasGlobal && hasTagEvidence) {
            return EngineConfidence.VERY_HIGH;
        }

        if (hasGlobal && hasActivity) {
            return heuristic3Applicable ? EngineConfidence.HIGH : EngineConfidence.VERY_HIGH;
        }

        if (hasGlobal || hasTagEvidence) {
            return EngineConfidence.LOW;
        }

        return EngineConfidence.LOW;
    }

    private static int toZapAlertConfidence(EngineConfidence confidence) {
        return switch (confidence) {
            case LOW -> Alert.CONFIDENCE_LOW;
            case HIGH -> Alert.CONFIDENCE_MEDIUM;
            case VERY_HIGH -> Alert.CONFIDENCE_HIGH;
        };
    }

    static String buildEngineDetectionReport(
            List<String> inputFindings,
            List<String> linkFindings,
            ClientSideEngineDetector.DetectionResult engine,
            EngineConfidence confidence) {

        StringBuilder sb = new StringBuilder();

        if (engine.detected()) {
            appendReportLine(sb, "engine.report.detected", engine.engineName());
            appendReportLine(sb, "engine.report.global", engine.globalExpression());
            sb.append("\n");
            appendReportLine(sb, "engine.report.confidence", confidence);
            appendReportLine(
                    sb,
                    "engine.report.heuristics",
                    engine.hasActiveCalls(),
                    engine.hasTagEvidence());
            sb.append("\n");

            appendReportLine(sb, "engine.report.calls");
            if (engine.hasActiveCalls()) {
                engine.matchedCalls().forEach(c -> appendReportLine(sb, "report.item", c));
            } else {
                appendReportLine(sb, "report.noneFound");
            }
            if (!engine.hasActiveCalls()) {
                sb.append("\n");
                appendReportLine(sb, "engine.report.noActiveCalls");
            }

            sb.append("\n");
            appendReportLine(sb, "engine.report.scriptTypes");
            if (!engine.matchedScriptTypes().isEmpty()) {
                engine.matchedScriptTypes().forEach(t -> appendReportLine(sb, "report.item", t));
            } else {
                appendReportLine(sb, "report.noneFound");
            }

            sb.append("\n");
            appendReportLine(sb, "engine.report.templateAttrs");
            if (!engine.matchedTemplateAttrs().isEmpty()) {
                engine.matchedTemplateAttrs().forEach(a -> appendReportLine(sb, "report.item", a));
            } else {
                appendReportLine(sb, "report.noneFound");
            }

            if (!engine.hasTagEvidence()) {
                sb.append("\n");
                appendReportLine(sb, "engine.report.noTagEvidence");
            }

        } else {
            appendReportLine(sb, "engine.report.notDetected");
        }

        return sb.toString().trim();
    }

    private static String buildProbeReport(
            ClientSideEngineDetector.DetectionResult engine,
            ClientSideEngineDetector.PayloadDefinition payloadDefinition,
            ProbeSummary probeSummary) {

        StringBuilder sb = new StringBuilder();
        appendReportLine(sb, "probe.report.engine", engine.engineName());
        if (!probeSummary.confirmed().isEmpty()) {
            ProbeResult primary = probeSummary.confirmed().get(0);
            appendReportLine(sb, "probe.report.payload", primary.payload());
            appendReportLine(sb, "probe.report.expected", primary.expectedResult());
        } else if (payloadDefinition == null) {
            appendReportLine(sb, "probe.report.payload", message("value.unavailable"));
            appendReportLine(sb, "probe.report.expected", message("value.unavailable"));
        } else {
            appendReportLine(sb, "probe.report.payload", payloadDefinition.payload());
            appendReportLine(sb, "probe.report.expected", payloadDefinition.expectedResult());
        }

        if (!probeSummary.confirmed().isEmpty()) {
            sb.append("\n");
            appendReportLine(sb, "probe.report.matched", message("value.yes"));
            appendReportLine(sb, "probe.report.confirmed");
            for (ProbeResult result : probeSummary.confirmed()) {
                appendReportLine(sb, "probe.report.confirmed.payload", result.payload());
                appendReportLine(sb, "probe.report.confirmed.expected", result.expectedResult());
                appendReportLine(sb, "probe.report.confirmed.observed", result.observedResult());
                appendReportLine(sb, "probe.report.confirmed.vector", result.vector());
                appendReportLine(sb, "probe.report.confirmed.source", result.source());
            }
        } else {
            sb.append("\n");
            appendReportLine(sb, "probe.report.matched", message("value.no"));
            appendReportLine(sb, "probe.report.observed", message("value.notObserved"));
        }

        return sb.toString().trim();
    }

    private void raiseConfirmedCstiAlert(
            HttpMessage baseMsg,
            ClientSideEngineDetector.DetectionResult engine,
            EngineConfidence engineConfidence,
            ProbeResult probeResult) {
        newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(toZapAlertConfidence(engineConfidence))
                .setName(getName())
                .setDescription(message("alert.confirmed.desc"))
                .setParam(probeResult.source())
                .setAttack(probeResult.payload())
                .setEvidence(probeResult.expectedResult())
                .setOtherInfo(
                        message(
                                "alert.confirmed.otherinfo",
                                engine.engineName(),
                                probeResult.payload(),
                                probeResult.expectedResult(),
                                probeResult.observedResult(),
                                message("value.yes"),
                                probeResult.vector(),
                                probeResult.source(),
                                probeResult.attackUrl(),
                                probeResult.evidence()))
                .setMessage(baseMsg)
                .raise();
    }

    private static void appendReportLine(StringBuilder sb, String key, Object... args) {
        sb.append(message(key, args)).append('\n');
    }

    private static String message(String key, Object... args) {
        return Constant.messages.getString(MESSAGE_PREFIX + key, args);
    }

    private static String yesNo(boolean value) {
        return message(value ? "value.yes" : "value.no");
    }

    private static String nullToEmpty(String value) {
        return value != null ? value : "-";
    }

    String stripQueryAndFragment(String fullUrl) {
        URI uri = parseEscapedUri(fullUrl, fullUrl);
        if (uri == null) return null;
        try {
            uri.setEscapedQuery(null);
            uri.setEscapedFragment(null);
            return toEscapedUriString(uri);
        } catch (URIException e) {
            LOGGER.debug("CSTI: unable to strip query from URL '{}' ({})", fullUrl, e.getMessage());
            return null;
        }
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
}
