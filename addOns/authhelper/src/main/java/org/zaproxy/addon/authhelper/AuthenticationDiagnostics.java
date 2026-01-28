/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.ScriptKey;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticBrowserStorageItem;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticMessage;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticScreenshot;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement.SelectorType;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zest.core.v1.ZestClientElement;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientScreenshot;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestRuntime;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class AuthenticationDiagnostics implements AutoCloseable {

    private static final Logger LOGGER = LogManager.getLogger(AuthenticationDiagnostics.class);

    private static final List<DiagnosticDataProvider> diagnosticDataProviders =
            Collections.synchronizedList(new ArrayList<>());

    private static final List<MessageAccessedConsumer> messageAccessedConsumers =
            Collections.synchronizedList(new ArrayList<>());

    private static final String ELEMENT_SELECTOR_SCRIPT =
            """
function isElementPathUnique(path, documentElement) {
  const elements = documentElement.querySelectorAll(path);
  return elements.length === 1;
}

function isElementXPathUnique(xpath, documentElement) {
  const result = documentElement.evaluate(
    xpath,
    documentElement,
    null,
    XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
    null,
  );
  return result.snapshotLength === 1;
}

function getCSSSelector(element, documentElement) {
  let selector = element.tagName.toLowerCase();
  if (selector === "html") {
    selector = "body";
  } else if (element === documentElement.body) {
    selector = "body";
  } else if (element.parentNode) {
    const parentSelector = getCSSSelector(element.parentNode, documentElement);
    selector = `${parentSelector} > ${selector}`;
  }
  return selector;
}

function getXPath(element, documentElement) {
  if (!element.tagName) {
    return "";
  }

  let selector = element.tagName.toLowerCase();

  if (element.id && isElementXPathUnique(selector, documentElement)) {
    selector += `[@id="${element.id}"]`;
  } else {
    let index = 1;
    let sibling = element.previousSibling;
    let isUnique = true;
    while (sibling) {
      if (
        sibling.nodeType === Node.ELEMENT_NODE &&
        sibling.nodeName === element.nodeName
      ) {
        index += 1;
        isUnique = false;
      }
      sibling = sibling.previousSibling;
    }

    if (isUnique) {
      sibling = element.nextSibling;
      while (sibling) {
        if (
          sibling.nodeType === Node.ELEMENT_NODE &&
          sibling.nodeName === element.nodeName
        ) {
          isUnique = false;
          break;
        }
        sibling = sibling.nextSibling;
      }
    }

    if (index !== 1 || !isUnique) {
      selector += `[${index}]`;
    }
  }

  if (element.parentNode) {
    const parentSelector = getXPath(element.parentNode, documentElement);
    selector = `${parentSelector}/${selector}`;
  }
  return selector;
}

function getSelector(element, documentElement) {
  const selector = { type: "", value: "" };

  if (element.id) {
    selector.type = "css";
    selector.value = `#${element.id}`;
  } else if (
    element.classList.length === 1 &&
    element.classList.item(0) != null &&
    isElementPathUnique(`.${element.classList.item(0)}`, documentElement)
  ) {
    selector.type = "css";
    selector.value = `.${element.classList.item(0)}`;
  } else {
    const cssSelector = getCSSSelector(element, documentElement);
    if (cssSelector && isElementPathUnique(cssSelector, documentElement)) {
      selector.type = "css";
      selector.value = cssSelector;
    } else {
      const xpath = getXPath(element, documentElement);
      if (xpath) {
        selector.type = "xpath";
        selector.value = xpath;
      }
    }
  }

  return selector;
}

return getSelector(arguments[0], document)
""";

    private final HttpSenderListener messageAccessedListener;

    private final boolean enabled;

    private Diagnostic diagnostic;
    private HttpSenderListener listener;
    private DiagnosticStep currentStep;
    private ScriptKey elementSelectorScriptKey;

    public AuthenticationDiagnostics(
            boolean enabled, String authenticationMethod, String context, String user) {
        this(enabled, authenticationMethod, context, user, null);
    }

    public AuthenticationDiagnostics(
            boolean enabled,
            String authenticationMethod,
            String context,
            String user,
            String script) {
        this.enabled = enabled;

        messageAccessedListener =
                new HttpSenderListener() {

                    private Context ctx = Model.getSingleton().getSession().getContext(context);

                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        // Nothing to do.

                    }

                    @Override
                    public void onHttpRequestSend(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        messageAccessedConsumers.forEach(e -> e.messageAccessed(ctx, msg));
                    }

                    @Override
                    public int getListenerOrder() {
                        return 0;
                    }
                };
        HttpSender.addListener(messageAccessedListener);

        if (!enabled) {
            return;
        }

        diagnostic = new Diagnostic(authenticationMethod, context, user);
        diagnostic.setScript(script);
        diagnostic.setCreateTimestamp(Instant.now());

        createStep();

        listener =
                new HttpSenderListener() {

                    @Override
                    public void onHttpRequestSend(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        // Nothing to do, recording the whole message.
                    }

                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        if (!AuthUtils.isRelevantToAuthDiags(msg)) {
                            return;
                        }
                        addMessageToStep(msg, initiator);
                    }

                    @Override
                    public int getListenerOrder() {
                        return Integer.MAX_VALUE;
                    }
                };
        HttpSender.addListener(listener);
    }

    private void addMessageToStep(HttpMessage msg) {
        addMessageToStep(msg, 0);
    }

    private void addMessageToStep(HttpMessage msg, int initiator) {
        try {
            HistoryReference ref =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_AUTHENTICATION,
                            msg);

            DiagnosticMessage message = new DiagnosticMessage();
            message.setCreateTimestamp(Instant.now());
            message.setStep(currentStep);
            message.setMessageId(ref.getHistoryId());
            message.setInitiator(initiator);
            currentStep.getMessages().add(message);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist message:", e);
        }
    }

    public void insertDiagnostics(ZestScript zestScript) {
        if (!enabled) {
            return;
        }

        for (int i = 0; i < zestScript.getStatements().size(); i++) {
            ZestStatement stmt = zestScript.getStatements().get(i);
            if (stmt instanceof ZestClientElementClear) {
                continue;
            }

            if (stmt instanceof ZestClientLaunch launch) {
                ZestClientScreenshotDiag screenshotDiag = new ZestClientScreenshotDiag();
                screenshotDiag.setWindowHandle(launch.getWindowHandle());
                screenshotDiag.setDescription(
                        Constant.messages.getString("authhelper.auth.method.diags.zest.open"));
                i += 1;
                zestScript.getStatements().add(i, screenshotDiag);
            } else if (stmt instanceof ZestClientElement element) {
                ZestClientScreenshotDiag screenshotDiag = new ZestClientScreenshotDiag();
                screenshotDiag.setClientElement(element);
                screenshotDiag.setWindowHandle(element.getWindowHandle());
                screenshotDiag.setDescription(
                        Constant.messages.getString(
                                "authhelper.auth.method.diags.zest.interaction",
                                ZestZapUtils.toUiString(element, false)));
                i += 1;
                zestScript.getStatements().add(i, screenshotDiag);
            } else if (stmt instanceof ZestClientWindowClose close) {
                ZestClientScreenshotDiag screenshotDiag = new ZestClientScreenshotDiag();
                screenshotDiag.setWindowHandle(close.getWindowHandle());
                zestScript.getStatements().add(i, screenshotDiag);
                screenshotDiag.setDescription(
                        Constant.messages.getString("authhelper.auth.method.diags.zest.close"));
                i += 1;
            }
        }
    }

    private void createStep() {
        if (currentStep != null) {
            currentStep.setDiagnostic(diagnostic);
            diagnostic.getSteps().add(currentStep);
        }
        currentStep = new DiagnosticStep();
    }

    public void recordStep(WebDriver wd, String description) {
        recordStep(wd, description, null);
    }

    public void recordStep(WebDriver wd, String description, WebElement element) {
        if (!enabled) {
            return;
        }

        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        currentStep.setCreateTimestamp(Instant.now());
        currentStep.setUrl(wd.getCurrentUrl());
        currentStep.setDescription(description);

        if (wd instanceof TakesScreenshot ts) {
            DiagnosticScreenshot screenshot = new DiagnosticScreenshot();
            screenshot.setData(ts.getScreenshotAs(OutputType.BASE64));
            screenshot.setCreateTimestamp(Instant.now());
            screenshot.setStep(currentStep);
            currentStep.setScreenshot(screenshot);
        }

        List<WebElement> foundElements =
                resetWait(wd, () -> wd.findElements(By.xpath("//input|//button")), () -> List.of());
        List<WebElement> forms =
                resetWait(wd, () -> wd.findElements(By.xpath("//form")), () -> List.of());

        currentStep.setWebElement(createDiagnosticWebElement(wd, forms, element));
        for (WebElement foundElement : foundElements) {
            DiagnosticWebElement field = createDiagnosticWebElement(wd, forms, foundElement);
            if (field != null) {
                currentStep.getWebElements().add(field);
            }
        }

        if (wd instanceof JavascriptExecutor je) {
            for (var type : DiagnosticBrowserStorageItem.Type.values()) {
                processStorage(je, type);
            }
        }

        createStep();
    }

    /**
     * Reset the webdriver implicit wait - use when you want the current state and don't want any
     * delays.
     */
    private static <T> T resetWait(
            WebDriver wd, Supplier<? extends T> function, Supplier<T> defaultValue) {
        Duration duration = wd.manage().timeouts().getImplicitWaitTimeout();
        wd.manage().timeouts().implicitlyWait(Duration.ofMillis(0));
        try {
            return function.get();
        } catch (Exception e) {
            return defaultValue.get();
        } finally {
            wd.manage().timeouts().implicitlyWait(duration);
        }
    }

    private void processStorage(JavascriptExecutor je, DiagnosticBrowserStorageItem.Type type) {
        try {
            @SuppressWarnings("unchecked")
            List<Map<String, String>> storage =
                    (List<Map<String, String>>) je.executeScript(type.getScript());
            if (storage == null || storage.isEmpty()) {
                return;
            }

            storage.stream()
                    .map(
                            e -> {
                                DiagnosticBrowserStorageItem item =
                                        new DiagnosticBrowserStorageItem();
                                item.setCreateTimestamp(Instant.now());
                                item.setStep(currentStep);
                                item.setType(type);
                                item.setKey(e.get("key"));
                                item.setValue(e.get("value"));
                                return item;
                            })
                    .forEach(currentStep.getBrowserStorageItems()::add);
        } catch (WebDriverException e) {
            LOGGER.debug("Failed to process the storage:", e);
        }
    }

    private DiagnosticWebElement createDiagnosticWebElement(
            WebDriver wd, List<WebElement> forms, WebElement element) {
        if (element == null) {
            return null;
        }

        try {
            DiagnosticWebElement diagElement = new DiagnosticWebElement();
            diagElement.setCreateTimestamp(Instant.now());
            if (wd instanceof JavascriptExecutor je) {
                WebElement form =
                        (WebElement) je.executeScript("return arguments[0].form", element);
                if (form != null) {
                    int idx = forms.indexOf(form);
                    diagElement.setFormIndex(idx != -1 ? idx : null);
                }

                if (elementSelectorScriptKey == null) {
                    elementSelectorScriptKey = je.pin(ELEMENT_SELECTOR_SCRIPT);
                }

                @SuppressWarnings("unchecked")
                Map<String, String> data =
                        (Map<String, String>) je.executeScript(elementSelectorScriptKey, element);
                diagElement.setSelectorType(
                        "xpath".equals(data.get("type")) ? SelectorType.XPATH : SelectorType.CSS);
                diagElement.setSelectorValue(data.get("value"));
            }

            diagElement.setTagName(element.getTagName());
            diagElement.setAttributeType(element.getAttribute("type"));
            diagElement.setAttributeId(element.getAttribute("id"));
            diagElement.setAttributeName(element.getAttribute("name"));
            diagElement.setAttributeValue(element.getAttribute("value"));
            diagElement.setText(element.getText());
            diagElement.setDisplayed(element.isDisplayed());
            diagElement.setEnabled(element.isEnabled());

            return diagElement;
        } catch (WebDriverException e) {
            LOGGER.debug("Failed to obtain field data:", e);
            return null;
        }
    }

    private void finishCurrentStep(String url, String description) {
        currentStep.setCreateTimestamp(Instant.now());
        currentStep.setUrl(url);
        currentStep.setDescription(description);
        createStep();
    }

    public void recordErrorStep(WebDriver webDriver) {
        if (!enabled) {
            return;
        }

        try {
            String description =
                    Constant.messages.getString("authhelper.auth.method.diags.steps.error");
            if (webDriver == null) {
                recordStep(description);
            } else {
                recordStep(webDriver, description);
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while recording the error step:", e);
        }
    }

    public void reportFlowException(Exception cause) {
        if (!enabled) {
            return;
        }

        LOGGER.info("Exception during steps:", cause);
    }

    public void recordStep(String description) {
        if (!enabled) {
            return;
        }
        finishCurrentStep("", description);
    }

    public void recordStep(HttpMessage message, String description) {
        if (!enabled) {
            return;
        }
        addMessageToStep(message);
        finishCurrentStep(message.getRequestHeader().getURI().toString(), description);
    }

    @Override
    public void close() {
        HttpSender.removeListener(messageAccessedListener);

        if (!enabled) {
            return;
        }

        HttpSender.removeListener(listener);

        diagnosticDataProviders.forEach(
                provider -> {
                    try {
                        provider.addDiagnostics(diagnostic);
                    } catch (Exception e) {
                        LOGGER.error("An error occurred calling a data provider:", e);
                    }
                });

        PersistenceManager pm = TableJdo.getPmf().getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(diagnostic);
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to persist diagnostics:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    private class ZestClientScreenshotDiag extends ZestClientScreenshot {

        private String description;

        private ZestClientElement element;

        public void setClientElement(ZestClientElement element) {
            this.element = element;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        @Override
        public String invoke(ZestRuntime runtime) throws ZestClientFailException {
            recordStep(
                    runtime.getWebDriver(this.getWindowHandle()),
                    description,
                    getWebElement(runtime, element));
            return null;
        }

        private WebElement getWebElement(ZestRuntime runtime, ZestClientElement element) {
            if (element == null) {
                return null;
            }

            WebDriver wd = runtime.getWebDriver(this.getWindowHandle());
            if (wd == null) {
                return null;
            }

            return resetWait(
                    wd,
                    () -> {
                        try {
                            return element.getWebElement(runtime);
                        } catch (ZestClientFailException e) {
                            return null;
                        }
                    },
                    () -> null);
        }
    }

    public static void addMessageAccessedConsumer(MessageAccessedConsumer consumer) {
        Objects.requireNonNull(consumer);
        messageAccessedConsumers.add(consumer);
    }

    public static void removeMessageAccessedConsumer(MessageAccessedConsumer consumer) {
        Objects.requireNonNull(consumer);
        messageAccessedConsumers.remove(consumer);
    }

    public interface MessageAccessedConsumer {

        void messageAccessed(Context ctx, HttpMessage message);
    }

    public static void addDiagnosticDataProvider(DiagnosticDataProvider provider) {
        Objects.requireNonNull(provider);
        diagnosticDataProviders.add(provider);
    }

    public static void removeDiagnosticDataProvider(DiagnosticDataProvider provider) {
        Objects.requireNonNull(provider);
        diagnosticDataProviders.remove(provider);
    }

    public interface DiagnosticDataProvider {

        void addDiagnostics(Diagnostic diagnostic);
    }
}
