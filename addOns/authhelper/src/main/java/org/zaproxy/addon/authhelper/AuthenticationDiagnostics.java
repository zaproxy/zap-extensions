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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
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
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
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

    private final boolean enabled;

    private Diagnostic diagnostic;
    private HttpSenderListener listener;
    private DiagnosticStep currentStep;

    public AuthenticationDiagnostics(
            boolean enabled, String authenticationMethod, String context, String user) {
        this.enabled = enabled;
        if (!enabled) {
            return;
        }

        diagnostic = new Diagnostic(authenticationMethod, context, user);
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
                        addMessageToStep(msg);
                    }

                    @Override
                    public int getListenerOrder() {
                        return Integer.MAX_VALUE;
                    }
                };
        HttpSender.addListener(listener);
    }

    private void addMessageToStep(HttpMessage msg) {
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
                screenshotDiag.setDescription("authhelper.auth.method.diags.zest.open");
                i += 1;
                zestScript.getStatements().add(i, screenshotDiag);
            } else if (stmt instanceof ZestClientElement element) {
                ZestClientScreenshotDiag screenshotDiag = new ZestClientScreenshotDiag();
                screenshotDiag.setWindowHandle(element.getWindowHandle());
                screenshotDiag.setDescription("authhelper.auth.method.diags.zest.interaction");
                i += 1;
                zestScript.getStatements().add(i, screenshotDiag);
            } else if (stmt instanceof ZestClientWindowClose close) {
                ZestClientScreenshotDiag screenshotDiag = new ZestClientScreenshotDiag();
                screenshotDiag.setWindowHandle(close.getWindowHandle());
                zestScript.getStatements().add(i, screenshotDiag);
                screenshotDiag.setDescription("authhelper.auth.method.diags.zest.close");
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

        List<WebElement> inputs = wd.findElements(By.xpath("//input"));
        List<WebElement> forms = wd.findElements(By.xpath("//form"));
        currentStep.setWebElement(createDiagnosticWebElement(wd, forms, element));
        for (WebElement input : inputs) {
            DiagnosticWebElement field = createDiagnosticWebElement(wd, forms, input);
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

    private <T> void processStorage(JavascriptExecutor je, DiagnosticBrowserStorageItem.Type type) {
        @SuppressWarnings("unchecked")
        List<Map<String, String>> storage =
                (List<Map<String, String>>) je.executeScript(type.getScript());
        if (storage == null || storage.isEmpty()) {
            return;
        }

        storage.stream()
                .map(
                        e -> {
                            DiagnosticBrowserStorageItem item = new DiagnosticBrowserStorageItem();
                            item.setCreateTimestamp(Instant.now());
                            item.setStep(currentStep);
                            item.setType(type);
                            item.setKey(e.get("key"));
                            item.setValue(e.get("value"));
                            return item;
                        })
                .forEach(currentStep.getBrowserStorageItems()::add);
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
            }

            diagElement.setAttributeType(getAttribute(element, "type"));
            diagElement.setAttributeId(getAttribute(element, "id"));
            diagElement.setAttributeName(getAttribute(element, "name"));
            diagElement.setAttributeValue(getAttribute(element, "value"));
            diagElement.setText(element.getText());
            diagElement.setDisplayed(element.isDisplayed());
            diagElement.setEnabled(element.isEnabled());

            return diagElement;
        } catch (WebDriverException e) {
            LOGGER.debug("Failed to obtain field data:", e);
            return null;
        }
    }

    public void recordStep(HttpMessage message, String description) {
        if (!enabled) {
            return;
        }

        currentStep.setCreateTimestamp(Instant.now());
        currentStep.setUrl(message.getRequestHeader().getURI().toString());
        currentStep.setDescription(description);

        addMessageToStep(message);

        createStep();
    }

    private static String getAttribute(WebElement element, String name) {
        String value = element.getDomAttribute(name);
        if (value != null) {
            return value;
        }
        return element.getDomProperty(name);
    }

    @Override
    public void close() {
        if (!enabled) {
            return;
        }

        HttpSender.removeListener(listener);

        PersistenceManager pm = TableJdo.getPmf().getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(diagnostic);
            tx.commit();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    private class ZestClientScreenshotDiag extends ZestClientScreenshot {

        private String description;

        public void setDescription(String description) {
            this.description = description;
        }

        @Override
        public String invoke(ZestRuntime runtime) throws ZestClientFailException {
            recordStep(runtime.getWebDriver(this.getWindowHandle()), description);
            return null;
        }
    }
}
