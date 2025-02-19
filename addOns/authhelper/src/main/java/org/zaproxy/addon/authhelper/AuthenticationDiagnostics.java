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

import java.util.ArrayList;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;
import lombok.Data;
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
import org.zaproxy.addon.authhelper.internal.db.DiagnosticInputField;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticMessage;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticScreenshot;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
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
    private List<InternalStep> steps;
    private HttpSenderListener listener;
    private InternalStep currentStep;

    public AuthenticationDiagnostics(
            boolean enabled, int authenticationMethod, int contextId, int userId) {
        this.enabled = enabled;
        if (!enabled) {
            return;
        }

        diagnostic = new Diagnostic(authenticationMethod, contextId, userId);
        steps = new ArrayList<>();

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
                        if (msg.getResponseHeader().isImage()
                                || !(msg.getResponseHeader().isHtml()
                                        || msg.getResponseHeader().isJson()
                                        || msg.getResponseHeader().isXml())) {
                            return;
                        }

                        try {
                            HistoryReference ref =
                                    new HistoryReference(
                                            Model.getSingleton().getSession(),
                                            HistoryReference.TYPE_AUTHENTICATION,
                                            msg);
                            currentStep.getMessages().add(ref.getHistoryId());
                        } catch (HttpMalformedHeaderException | DatabaseException e) {
                            LOGGER.warn("Failed to persist message:", e);
                        }
                    }

                    @Override
                    public int getListenerOrder() {
                        return Integer.MAX_VALUE;
                    }
                };
        HttpSender.addListener(listener);
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
        currentStep = new InternalStep();
        steps.add(currentStep);
    }

    public void recordStep(WebDriver wd, String description) {
        if (!enabled) {
            return;
        }

        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        currentStep.setUrl(wd.getCurrentUrl());
        currentStep.setDescription(description);

        if (wd instanceof TakesScreenshot ts) {
            DiagnosticScreenshot screenshot = new DiagnosticScreenshot();
            screenshot.setScreenshot(ts.getScreenshotAs(OutputType.BASE64));
            currentStep.setScreenshot(screenshot);
        }

        List<WebElement> inputs = wd.findElements(By.xpath("//input"));
        List<WebElement> forms = wd.findElements(By.xpath("//form"));
        for (WebElement input : inputs) {
            try {
                DiagnosticInputField field = new DiagnosticInputField();
                if (wd instanceof JavascriptExecutor je) {
                    WebElement form =
                            (WebElement) je.executeScript("return arguments[0].form", input);
                    if (form != null) {
                        int idx = forms.indexOf(form);
                        field.setFormIndex(idx != -1 ? idx : null);
                    }
                }

                field.setFieldId(getAttribute(input, "id"));
                field.setFieldName(getAttribute(input, "name"));
                field.setDisplayed(input.isDisplayed());
                field.setEnabled(input.isEnabled());
                currentStep.getFields().add(field);
            } catch (WebDriverException e) {
                LOGGER.debug("Failed to obtain field data:", e);
            }
        }

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

            steps.forEach(step -> step.persist(diagnostic, pm));

            tx.commit();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    @Data
    private static class InternalStep {

        private String url;
        private String description;

        private List<Integer> messages = new ArrayList<>();
        private List<DiagnosticInputField> fields = new ArrayList<>();
        private DiagnosticScreenshot screenshot;

        public void persist(Diagnostic diagnostic, PersistenceManager pm) {
            if (url == null) {
                return;
            }

            DiagnosticStep step = new DiagnosticStep();
            step.setDiagnostic(diagnostic);
            step.setUrl(url);
            step.setDescription(description);
            pm.makePersistent(step);

            diagnostic.getSteps().add(step);

            messages.forEach(
                    e -> {
                        DiagnosticMessage message = new DiagnosticMessage();
                        message.setStep(step);
                        message.setMessageId(e);
                        pm.makePersistent(message);
                    });

            fields.forEach(
                    e -> {
                        e.setStep(step);
                        pm.makePersistent(e);
                    });

            if (screenshot != null) {
                screenshot.setStep(step);
                pm.makePersistent(screenshot);
            }
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
