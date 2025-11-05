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
package org.zaproxy.addon.authhelper;

import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.extension.selenium.Browser;

public class AuthhelperParam extends AbstractParam {

    public static final int DEFAULT_WAIT = 2;
    public static final Browser DEFAULT_BROWSER = Browser.FIREFOX;
    private static final String AUTO_KEY = "authhelper";

    private static final String LOGIN_URL_KEY = AUTO_KEY + ".loginurl";
    private static final String DOMAINS_KEY = AUTO_KEY + ".domains";
    private static final String USERNAME_KEY = AUTO_KEY + ".username";
    private static final String BROWSER_KEY = AUTO_KEY + ".browser";
    private static final String WAIT_KEY = AUTO_KEY + ".wait";
    private static final String DEMO_MODE_KEY = AUTO_KEY + ".demo";
    private static final String RECORD_DIAGNOSTICS_KEY = AUTO_KEY + ".diagnostics";
    private static final String STEP_KEY = AUTO_KEY + ".steps.step";
    private static final String STEP_DELAY_KEY = AUTO_KEY + ".stepDelay";
    private static final String AUTH_REPORT_DIR_KEY = AUTO_KEY + ".authReportDir";

    private String loginUrl;
    private String username;
    private String browser;
    private String domains;
    private int wait = DEFAULT_WAIT;
    private int stepDelay;
    private boolean recordDiagnostics;
    private List<AuthenticationStep> steps = List.of();

    private String authReportDir = "";

    public AuthhelperParam() {}

    @Override
    protected void parse() {
        this.loginUrl = this.getString(LOGIN_URL_KEY, "");
        this.domains = this.getString(DOMAINS_KEY, "");
        this.username = this.getString(USERNAME_KEY, null);
        this.browser = this.getString(BROWSER_KEY, DEFAULT_BROWSER.getId());
        this.wait = getInteger(WAIT_KEY, DEFAULT_WAIT);
        this.stepDelay = getInteger(STEP_DELAY_KEY, 0);
        this.recordDiagnostics = getBoolean(RECORD_DIAGNOSTICS_KEY, false);

        steps =
                getConfig().getList(STEP_KEY).stream()
                        .map(Object::toString)
                        .map(AuthenticationStep::decode)
                        .filter(Objects::nonNull)
                        .toList();
        if (this.getConfig().containsKey(DEMO_MODE_KEY)) {
            // No longer used
            this.getConfig().clearProperty(DEMO_MODE_KEY);
        }

        authReportDir = getString(AUTH_REPORT_DIR_KEY, "");
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
        getConfig().setProperty(LOGIN_URL_KEY, loginUrl);
    }

    public String getDomains() {
        return domains;
    }

    public void setDomains(String domains) {
        this.domains = domains;
        getConfig().setProperty(DOMAINS_KEY, domains);
    }

    public String getBrowser() {
        return browser;
    }

    public void setBrowser(String browser) {
        this.browser = browser;
        getConfig().setProperty(BROWSER_KEY, browser);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
        getConfig().setProperty(USERNAME_KEY, username);
    }

    public int getWait() {
        return wait;
    }

    public void setWait(int wait) {
        this.wait = wait;
        getConfig().setProperty(WAIT_KEY, wait);
    }

    public int getStepDelay() {
        return stepDelay;
    }

    public void setStepDelay(int stepDelay) {
        this.stepDelay = stepDelay;
        getConfig().setProperty(STEP_DELAY_KEY, stepDelay);
    }

    public boolean isRecordDiagnostics() {
        return recordDiagnostics;
    }

    public void setRecordDiagnostics(boolean recordDiagnostics) {
        this.recordDiagnostics = recordDiagnostics;
        getConfig().setProperty(RECORD_DIAGNOSTICS_KEY, recordDiagnostics);
    }

    public List<AuthenticationStep> getSteps() {
        return steps;
    }

    public void setSteps(List<AuthenticationStep> steps) {
        this.steps = steps == null ? List.of() : steps;

        getConfig().clearProperty(STEP_KEY);
        this.steps.stream()
                .map(AuthenticationStep::encode)
                .forEach(e -> getConfig().addProperty(STEP_KEY, e));
    }

    public String getAuthReportDir() {
        return authReportDir;
    }

    public void setAuthReportDir(String authReportDir) {
        this.authReportDir = authReportDir == null ? "" : authReportDir;
        getConfig().setProperty(AUTH_REPORT_DIR_KEY, this.authReportDir);
    }
}
