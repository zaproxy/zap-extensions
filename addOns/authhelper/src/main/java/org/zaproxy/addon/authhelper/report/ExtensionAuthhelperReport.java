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
package org.zaproxy.addon.authhelper.report;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.AutoDetectSessionManagementMethodType;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.report.AuthReportData.FailureDetail;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;

public class ExtensionAuthhelperReport extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAuthhelperReport";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionReports.class);
    private static final Logger LOGGER = LogManager.getLogger(ExtensionAuthhelperReport.class);

    private AuthReportDataHandler authReportDataHandler;

    public ExtensionAuthhelperReport() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void optionsLoaded() {
        ExtensionReports extReports = AuthUtils.getExtension(ExtensionReports.class);
        authReportDataHandler = new AuthReportDataHandler();
        extReports.addReportDataHandler(authReportDataHandler);
    }

    @Override
    public void unload() {
        ExtensionReports extReports = AuthUtils.getExtension(ExtensionReports.class);
        if (authReportDataHandler != null) {
            extReports.removeReportDataHandler(authReportDataHandler);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authhelper.authreport.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authhelper.authreport.name");
    }

    private static void addSummaryItem(AuthReportData ard, String key, boolean pass) {
        ard.addSummaryItem(
                pass,
                "auth.summary." + key,
                Constant.messages.getString(
                        "authhelper.authreport.summary." + key + (pass ? ".pass" : ".fail")));
    }

    private static Context getFirstAuthConfiguredContext(ReportData reportData) {
        List<Context> contexts = reportData.getContexts();
        for (Context c : contexts) {
            if (!(c.getAuthenticationMethod() instanceof ManualAuthenticationMethod)) {
                return c;
            }
        }
        return null;
    }

    protected static String getHostName(String regexStr) throws URIException {
        return SessionStructure.getHostName(new URI(regexStr.replace(".*", ""), false));
    }

    protected static class AuthReportDataHandler implements ExtensionReports.ReportDataHandler {

        @Override
        public void handle(ReportData reportData) {
            // Just add data if its one of the reports in this add-on
            if (!reportData.getTemplateName().startsWith("auth-report-")) {
                return;
            }
            AuthReportData ard = new AuthReportData();
            reportData.addReportObjects("authdata", ard);

            Context authContext = getFirstAuthConfiguredContext(reportData);
            if (authContext == null) {
                return;
            }
            ard.setValidReport(true);

            boolean sessionPassed =
                    !(authContext.getSessionManagementMethod()
                            instanceof
                            AutoDetectSessionManagementMethodType
                                    .AutoDetectSessionManagementMethod);
            boolean verificationPassed =
                    !(AuthCheckingStrategy.AUTO_DETECT.equals(
                            authContext.getAuthenticationMethod().getAuthCheckingStrategy()));

            List<String> incRegexes = authContext.getIncludeInContextRegexs();

            InMemoryStats inMemoryStats =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionStats.class)
                            .getInMemoryStats();

            if (!incRegexes.isEmpty() && inMemoryStats != null) {
                String hostname;
                try {
                    hostname = getHostName(incRegexes.get(0));
                    ard.setSite(hostname);

                    if (authContext.getAuthenticationMethod()
                            instanceof
                            BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod) {

                        Long passedCount =
                                inMemoryStats.getStat(
                                        hostname, AuthUtils.AUTH_BROWSER_PASSED_STATS);

                        /*
                         * The AUTH_SUCCESS_STATS / AUTH_FAILURE_STATS stats can get raised on another domain.
                         * Any successes are good, but just failures are bad.
                         */
                        boolean hasSuccessStats =
                                inMemoryStats.getStat(
                                                hostname, AuthenticationHelper.AUTH_SUCCESS_STATS)
                                        != null;
                        boolean hasFailureStats =
                                inMemoryStats.getStat(
                                                hostname, AuthenticationHelper.AUTH_FAILURE_STATS)
                                        != null;
                        boolean overallStatus =
                                sessionPassed
                                        && verificationPassed
                                        && passedCount != null
                                        && (hasSuccessStats || !hasFailureStats);
                        addSummaryItem(ard, "auth", overallStatus);
                        if (!overallStatus) {
                            if (!sessionPassed) {
                                ard.addFailureDetail(FailureDetail.SESSION_MGMT);
                            }
                            if (!verificationPassed) {
                                ard.addFailureDetail(FailureDetail.VERIF_IDENT);
                            }
                            if (passedCount == null) {
                                ard.addFailureDetail(FailureDetail.PASS_COUNT);
                            }
                            if (!hasSuccessStats) {
                                ard.addFailureDetail(FailureDetail.NO_SUCCESSFUL_LOGINS);
                            }
                            if (hasFailureStats) {
                                ard.addFailureDetail(FailureDetail.LOGIN_FAILURES);
                            }
                            // We got this far so did fail overall
                            if (!ard.hasFailureDetails()) {
                                ard.addFailureDetail(FailureDetail.OVERALL);
                            }
                        }

                        if (passedCount != null) {
                            addSummaryItem(ard, "username", true);
                            addSummaryItem(ard, "password", true);
                        } else {
                            Long noUserCount =
                                    inMemoryStats.getStat(
                                            hostname, AuthUtils.AUTH_NO_USER_FIELD_STATS);
                            Long noPwdCount =
                                    inMemoryStats.getStat(
                                            hostname, AuthUtils.AUTH_NO_PASSWORD_FIELD_STATS);

                            addSummaryItem(ard, "username", noUserCount != null);
                            addSummaryItem(ard, "password", noPwdCount != null);
                        }
                    } else {
                        addSummaryItem(
                                ard,
                                "auth",
                                sessionPassed
                                        && verificationPassed
                                        && inMemoryStats.getStat(
                                                        hostname,
                                                        AuthenticationHelper.AUTH_SUCCESS_STATS)
                                                != null);
                    }

                    // Add all of the stats
                    inMemoryStats.getStats("").forEach((k, v) -> ard.addStatsItem(k, "global", v));
                    inMemoryStats
                            .getSiteStats(hostname, "")
                            .forEach((k, v) -> ard.addStatsItem(k, "site", v));

                } catch (Exception e) {
                    LOGGER.warn(e.getMessage(), e);
                }

            } else {
                addSummaryItem(ard, "stats", false);
            }

            addSummaryItem(ard, "session", sessionPassed);
            addSummaryItem(ard, "verif", verificationPassed);

            AutomationProgress progress = new AutomationProgress();
            AutomationEnvironment env = new AutomationEnvironment(progress);
            env.addContext(authContext);
            AutomationPlan plan = new AutomationPlan(env, new ArrayList<>(), progress);
            try {
                ard.setAfEnv(plan.toYaml());
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }
}
