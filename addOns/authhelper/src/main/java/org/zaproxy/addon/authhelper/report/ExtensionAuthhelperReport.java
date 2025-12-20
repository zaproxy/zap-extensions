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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.AutoDetectSessionManagementMethodType;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.report.AuthReportData.FailureDetail;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod;
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

    private enum ContextState {
        IN_CONTEXT,
        OUT_OF_CONTEXT,
        PARTIAL_OUT_OF_CONTEXT,
    }

    private static Map<String, ContextState> domainsAccessed =
            Collections.synchronizedMap(new HashMap<>());

    private ExtensionAutomation extensionAutomation;
    private AuthReportDataHandler authReportDataHandler;
    private AuthenticationDiagnostics.DiagnosticDataProvider diagnosticDataProvider;

    public ExtensionAuthhelperReport() {
        super(NAME);
    }

    @Override
    public void init() {
        extensionAutomation = AuthUtils.getExtension(ExtensionAutomation.class);
        if (extensionAutomation != null) {
            diagnosticDataProvider = this::addDiagnosticData;
            AuthenticationDiagnostics.addDiagnosticDataProvider(diagnosticDataProvider);
        }
        AuthenticationDiagnostics.addMessageAccessedConsumer(this::processMessageAccessed);
    }

    private void processMessageAccessed(Context ctx, HttpMessage msg) {
        try {
            String domain = SessionStructure.getHostName(msg);
            domainsAccessed.compute(
                    domain,
                    (k, v) -> {
                        boolean inCtx = ctx.isInContext(msg.getRequestHeader().getURI().toString());
                        if (v == null) {
                            return inCtx ? ContextState.IN_CONTEXT : ContextState.OUT_OF_CONTEXT;
                        }

                        return switch (v) {
                            case IN_CONTEXT ->
                                    inCtx
                                            ? ContextState.IN_CONTEXT
                                            : ContextState.PARTIAL_OUT_OF_CONTEXT;
                            case OUT_OF_CONTEXT ->
                                    inCtx
                                            ? ContextState.PARTIAL_OUT_OF_CONTEXT
                                            : ContextState.OUT_OF_CONTEXT;
                            default -> ContextState.PARTIAL_OUT_OF_CONTEXT;
                        };
                    });
        } catch (URIException ignore) {
            // Nothing to do.
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addSessionListener(
                new SessionChangedListener() {

                    @Override
                    public void sessionScopeChanged(Session session) {
                        // Nothing to do.

                    }

                    @Override
                    public void sessionModeChanged(Mode mode) {
                        // Nothing to do.

                    }

                    @Override
                    public void sessionChanged(Session session) {
                        domainsAccessed.clear();
                    }

                    @Override
                    public void sessionAboutToChange(Session session) {
                        // Nothing to do.
                    }
                });
    }

    private void addDiagnosticData(Diagnostic diagnostic) {
        List<AutomationPlan> plans = extensionAutomation.getRunningPlans();
        if (plans.isEmpty()) {
            diagnostic.setAfPlan("");
            return;
        }
        try {
            diagnostic.setAfPlan(plans.get(plans.size() - 1).toYaml());
        } catch (IOException e) {
            LOGGER.warn("An error occurred while setting the AF plan:", e);
        }
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

        if (diagnosticDataProvider != null) {
            AuthenticationDiagnostics.removeDiagnosticDataProvider(diagnosticDataProvider);
        }

        AuthenticationDiagnostics.addMessageAccessedConsumer(this::processMessageAccessed);
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

            ard.setDomains(getDomains(null));
            ard.setDomainsPartiallyOutOfScope(getDomains(ContextState.PARTIAL_OUT_OF_CONTEXT));
            ard.setDomainsOutOfScope(getDomains(ContextState.OUT_OF_CONTEXT));
            domainsAccessed.clear();

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
            boolean verificationUrlIdentified =
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

                    AuthenticationMethod authMethod = authContext.getAuthenticationMethod();

                    boolean authBBA =
                            authMethod
                                    instanceof
                                    BrowserBasedAuthenticationMethodType
                                            .BrowserBasedAuthenticationMethod;
                    boolean authClient =
                            authMethod
                                    instanceof
                                    ClientScriptBasedAuthenticationMethodType
                                            .ClientScriptBasedAuthenticationMethod;

                    // Add all of the stats
                    if (authMethod.getAuthCheckingStrategy() == AuthCheckingStrategy.POLL_URL
                            && StringUtils.isNotEmpty(authMethod.getPollUrl())) {
                        String pollHost =
                                SessionStructure.getHostName(
                                        new URI(authMethod.getPollUrl(), true));

                        if (!hostname.equals(pollHost)) {
                            addSiteStats(ard, inMemoryStats, pollHost);
                        }
                    }

                    inMemoryStats.getStats("").forEach((k, v) -> ard.addStatsItem(k, "global", v));
                    addSiteStats(ard, inMemoryStats, hostname);

                    if (authBBA || authClient) {

                        AutomationProgress afProg =
                                (AutomationProgress)
                                        reportData.getReportObject("automation.progress");

                        Long passedCount =
                                inMemoryStats.getStat(
                                        hostname, AuthUtils.AUTH_BROWSER_PASSED_STATS);

                        /*
                         * The AUTH_SUCCESS_STATS / AUTH_FAILURE_STATS stats can get raised on another domain.
                         * Any successes are good, as long as there are not more failures.
                         */
                        Long successStat =
                                inMemoryStats.getStat(
                                        hostname, AuthenticationHelper.AUTH_SUCCESS_STATS);
                        Long failureStat =
                                inMemoryStats.getStat(
                                        hostname, AuthenticationHelper.AUTH_FAILURE_STATS);

                        boolean hasMoreFailures =
                                failureStat != null
                                        && (successStat == null
                                                || failureStat.compareTo(successStat) > 0);

                        boolean hasAfErrors = afProg != null && afProg.hasErrors();

                        if (hasAfErrors) {
                            ard.setAfPlanErrors(afProg.getErrors());
                        }

                        boolean loggedIn = isLoggedIn(ard) && !isLoggedUnknown(ard);

                        boolean overallStatus =
                                sessionPassed
                                        && verificationUrlIdentified
                                        && (!authBBA || passedCount != null)
                                        && !hasAfErrors
                                        && !hasMoreFailures
                                        && loggedIn;
                        addSummaryItem(ard, "auth", overallStatus);
                        if (!overallStatus) {
                            if (!sessionPassed) {
                                ard.addFailureDetail(FailureDetail.SESSION_MGMT);
                            }
                            if (!verificationUrlIdentified) {
                                ard.addFailureDetail(FailureDetail.VERIF_IDENT);
                            }
                            if (!authBBA && passedCount == null) {
                                ard.addFailureDetail(FailureDetail.PASS_COUNT);
                            }
                            if (successStat == null) {
                                ard.addFailureDetail(FailureDetail.NO_SUCCESSFUL_LOGINS);
                            }
                            if (hasMoreFailures) {
                                ard.addFailureDetail(FailureDetail.LOGIN_FAILURES);
                            }
                            if (hasAfErrors) {
                                ard.addFailureDetail(FailureDetail.AF_PLAN_ERRORS);
                            }
                            if (!loggedIn) {
                                ard.addFailureDetail(FailureDetail.LOGGED_IN);
                            }

                            // We got this far so did fail overall
                            if (!ard.hasFailureDetails()) {
                                ard.addFailureDetail(FailureDetail.OVERALL);
                            }
                        }

                        if (passedCount != null) {
                            addSummaryItem(ard, "username", true);
                            addSummaryItem(ard, "password", true);
                        } else if (authBBA) {
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
                                        && verificationUrlIdentified
                                        && inMemoryStats.getStat(
                                                        hostname,
                                                        AuthenticationHelper.AUTH_SUCCESS_STATS)
                                                != null);
                    }

                } catch (Exception e) {
                    LOGGER.warn(e.getMessage(), e);
                }

            } else {
                addSummaryItem(ard, "stats", false);
            }

            addSummaryItem(ard, "session", sessionPassed);
            addSummaryItem(ard, "verif", verificationUrlIdentified);

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

        private static Set<String> getDomains(ContextState state) {
            return domainsAccessed.entrySet().stream()
                    .filter(e -> state == null || e.getValue() == state)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toCollection(TreeSet::new));
        }

        private static void addSiteStats(
                AuthReportData ard, InMemoryStats inMemoryStats, String site) {
            inMemoryStats
                    .getSiteStats(site, "")
                    .forEach((k, v) -> ard.addStatsItem(k, "site", site, v));
        }

        private static boolean isLoggedIn(AuthReportData ard) {
            return hasStat(ard, AuthenticationMethod.AUTH_STATE_LOGGED_IN_STATS);
        }

        private static boolean hasStat(AuthReportData ard, String stat) {
            return ard.getStatisticsImpl().stream().anyMatch(e -> stat.equals(e.key()));
        }

        private static boolean isLoggedUnknown(AuthReportData ard) {
            return hasStat(ard, AuthenticationMethod.AUTH_STATE_UNKNOWN_STATS);
        }
    }
}
