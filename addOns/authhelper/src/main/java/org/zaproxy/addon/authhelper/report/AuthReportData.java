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

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;

@Getter
@Setter
public class AuthReportData implements Closeable {

    private static final String KEY_PREFIX = "auth.failure.";
    private static final String PREFIX = "authhelper.authreport.summary.fail.detail.";

    @Getter
    public enum FailureDetail {
        OVERALL("overall.failed"),
        PASS_COUNT("pass.count.failed"),
        SESSION_MGMT("sessmgmt.failed"),
        LOGIN_FAILURES("login.failures"),
        NO_SUCCESSFUL_LOGINS("no.successful.logins"),
        VERIF_IDENT("verif.failed");

        private final String key;
        private final String detail;

        private FailureDetail(String resName) {
            key = KEY_PREFIX + name().toLowerCase(Locale.ROOT);
            this.detail = Constant.messages.getString(PREFIX + resName);
        }
    }

    private static final Logger LOGGER = LogManager.getLogger(AuthReportData.class);

    private String site;
    private boolean validReport;
    private String afEnv;
    private List<SummaryItem> summaryItems = new ArrayList<>();
    private Map<String, StatsItem> statistics = new TreeMap<>();
    private List<String> nextSteps = new ArrayList<>();
    private PersistenceManager pm;
    private List<Diagnostic> diagnostics;
    private List<FailureDetail> failureDetails;

    public void addSummaryItem(boolean passed, String key, String description) {
        summaryItems.add(new SummaryItem(passed, key, description));
    }

    public void addFailureDetail(FailureDetail detail) {
        if (failureDetails == null) {
            failureDetails = new ArrayList<>();
        }
        failureDetails.add(detail);
    }

    public boolean hasFailureDetails() {
        return failureDetails != null && !failureDetails.isEmpty();
    }

    public void addStatsItem(String key, String scope, long value) {
        statistics.put(key, new StatsItem(key, scope, value));
    }

    public Object[] getStatistics() {
        return statistics.values().toArray();
    }

    public List<Diagnostic> getDiagnostics() {
        if (diagnostics == null) {
            diagnostics = readDiagnostics();
        }
        return diagnostics;
    }

    @SuppressWarnings("try")
    private List<Diagnostic> readDiagnostics() {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }

        pm = pmf.getPersistenceManager();
        try (Query<Diagnostic> query = pm.newQuery(Diagnostic.class)) {
            return new ArrayList<>(query.executeList());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while reading diagnostics", e);
        } catch (Exception e) {
            LOGGER.error("An error occurred while getting the diagnostics:", e);
        }
        return List.of();
    }

    @Override
    public void close() throws IOException {
        if (pm != null) {
            pm.close();
        }
    }

    public record SummaryItem(boolean passed, String key, String description) {}

    public record StatsItem(String key, String scope, long value) {}
}
