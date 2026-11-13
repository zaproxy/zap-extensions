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
package org.zaproxy.addon.sqliwip;

import java.io.IOException;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.TechSet;

/**
 * Narrow seam a {@link DetectionStrategy} uses to talk to the scan engine, without needing to
 * extend {@code AbstractAppParamPlugin} itself.
 *
 * <p>Implemented by {@link SqlInjectionModularScanRule}, which already has access to the
 * (package-private-to-{@code org.parosproxy.paros.core.scanner}) scanner primitives this delegates
 * to. Keeping this interface narrow is what lets each {@link DetectionStrategy} live in its own
 * file/class and be unit tested in isolation from the others.
 */
public interface ScanContext {

    /**
     * Suffix appended to the original value to build the benign control value, sent once per
     * parameter before any technique runs. No SQL metacharacters, so a page that errors on it is
     * erroring on anything, which is what makes it a control rather than a payload.
     */
    String CONTROL_SUFFIX = "_safe_control";

    /** The message as originally seen, before any injection. */
    HttpMessage getBaseMessage();

    /**
     * A fresh copy of the base message, ready to have a payload set on the parameter under test.
     */
    HttpMessage newMessage();

    /** Sets {@code value} on the parameter under test in {@code message}. */
    void setParam(HttpMessage message, String value);

    /** Sends {@code message} and waits for the response. */
    void sendAndReceive(HttpMessage message) throws IOException;

    /** Whether the scan has been asked to stop (e.g. the user cancelled it). */
    boolean isStopped();

    /** Starts building an alert for a finding raised by a strategy. */
    AlertBuilder newAlert();

    /** Name of the parameter under test. */
    String getParamName();

    /** Original (un-injected) value of the parameter under test. */
    String getOriginalValue();

    /** Tech scope for the target application (e.g., MySQL, PostgreSQL). */
    TechSet getTechSet();

    /**
     * Current attack strength, used by strategies to skip expensive payload families (e.g. LIKE
     * attacks, which baseline rule 40018 only runs at HIGH) that would blow the per-strength
     * message budgets.
     */
    AttackStrength getAttackStrength();

    /**
     * Current alert threshold, used by strategies to gate noisy/FP-prone payload families (e.g. the
     * LIKE family) so they only run when the user has opted into low-evidence scanning.
     */
    AlertThreshold getAlertThreshold();

    /**
     * Sets the current technique identifier so budget tracking is per-technique. Called by the scan
     * rule before invoking each {@link DetectionStrategy}, passing the name of its technique.
     */
    void setCurrentTechnique(String technique);

    /**
     * The number of requests remaining in the per-technique budget at the current attack strength.
     * Strategies must stop sending requests once they've used this many. Each technique has its own
     * allocated budget; earlier strategies that succeed in finding a vulnerability do not affect
     * the budget available to later techniques.
     */
    int getRemainingBudget();

    /** Parameter context analysis hints for payload prioritization and strategy ordering. */
    ParameterContext getParameterContext();

    /**
     * Cached baseline response (un-injected). Reused across strategies to avoid redundant requests.
     */
    HttpMessage getCachedBaseline();

    /**
     * Cached control response (injected with a safe, non-SQL-breaking value). Reused by strategies
     * for false-positive validation.
     */
    HttpMessage getCachedControl();

    /**
     * The baseline request sent again, fetched on first use and cached for the rest of the
     * parameter. Comparing it against the baseline tells volatile content (timestamps, counters,
     * tokens) from a genuine outcome change, which is what lets a strategy keep working on a page
     * whose body moves on every request.
     *
     * <p>Charged to the technique whose strategy asks for it, the way any other probe is: the
     * technique's budget pays for it and it shows up in that technique's request count. Callers
     * must check their budget first, exactly as they do before sending a probe of their own.
     *
     * @return the replay of the baseline for the parameter under test
     * @throws IOException if the replay cannot be sent
     */
    HttpMessage getRepeatedBaseline() throws IOException;

    /**
     * Records that a probe response matched the baseline — the first gate every differential
     * technique must pass before it can raise an alert. Counted per request so the metrics runner
     * can report how close a non-injectable row came to alerting: rows that pass this gate without
     * alerting are the ones a noisy page would have to fool to produce a false positive.
     */
    void recordBaselineMatch();

    /**
     * Records a differential that would have alerted but was not raised, because the difference was
     * explained by the probe answering with an error status (rate limited, WAF, timeout). These are
     * the closest near misses a scan has, and the count is reported alongside {@link
     * #recordBaselineMatch()}.
     */
    void recordSuppressedDifferential();
}
