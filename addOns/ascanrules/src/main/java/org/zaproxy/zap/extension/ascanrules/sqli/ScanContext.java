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
package org.zaproxy.zap.extension.ascanrules.sqli;

import java.io.IOException;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
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
     * Sets the current technique identifier so budget tracking is per-technique. Called by the scan
     * rule before invoking each {@link DetectionStrategy}, passing one of: "ERROR", "EXPRESSION",
     * "BOOLEAN", "ORDERBY", "UNION".
     */
    void setCurrentTechnique(String technique);

    /**
     * The number of requests remaining in the per-technique budget at the current attack strength.
     * Strategies must stop sending requests once they've used this many. Each technique has its own
     * allocated budget; earlier strategies that succeed in finding a vulnerability do not affect
     * the budget available to later techniques.
     */
    int getRemainingBudget();
}
