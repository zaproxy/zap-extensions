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

/**
 * One SQL injection detection technique (error-based, boolean-based, time-based, ...).
 *
 * <p>Each implementation owns exactly one technique end to end: building its own payloads, sending
 * its own requests via the given {@link ScanContext}, deciding whether the response is evidence of
 * injection, and raising its own alert (via {@code context.newAlert()...raise()}) if so. The
 * orchestrator ({@link SqlInjectionModularScanRule}) knows nothing about how any individual
 * strategy works -- it just runs each one in turn until one reports a finding. This is the seam
 * that keeps the rule from re-collapsing into one monolithic method the way the existing generic
 * SQL injection rule (id 40018) did.
 */
public interface DetectionStrategy {

    /**
     * Runs this strategy against the parameter described by {@code context}.
     *
     * @param context the scan context for the parameter currently under test
     * @return {@code true} if this strategy found and raised an alert for a vulnerability, {@code
     *     false} otherwise
     * @throws IOException if sending a request failed
     */
    boolean detect(ScanContext context) throws IOException;
}
