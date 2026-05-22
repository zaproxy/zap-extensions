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
package org.zaproxy.zap.extension.scripts.zest;

import java.util.List;
import java.util.Optional;

public interface ZestScriptDiagnosticSource {

    /**
     * {@code context}: full diagnostic text; {@code detailMessage}: single-line summary; unknown
     * indices are {@code -1}. {@code printCaptures}: print output captured during the run, in
     * execution order.
     */
    record ZestScriptRunDiagnostic(
            String context,
            String detailMessage,
            int chainScriptOrder,
            int sourceStatementIndex,
            String elementType,
            String screenshotBase64,
            List<ZestScriptPrintCapture> printCaptures) {
        public ZestScriptRunDiagnostic {
            printCaptures = printCaptures == null ? List.of() : List.copyOf(printCaptures);
        }
    }

    /**
     * One line of output captured from a script's print statement. {@code chainScriptOrder} is the
     * 1-based chain segment index for chain runs (or {@code -1} for single-script runs).
     */
    record ZestScriptPrintCapture(int chainScriptOrder, String line) {}

    Optional<ZestScriptRunDiagnostic> getLastRunDiagnostic();

    default List<ZestScriptPrintCapture> getLastRunPrintCaptures() {
        return getLastRunDiagnostic().map(ZestScriptRunDiagnostic::printCaptures).orElse(List.of());
    }
}
