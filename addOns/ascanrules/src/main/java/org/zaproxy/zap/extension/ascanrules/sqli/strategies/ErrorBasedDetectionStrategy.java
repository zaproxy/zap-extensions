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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects SQL injection by breaking the query with a metacharacter and recognizing a database error
 * signature ({@link DbErrorSignatures}) in the response.
 *
 * <p>Unlike the generic rule (40018), a raw error-signature match here is never itself sufficient:
 * some pages (see WAVSEP's honeypot false-positive traps) return a generic SQL-error-shaped
 * response for <em>any</em> malformed input, not specifically because of the SQL metacharacter.
 * Before alerting, this strategy re-sends the same parameter with a value that contains no SQL
 * metacharacters at all; if that control request produces the same error signature, the page errors
 * on anything, and this is not evidence of injection.
 */
public class ErrorBasedDetectionStrategy implements DetectionStrategy {

    /** Metacharacter payloads that tend to break a naively-concatenated SQL query. */
    private static final List<String> ERROR_PAYLOADS =
            List.of("'", "\"", "';", "\");", "'(", ")", "NULL", "'\"");

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        int used = 0;

        // Get baseline response for response similarity comparison (honeypot detection)
        HttpMessage baseline = context.newMessage();
        context.setParam(baseline, originalValue);
        context.sendAndReceive(baseline);
        used++;

        // Early exit: if baseline itself contains an error signature, the page is broken
        // (unrelated internal error), not vulnerable to injection
        if (DbErrorSignatures.identify(baseline.getResponseBody().toString()).isPresent()) {
            return false;
        }

        for (String payload : ERROR_PAYLOADS) {
            if (context.isStopped() || used >= budget) {
                return false;
            }

            String attackValue = originalValue + payload;
            HttpMessage attackMsg = context.newMessage();
            context.setParam(attackMsg, attackValue);
            context.sendAndReceive(attackMsg);
            used++;

            Optional<Dbms> dbms =
                    DbErrorSignatures.identify(attackMsg.getResponseBody().toString());
            if (dbms.isEmpty()) {
                continue;
            }

            if (used >= budget) {
                // No budget left to run the false-positive control check -- without it we can't
                // trust the match, so stop rather than risk alerting on an unconfirmed signature.
                return false;
            }
            used++;
            if (StrictInputValidationGuard.detectsStrictInputValidation(
                    context, originalValue, baseline, attackMsg, attackValue)) {
                continue;
            }

            String evidence =
                    dbms.get()
                            .findMatchedFragment(attackMsg.getResponseBody().toString())
                            .orElse(dbms.get().getLabel());
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(attackValue)
                    .setEvidence(evidence)
                    .setOtherInfo("Likely RDBMS: " + dbms.get().getLabel())
                    .setMessage(attackMsg)
                    .raise();
            return true;
        }
        return false;
    }

}
