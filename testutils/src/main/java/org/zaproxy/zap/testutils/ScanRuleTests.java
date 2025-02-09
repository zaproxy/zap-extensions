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
package org.zaproxy.zap.testutils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.auth.AuthenticationMethod;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.testutils.ZapTestCase;

interface ScanRuleTests {

    Object getScanRule();

    @TestFactory
    default Collection<DynamicTest> addScanRuleTests() {
        List<DynamicTest> tests = new ArrayList<>();
        // XXX Enable once all rules pass.
        // tests.add(dynamicTest("shouldHaveValidReferences", this::shouldHaveValidReferences));
        return tests;
    }

    default void shouldHaveValidReferences() {
        // Given / When
        Set<String> references = getAllReferences(getScanRule());
        // Then
        if (references.isEmpty()) {
            return;
        }

        List<AlertReferenceError> errors = new ArrayList<>();
        for (String reference : references) {
            if (!reference.startsWith(HttpHeader.HTTP)) {
                errors.add(AlertReferenceError.Cause.NOT_LINK.create(reference, ""));
                continue;
            }

            URI uri;
            try {
                uri = new URI(reference, true);
            } catch (Exception e) {
                errors.add(AlertReferenceError.Cause.INVALID_URI.create(reference, e));
                continue;
            }

            if (!HttpHeader.HTTPS.equals(uri.getScheme())) {
                errors.add(AlertReferenceError.Cause.NOT_HTTPS.create(reference, ""));
            } else if (false) {
                fetchUrl(uri, reference, errors);
            }
        }

        assertThat(errors.toString(), errors, is(empty()));
    }

    private static void fetchUrl(URI uri, String reference, List<AlertReferenceError> errors) {
        try {
            HttpMessage message = new HttpMessage(uri);
            new HttpSender(0).sendAndReceive(message);
            var responseHeader = message.getResponseHeader();
            int statusCode = responseHeader.getStatusCode();
            if (statusCode != HttpStatusCode.OK) {
                errors.add(
                        AlertReferenceError.Cause.UNEXPECTED_STATUS_CODE.create(
                                reference, statusCode));
            }
        } catch (IOException e) {
            errors.add(AlertReferenceError.Cause.IO_EXCEPTION.create(reference, e));
        }
    }

    private static Set<String> getAllReferences(Object scanRule) {
        Set<String> references = new TreeSet<>();
        if (scanRule instanceof ExampleAlertProvider) {
            Optional.ofNullable(((ExampleAlertProvider) scanRule).getExampleAlerts())
                    .orElse(List.of())
                    .stream()
                    .map(Alert::getReference)
                    .map(ScanRuleTests::convertReferences)
                    .flatMap(Function.identity())
                    .forEach(references::add);
        }
        if (scanRule instanceof Plugin) {
            convertReferences(((Plugin) scanRule).getReference()).forEach(references::add);
        }

        return references;
    }

    private static Stream<String> convertReferences(String refs) {
        return Arrays.stream(Optional.ofNullable(refs).orElse("").split("\\r?\\n"))
                .map(String::trim)
                .filter(e -> !e.isEmpty());
    }
}


public class CredentiallessScanTest extends ZapTestCase {

    @Test
    void shouldHandleMissingCredentialsGracefully() {
        // Given: An unauthenticated scan rule
        ScanRule scanRule = new ScanRule(); // assuming this is a rule being tested
        scanRule.setAuthenticationMethod(null); // Simulate missing credentials

        // When: Running the scan with the missing credentials
        ApiResponse response = runScan(scanRule);  // Assuming runScan is a helper method to simulate the scan

        // Then: The scan should indicate an authentication issue or produce an appropriate error message
        assertThat("The scan should indicate missing credentials", response.getMessage(),
                containsString("Authentication failed or credentials missing"));

        // Optional: Check that no sensitive data was exposed (if relevant to the problem)
        assertThat("No sensitive data should be exposed", response.getBody(), not(containsString("sensitive data")));
    }

    // Helper method to simulate running a scan
    private ApiResponse runScan(ScanRule scanRule) {
        // This would be a mock or a real method to simulate a scan in your testing environment
        return scanRule.run();
    }
}
