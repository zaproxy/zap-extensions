/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Performance test for ContentSecurityPolicyMissingScanRule
 * to demonstrate the META tag parsing bottleneck (Issue #9229)
 */
class ContentSecurityPolicyMissingScanRulePerformanceTest
        extends PassiveScannerTest<ContentSecurityPolicyMissingScanRule> {

    private static final String URI_STRING = "https://www.example.com";
    private static final String HEADER_HTML = "Content-Type: text/html";

    @Override
    protected ContentSecurityPolicyMissingScanRule createScanner() {
        return new ContentSecurityPolicyMissingScanRule();
    }

    /**
     * This test demonstrates the performance issue with META tag parsing.
     * A page with many META tags (simulating modern frameworks) should be
     * significantly faster at MEDIUM threshold (no META parsing) than at LOW (with META parsing).
     */
    @Test
    void testPerformanceWithManyMetaTags() throws Exception {
        // Create a response with 500 META tags (common in modern SPAs)
        StringBuilder htmlBody = new StringBuilder("<html><head>");
        
        // Add 500 META tags (none are CSP)
        for (int i = 0; i < 500; i++) {
            htmlBody.append("<meta name=\"tag").append(i).append("\" content=\"value").append(i).append("\">");
        }
        htmlBody.append("</head><body><h1>Test</h1></body></html>");

        HttpMessage msg = new HttpMessage(new URI(URI_STRING, false));
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + HEADER_HTML);
        msg.setResponseBody(htmlBody.toString());

        System.out.println("\n=== Performance Test: 500 META tags, no CSP ===");
        
        // Test at MEDIUM threshold (no META parsing)
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        long startMedium = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long mediumTime = System.currentTimeMillis() - startMedium;
        
        // Test at LOW threshold (with META parsing)
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        long startLow = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long lowTime = System.currentTimeMillis() - startLow;
        
        System.out.println("MEDIUM threshold (100 iterations): " + mediumTime + "ms");
        System.out.println("LOW threshold (100 iterations): " + lowTime + "ms");
        System.out.println("Difference: " + (lowTime - mediumTime) + "ms");
        System.out.println("Performance improvement: " + 
            String.format("%.1f", (lowTime - mediumTime) * 100.0 / lowTime) + "%");
        
        // The performance difference should be significant
        System.out.println("\nConclusion: " + 
            (lowTime > mediumTime * 2 ? "CONFIRMED - META parsing is the bottleneck" 
                                       : "Not significant - further investigation needed"));
    }

    /**
     * Test with realistic modern web page (100 META tags)
     */
    @Test
    void testPerformanceRealisticModernPage() throws Exception {
        StringBuilder htmlBody = new StringBuilder("<html><head>");
        
        // 100 META tags - typical for modern React/Angular apps
        for (int i = 0; i < 100; i++) {
            htmlBody.append("<meta property=\"og:tag").append(i).append("\" content=\"value").append(i).append("\">");
        }
        htmlBody.append("</head><body><h1>Modern SPA</h1></body></html>");

        HttpMessage msg = new HttpMessage(new URI(URI_STRING, false));
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + HEADER_HTML);
        msg.setResponseBody(htmlBody.toString());

        System.out.println("\n=== Performance Test: 100 META tags (realistic) ===");
        
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        long startMedium = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long mediumTime = System.currentTimeMillis() - startMedium;
        
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        long startLow = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long lowTime = System.currentTimeMillis() - startLow;
        
        System.out.println("MEDIUM threshold (1000 iterations): " + mediumTime + "ms");
        System.out.println("LOW threshold (1000 iterations): " + lowTime + "ms");
        System.out.println("Per-page overhead at LOW: " + String.format("%.2f", (lowTime - mediumTime) / 1000.0) + "ms");
        
        System.out.println("\nOn 10,000 pages scan:");
        System.out.println("  Additional time at LOW threshold: ~" + 
            String.format("%.1f", (lowTime - mediumTime) * 10.0 / 1000.0) + " seconds");
    }

    /**
     * Extreme case: very large page with many META tags
     */
    @Test
    void testPerformanceExtremeCaseVeryLargePage() throws Exception {
        StringBuilder htmlBody = new StringBuilder("<html><head>");
        
        // 1000 META tags - extreme but possible
        for (int i = 0; i < 1000; i++) {
            htmlBody.append("<meta name=\"extreme").append(i).append("\" content=\"test").append(i).append("\">");
        }
        htmlBody.append("</head><body><h1>Extreme Page</h1></body></html>");

        HttpMessage msg = new HttpMessage(new URI(URI_STRING, false));
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + HEADER_HTML);
        msg.setResponseBody(htmlBody.toString());

        System.out.println("\n=== Performance Test: 1000 META tags (extreme) ===");
        
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        long startMedium = System.currentTimeMillis();
        for (int i = 0; i < 50; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long mediumTime = System.currentTimeMillis() - startMedium;
        
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        long startLow = System.currentTimeMillis();
        for (int i = 0; i < 50; i++) {
            alertsRaised.clear();
            scanHttpResponseReceive(msg);
        }
        long lowTime = System.currentTimeMillis() - startLow;
        
        System.out.println("MEDIUM threshold (50 iterations): " + mediumTime + "ms");
        System.out.println("LOW threshold (50 iterations): " + lowTime + "ms");
        System.out.println("Per-page overhead: " + String.format("%.2f", (lowTime - mediumTime) / 50.0) + "ms");
    }
}
