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
package org.zaproxy.addon.dev.seq.performance;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SequencePage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(SequencePage.class);
    private TestProxyServer server;

    private static int numberOfSteps = 3;
    private static int numberOfFields = 3;
    private static boolean checkSequence = true;

    private Map<UUID, Integer> seqMap = new HashMap<>();

    public SequencePage(TestProxyServer server) {
        super(server, "seq");
        this.server = server;
    }

    /**
     * Set the number of steps to be used in the sequence, default is 3. This is designed to be
     * called from a script.
     *
     * @param numberOfSteps
     */
    public static void setNumberOfSteps(int numberOfSteps) {
        SequencePage.numberOfSteps = numberOfSteps;
    }

    /**
     * Set the number of fields to be used in each step, default is 3. This is designed to be called
     * from a script.
     *
     * @param numberOfFields
     */
    public static void setNumberOfFields(int numberOfFields) {
        SequencePage.numberOfFields = numberOfFields;
    }

    /**
     * If true then the sequence ordering will be enforces, if false then the steps can be submitted
     * in any order.
     *
     * @param checkSequence
     */
    public static void setCheckSequence(boolean checkSequence) {
        SequencePage.checkSequence = checkSequence;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String body = server.getTextFile(this.getParent(), "seq.html");

        UUID seqUuid = null;
        int seqStep = 0;

        if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            String seqId = super.getFormParameter(msg, "seqId");
            if (seqId != null) {
                try {
                    seqUuid = UUID.fromString(seqId);
                } catch (Exception e) {
                    // Ignore
                }
            }
            String seqStepStr = super.getFormParameter(msg, "seqStep");
            if (seqStepStr != null) {
                try {
                    seqStep = Integer.parseInt(seqStepStr);
                } catch (NumberFormatException e) {
                    // Ignore
                }
            }
        }
        if (seqUuid == null) {
            // Its the start of a new sequence
            seqUuid = UUID.randomUUID();
            if (checkSequence) {
                seqMap.put(seqUuid, seqStep);
            }
        }

        try {
            StringBuilder sb = new StringBuilder();
            String responseStatus = TestProxyServer.STATUS_OK;

            Integer expectedStep = seqMap.get(seqUuid);

            if (checkSequence && expectedStep == null) {
                // Unknown sequence
                sb.append("Unregistered sequence!\n");
                sb.append("<p>\n");
                sb.append("Sorry, but you have to <a href=\"seq\">Start Again</a>");
                sb.append("<p>\n");

                responseStatus = TestProxyServer.STATUS_FORBIDDEN;
                seqMap.remove(seqUuid);
            } else if (checkSequence && seqStep != expectedStep) {
                // Out of sequence
                sb.append("Out of sequence step!\n");
                sb.append("Got ");
                sb.append(seqStep);
                sb.append(" but expected ");
                sb.append(seqMap.get(seqUuid));
                sb.append("<p>\n");
                sb.append("Sorry, but you have to <a href=\"seq\">Start Again</a>");
                sb.append("<p>\n");

                responseStatus = TestProxyServer.STATUS_FORBIDDEN;
                seqMap.remove(seqUuid);

            } else if (seqStep >= numberOfSteps) {
                // All done, just need to output the vulnerable value..
                sb.append("You got to the end of the sequence!\n");
                sb.append("<p>\n");
                sb.append("The final value supplied was ");
                sb.append(super.getFormParameter(msg, "vuln"));
                sb.append("<p>\n");
                sb.append("<a href=\"seq\">Start Again</a>");
                sb.append("<p>\n");

                if (checkSequence) {
                    seqMap.remove(seqUuid);
                }
            } else {
                seqStep++;
                if (checkSequence) {
                    seqMap.put(seqUuid, seqStep);
                }

                sb.append("<H3>Step ");
                sb.append(seqStep);
                sb.append("</H3>\n");
                sb.append("<form method=\"POST\">\n");
                appendInput(sb, "hidden", "step" + seqStep, Integer.toString(seqStep));
                appendInput(sb, "hidden", "seqId", seqUuid.toString());
                appendInput(sb, "hidden", "seqStep", Integer.toString(seqStep));

                sb.append("<table style=\"border: none;\">\n");
                IntStream.range(0, numberOfFields)
                        .forEach(i -> appendParam(sb, "Field " + i, "text", "field" + i, ""));

                if (seqStep == numberOfSteps) {
                    appendParam(sb, "Vulnerable Param", "text", "vuln", "Not Safe!");
                }

                sb.append("<tr>\n");
                sb.append("\t<td></td>\n");
                sb.append("\t<td><button>Next</button></td>\n");
                sb.append("</tr>\n");
                sb.append("</table>\n");
                sb.append("</form>\n");
            }
            body = body.replace("<!-- CONTENT -->", sb.toString());

            msg.setResponseBody(body);
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            responseStatus, "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private static void appendParam(
            StringBuilder sb, String desc, String type, String name, String value) {
        sb.append("<tr>\n");
        sb.append("\t<td>");
        sb.append(desc);
        sb.append(":\n");
        sb.append("\t<td>");
        appendInput(sb, type, name, value);
        sb.append("\t</td>\n");
        sb.append("</tr>\n");
    }

    private static void appendInput(StringBuilder sb, String type, String name, String value) {
        sb.append("<input id=\"");
        sb.append(name);
        sb.append("\" name=\"");
        sb.append(name);
        sb.append("\" type=\"");
        sb.append(type);
        sb.append("\" value=\"");
        sb.append(value);
        sb.append("\">\n");
    }

    @Override
    public PerformanceDir getParent() {
        return (PerformanceDir) super.getParent();
    }
}
