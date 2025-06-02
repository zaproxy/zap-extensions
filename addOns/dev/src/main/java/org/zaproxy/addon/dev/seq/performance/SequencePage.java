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
    private static final String PARA = "<p>\n";
    private static final String HIDDEN = "hidden";
    private TestProxyServer server;

    private static int numberOfSteps = 5;
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
     * If true then the sequence ordering will be enforced, if false then the steps can be submitted
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
        boolean stepBack = super.getFormParameter(msg, "back") != null;

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
                LOGGER.debug("New Sequence {}", seqUuid);
                seqMap.put(seqUuid, seqStep);
            }
        }

        try {
            StringBuilder sb = new StringBuilder();
            String responseStatus = TestProxyServer.STATUS_OK;

            Integer expectedStep = seqMap.get(seqUuid);

            if (checkSequence && expectedStep == null) {
                responseStatus = handledUnknownSequence(sb);
            } else if (checkSequence && seqStep > expectedStep) {
                responseStatus = handleOutOfSequenceStep(seqUuid, seqStep, sb);
            } else if (seqStep >= numberOfSteps) {
                handleFinalStep(seqUuid, sb);
            } else {
                handleIntermediateStep(msg, seqUuid, seqStep, stepBack, sb);
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

    private void handleIntermediateStep(
            HttpMessage msg, UUID seqUuid, int seqStep, boolean stepBack, StringBuilder sb) {
        if (stepBack) {
            seqStep--;
        } else {
            seqStep++;
            if (checkSequence && seqStep > seqMap.get(seqUuid)) {
                LOGGER.debug("Sequence step {} {} ", seqUuid, seqStep);
                seqMap.put(seqUuid, seqStep);
            }
        }

        sb.append("<H3>Step ");
        sb.append(seqStep);
        sb.append("</H3>\n");

        if (seqStep == numberOfSteps) {
            sb.append("The vulnerable value supplied was ");
            sb.append(super.getFormParameter(msg, "vuln"));
            sb.append(PARA);
        }

        sb.append("<form method=\"POST\">\n");
        appendInput(sb, HIDDEN, "step" + seqStep, Integer.toString(seqStep));
        appendInput(sb, HIDDEN, "seqId", seqUuid.toString());
        appendInput(sb, HIDDEN, "seqStep", Integer.toString(seqStep));

        sb.append("<table style=\"border: none;\">\n");
        IntStream.range(0, numberOfFields)
                .forEach(i -> appendParam(sb, "Field " + i, "text", "field" + i, ""));

        if (seqStep == numberOfSteps - 1) {
            appendParam(sb, "Vulnerable Param", "text", "vuln", "Not Safe!");
        }

        sb.append("<tr>\n");
        if (seqStep == 1) {
            sb.append("\t<td></td>\n");
        } else {
            sb.append("\t<td><button name=\"back\">Back</button></td>\n");
        }
        sb.append("\t<td><button name=\"next\">Next</button></td>\n");
        sb.append("</tr>\n");
        sb.append("</table>\n");
        sb.append("</form>\n");
    }

    private void handleFinalStep(UUID seqUuid, StringBuilder sb) {
        sb.append("You got to the end of the sequence!\n");
        sb.append(PARA);
        sb.append("<a href=\"seq\">Start Again</a>");
        sb.append(PARA);

        if (checkSequence) {
            LOGGER.debug("Finished Sequence {}", seqUuid);
            seqMap.remove(seqUuid);
        }
    }

    private String handleOutOfSequenceStep(UUID seqUuid, int seqStep, StringBuilder sb) {
        sb.append("Out of sequence step!\n");
        sb.append("Got ");
        sb.append(seqStep);
        sb.append(" but expected ");
        sb.append(seqMap.get(seqUuid));
        sb.append(PARA);
        sb.append("Sorry, but you have to <a href=\"seq\">Start Again</a>");
        sb.append(PARA);

        return TestProxyServer.STATUS_FORBIDDEN;
    }

    private static String handledUnknownSequence(StringBuilder sb) {
        sb.append("Unregistered sequence!\n");
        sb.append(PARA);
        sb.append("Sorry, but you have to <a href=\"seq\">Start Again</a>");
        sb.append(PARA);

        return TestProxyServer.STATUS_FORBIDDEN;
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
}
