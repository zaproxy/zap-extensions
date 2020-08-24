/*
 *
 * Paros and its related class files.
 *
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 *
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/01/02 Separate param and attack
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/08/01 Removed the "(non-Javadoc)" comments.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2015/07/27 Issue 1618: Target Technology Not Honored
// ZAP: 2016/02/02 Add isStop() checks and refactor the code to reduce code duplication
// ZAP: 2018/02/01 Issue 1366: Change match pattern slightly, and implement pre-check
// ZAP: 2019/05/08 Normalise format/indentation.
// ZAP: 2020/07/24 Normalise scan rule class names.
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class ServerSideIncludeScanRule extends AbstractAppParamPlugin {

    private static final Logger LOGGER = Logger.getLogger(ServerSideIncludeScanRule.class);

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.serversideinclude.";

    private static final String SSI_UNIX = "<!--#EXEC cmd=\"ls /\"-->";
    private static final String SSI_UNIX2 = "\">" + SSI_UNIX + "<";
    private static final String SSI_WIN = "<!--#EXEC cmd=\"dir \\\"-->";
    private static final String SSI_WIN2 = "\">" + SSI_WIN + "<";

    private static Pattern patternSSIUnix =
            Pattern.compile("\\broot\\b.*\\busr\\b", PATTERN_PARAM | Pattern.DOTALL);
    private static Pattern patternSSIWin =
            Pattern.compile(
                    "\\bprogram files\\b.*\\b(WINDOWS|WINNT)\\b", PATTERN_PARAM | Pattern.DOTALL);

    @Override
    public int getId() {
        return 40009;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Linux)
                || technologies.includes(Tech.MacOS)
                || technologies.includes(Tech.Windows)) {
            return true;
        }
        return false;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    // Pre-check the original response for the detection pattern (to avoid false positives)
    private boolean isEvidencePresent(Pattern pattern) {
        return matchBodyPattern(getBaseMsg(), pattern, null);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        if ((this.inScope(Tech.Linux) || this.inScope(Tech.MacOS))
                && !isEvidencePresent(patternSSIUnix)) {

            if (testServerSideInclude(param, SSI_UNIX, patternSSIUnix)) {
                return;
            }

            if (testServerSideInclude(param, SSI_UNIX2, patternSSIUnix)) {
                return;
            }
        }

        if (this.inScope(Tech.Windows) && !isEvidencePresent(patternSSIWin)) {

            if (testServerSideInclude(param, SSI_WIN, patternSSIWin)) {
                return;
            }

            if (testServerSideInclude(param, SSI_WIN2, patternSSIWin)) {
                return;
            }
        }
    }

    /**
     * Tests for SSI vulnerability in the give {@code parameter} with the given {@code value}.
     *
     * @param parameter the name of the parameter that will be used for testing SSI
     * @param value the value of the parameter that will be used for testing SSI
     * @param testEvidence the pattern used to assert that the test worked
     * @return {@code true} if the test should stop, either because a vulnerability was found or the
     *     scanner was stopped, {@code false} otherwise.
     */
    private boolean testServerSideInclude(String parameter, String value, Pattern testEvidence) {
        if (isStop()) {
            return true;
        }

        HttpMessage message = getNewMsg();
        try {
            setParameter(message, parameter, value);
            sendAndReceive(message);

            StringBuilder evidence = new StringBuilder();
            if (matchBodyPattern(message, testEvidence, evidence)) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(parameter)
                        .setAttack(value)
                        .setEvidence(evidence.toString())
                        .setMessage(message)
                        .raise();
                return true;
            }
        } catch (IOException e) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "IO exception while sending a message [URI="
                                + getBaseMsg().getRequestHeader().getURI()
                                + ", parameter="
                                + parameter
                                + ", value="
                                + value
                                + "]:",
                        e);
            }
        }
        return false;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 97;
    }

    @Override
    public int getWascId() {
        return 31;
    }
}
