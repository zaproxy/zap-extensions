/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
/*
 * A Format String  scan rule
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE
 */
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.net.UnknownHostException;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpResponseBody;

public class FormatStringScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.formatstring.";

    private static final int PLUGIN_ID = 30002;
    private static Logger log = LogManager.getLogger(FormatStringScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.C);
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

    private String getError(char c) {
        return Constant.messages.getString(MESSAGE_PREFIX + "error" + c);
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        if (this.isStop()) { // Check if the user stopped things
            log.debug("Scanner {} Stopping.", getName());
            return; // Stop!
        }

        if (isPage500(getBaseMsg())) // Check to see if the page closed initially
        {
            return; // Stop
        }

        try {

            /*
             * This represents the meaning of format string variables.
             * %%  character (literal)  Reference
             * %p  External representation of a pointer to void  Reference
             * %d  Decimal  Value
             * %c  Character
             * %u  Unsigned decimal  Value
             * %x  Hexadecimal  Value
             * %s  String  Reference
             * %n  Writes the number of characters into a pointer  Reference
             */
            // Always use getNewMsg() for each new request
            HttpMessage testMsg = getNewMsg();
            String initialMessage = "ZAP";
            setParameter(testMsg, param, initialMessage);
            try {
                sendAndReceive(testMsg);
            } catch (InvalidRedirectLocationException | UnknownHostException ex) {
                log.debug(
                        "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        testMsg.getRequestHeader().getURI().toString());
                return; // Something went wrong, no point continuing
            }

            if (isPage500(testMsg)) {
                return; // Initial message returned error, subsequent requests are likely to as well
            }

            HttpResponseBody initialResponseBody = testMsg.getResponseBody();
            int initialResponseLength = initialResponseBody.length();
            //  The following section of the code attacks GNU and generic C compiler format
            //	string errors.  It does not attack specific Microsoft format string  errors.
            StringBuilder sb = new StringBuilder();
            sb.append(initialMessage);
            int i;
            //  Use a large number of %s in series;  Because `%s' displays memory from an address
            //  that is supplied on the stack, where a lot of other data is stored, too, our
            //  chances are high to read from an illegal address, which is not mapped. Also
            //  you can use `%n' to write to the addresses on the stack a few times, which
            //  should reliably produce a crash, too.

            for (i = 0; i < 20; i++) {
                sb.append("%n%s");
            }
            sb.append('\n');
            String initialAttackPayload = sb.toString();

            HttpMessage intialAttackMsg = getNewMsg();
            setParameter(intialAttackMsg, param, initialAttackPayload);
            try {
                sendAndReceive(intialAttackMsg);
            } catch (InvalidRedirectLocationException | UnknownHostException ex) {
                log.debug(
                        "Caught {} {} when accessing: {}.\nThe target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        intialAttackMsg.getRequestHeader().getURI().toString());
                return; // Something went wrong, no point continuing
            }
            if (isPage500(intialAttackMsg)) {
                StringBuilder sb1 = new StringBuilder();
                sb1.append(initialMessage);
                for (i = 0; i < 10; i++) {
                    sb1.append("%x");
                }
                sb1.append('\n');
                String secondAttackPayload = sb1.toString();

                HttpMessage verificationMsg = getNewMsg();
                setParameter(verificationMsg, param, secondAttackPayload);
                try {
                    sendAndReceive(verificationMsg);
                } catch (InvalidRedirectLocationException | UnknownHostException ex) {
                    log.debug(
                            "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            verificationMsg.getRequestHeader().getURI().toString());
                    return; // Something went wrong, no point continuing
                }
                HttpResponseBody secondAttackResponseBody = verificationMsg.getResponseBody();
                if (secondAttackResponseBody.length() > initialResponseLength + 20
                        && isPage200(verificationMsg)) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(secondAttackPayload)
                            .setOtherInfo(getError('2'))
                            .setMessage(verificationMsg)
                            .raise();
                } else {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(initialAttackPayload)
                            .setOtherInfo(getError('1'))
                            .setMessage(intialAttackMsg)
                            .raise();
                }
                return;
            }
            //  The following section of the code only attacks Microsoft C compiler format string
            // errors.  It is only
            //  used if the GNU and generic C compiler check fails to find a vulnerability.
            if (this.isStop()) { // Check if the user stopped things
                log.debug("Scanner {} Stopping.", getName());
                return; // Stop!
            }
            StringBuilder sb2 = new StringBuilder();
            sb2.append(initialMessage);
            sb2.append(' ');
            for (i = 0; i < 20; i++) {
                sb2.append('%');
                sb2.append(i + 1);
                sb2.append("!s");
            }
            for (i = 20; i < 40; i++) {
                sb2.append('%');
                sb2.append(i + 1);
                sb2.append("!n");
            }
            sb2.append('\n');
            String microsoftAttackMessage = sb2.toString();
            HttpMessage microsoftTestMsg = getNewMsg();
            setParameter(microsoftTestMsg, param, microsoftAttackMessage);
            try {
                sendAndReceive(microsoftTestMsg);
            } catch (InvalidRedirectLocationException | UnknownHostException ex) {
                log.debug(
                        "Caught {} {} when accessing: {}. \nThe target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        microsoftTestMsg.getRequestHeader().getURI().toString());
                return; // Something went wrong, no point continuing
            }
            if (isPage500(microsoftTestMsg)) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(microsoftAttackMessage)
                        .setOtherInfo(getError('3'))
                        .setMessage(microsoftTestMsg)
                        .raise();
            }
            return;

        } catch (URIException e) {
            log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 134;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 6;
    }
}
