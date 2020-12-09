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
 * Integer Overflow an active scan rule
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class IntegerOverflowScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.integeroverflow.";

    private static final int PLUGIN_ID = 30003;
    private static final Logger log = Logger.getLogger(IntegerOverflowScanRule.class);

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

        if (checkStop() == true) {
            return;
        }
        if (isPage500(getBaseMsg())) // Check to see if the page was initially a 500
        {
            return; // Stop
        }

        String returnAttack = randomIntegerString(4); // The number of full length ints to send.
        if (attackVector(param, '1', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '0'); // The number of full length ints to send.
        if (attackVector(param, '2', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '1'); // The number of full length ints to send.
        if (attackVector(param, '3', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '9'); // The number of full length ints to send.
        if (attackVector(param, '4', returnAttack) == true) {
            return;
        }
        return;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 190;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 3;
    }

    private String randomIntegerString(int length) {

        int numbercounter = 0;
        int character = 0;
        long charactercounter = 0;
        int maxcharacter = 11;
        StringBuilder sb1 = new StringBuilder(maxcharacter * length);
        while (numbercounter < length) {
            charactercounter = 0;
            while (charactercounter < maxcharacter) {
                character = 48 + (int) (Math.random() * 10);

                while (character > 57 && character < 48) {
                    character = 48 + (int) (Math.random() * 10);
                }

                charactercounter++;
                sb1.append((char) character);
            }
            numbercounter++;
        }
        return sb1.toString();
    }

    private String singleString(int length, char c) // Single Character String
            {

        int numbercounter = 0;
        long charactercounter = 0;
        int maxcharacter = 11;
        StringBuilder sb1 = new StringBuilder(maxcharacter * length);
        while (numbercounter < length) {
            charactercounter = 0;
            while (charactercounter < maxcharacter) {
                charactercounter++;
                sb1.append(c);
            }
            numbercounter++;
        }
        return sb1.toString();
    }

    private boolean checkStop() {
        if (this.isStop()) { // Check if the user stopped things
            if (log.isDebugEnabled()) {
                log.debug("Scan rule " + this.getName() + " Stopping.");
            }
            return true; // Stop!
        }
        return false;
    }

    private boolean attackVector(String param, char type, String returnAttack) {
        if (checkStop() == true) {
            return true;
        }
        HttpMessage msg;
        msg = getNewMsg();
        setParameter(msg, param, returnAttack);
        try {
            sendAndReceive(msg);
            if (isPage500(msg)) {
                log.debug("Found Header");
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setUri(this.getBaseMsg().getRequestHeader().getURI().toString())
                        .setParam(param)
                        .setAttack(returnAttack)
                        .setOtherInfo(this.getError(type))
                        .setMessage(msg)
                        .raise();
                return true;
            }
        } catch (IOException e) {
            log.debug(e.getMessage(), e);
        }
        return false;
    }
}
