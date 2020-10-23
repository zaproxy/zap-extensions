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
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2013/01/25 Removed the "(non-Javadoc)" comments.
// ZAP: 2014/09/16 Address FindBug issue surrounding attempt to compute absolute value of signed
// random int
// RV_ABSOLUTE_VALUE_OF_RANDOM_INT
// ZAP: 2014/09/16 Removed forced HTML reference formatting and add proper WASC id.
// ZAP: 2019/05/08 Normalise format/indentation.
// ZAP: 2020/07/24 Normalise scan rule class names.
package org.zaproxy.zap.extension.ascanrules;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class CrlfInjectionScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.crlfinjection.";

    private String randomString = "Tamper=" + UUID.randomUUID().toString();
    private String cookieTamper1 = "Set-cookie: " + randomString;
    private String cookieTamper2a = "any\r\nSet-cookie: " + randomString;
    private String cookieTamper2b = "any?\r\nSet-cookie: " + randomString;
    private String cookieTamper3a = "any\nSet-cookie: " + randomString;
    private String cookieTamper3b = "any?\nSet-cookie: " + randomString;
    private String cookieTamper4a = "any\r\nSet-cookie: " + randomString + "\r\n";
    private String cookieTamper4b = "any?\r\nSet-cookie: " + randomString + "\r\n";

    // should not be changed to static as Global may not be ready
    private String[] PARAM_LIST = {
        cookieTamper1,
        cookieTamper2a,
        cookieTamper2b,
        cookieTamper3a,
        cookieTamper3b,
        cookieTamper4a,
        cookieTamper4b
    };

    private Pattern patternCookieTamper =
            Pattern.compile("\\nSet-cookie: " + randomString, PATTERN_PARAM);

    @Override
    public int getId() {
        return 40003;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        // loop parameters

        for (int i = 0; i < PARAM_LIST.length; i++) {
            HttpMessage testMsg = getNewMsg();
            setParameter(testMsg, param, PARAM_LIST[i]);
            try {
                sendAndReceive(testMsg, false);
                if (checkResult(testMsg, param, PARAM_LIST[i])) {
                    return;
                }

            } catch (Exception e) {
            }
        }
    }

    private boolean checkResult(HttpMessage msg, String param, String attack) {
        // no need to bother if response OK or not.
        //      if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK
        //          && !HttpStatusCode.isServerError(msg.getResponseHeader().getStatusCode())) {
        //          return false;
        //      }

        Matcher matcher = patternCookieTamper.matcher(msg.getResponseHeader().toString());
        if (matcher.find()) {
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(param)
                    .setAttack(matcher.group())
                    .setOtherInfo(attack)
                    .setMessage(msg)
                    .raise();
            return true;
        }

        return false;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 113;
    }

    @Override
    public int getWascId() {
        return 25;
    }
}
