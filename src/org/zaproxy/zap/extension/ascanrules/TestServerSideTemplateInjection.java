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
// Based off TestInjectionCRLF
// TODO: add more payloads, see: https://github.com/epinna/tplmap

package org.zaproxy.zap.extension.ascanrules;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TestServerSideTemplateInjection extends AbstractAppParamPlugin {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanrules.testinjectionssti.";
    private static Logger log = Logger.getLogger(TestServerSideTemplateInjection.class);

	// Payloads taken from flowchart here:
    // https://www.we45.com/blog/server-side-template-injection-a-crash-course-
    private String payload1 = "{9*99}";
    private String result1 = "891";

    private String payload1a = "ZAP{*comment*}ZAP";
    private String result1a = "ZAPZAP";

    private String payload1b = "{\"ZAP\".join(\"ZAP\")}";
    private String result1b = "zapzap";

    private String payload2 = "{{9*99}}";
    private String result2 = "891";

    private String payload2a = "{{9*'99'}}";
    private String result2a = "891";


    @Override
    public int getId() {
        return 9919991;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }



    @Override
    public String[] getDependency() {
        return null;
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
    public void init() {
 
    }
    
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        // start check following flowchart
        msg = getNewMsg();
        setParameter(msg, param, payload1);
        log.info(getName()+": Sending payload: "+payload1);

        try {
            sendAndReceive(msg, false);
            if (checkResult(msg, result1)) {

                msg = getNewMsg();
                setParameter(msg, param, payload1a);
                sendAndReceive(msg, false);
                log.info(getName()+": Sending payload: "+payload1a);

                if (checkResult(msg, result1a)){

                    bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, null,
                            param, payload1a, "Vulnerable to SSTI (Smarty Framework)", msg);

                } else {

                    msg = getNewMsg();
                    setParameter(msg, param, payload1b);
                    sendAndReceive(msg, false);
                    log.info(getName()+": Sending payload: "+payload1b);
                    if (checkResult(msg, result1b)){

                        bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, null,
                                param, result1b, "Vulnerable to SSTI (Mako Framework)", msg);

                    } else {

                        bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, null,
                                param, result1a, "Vulnerable to SSTI (Unknown Framework)", msg);

                    }

                }

            } else {

                msg = getNewMsg();
                setParameter(msg, param, payload2);
                sendAndReceive(msg, false);
                log.info(getName()+": Sending payload: "+payload2);

                if (checkResult(msg, result2)){

                    msg = getNewMsg();
                    setParameter(msg, param, payload2a);
                    sendAndReceive(msg, false);
                    log.info(getName()+": Sending payload: "+payload2a);

                    if (checkResult(msg, result2a)){

                        bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, null,
                                param, payload2a, "Vulnerable to SSTI (Jinja2 / Twig / Nunjucks Framework)", msg);

                    } else {

                        bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, null,
                                param, payload2, "Vulnerable to SSTI (Unknown Framework)", msg);

                    }

                } else {

                    return;

                }

            }

        } catch (Exception e) {
            log.error(e);
        }

        
    }

    private boolean checkResult(HttpMessage msg, String result) {
        // check if response OK or not.
        if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK
          && !HttpStatusCode.isServerError(msg.getResponseHeader().getStatusCode())) {
          return false;
        }

        if (msg.getResponseBody().toString().contains(result)) {
            log.info(getName()+": Found Vulnerability!!!");
            return true;
        }
        
        return false;
        
    }

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		return 917;
	}

	@Override
	public int getWascId() {
        // Not exact, but close...
		return 23;
	}

}
