/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The MongoInjection plugin identifies MongoDB injection vulnerabilities
 *
 * @author l.casciaro
 */
public class MongoDbInjection extends AbstractAppParamPlugin {

    // Prefix for internationalised messages used by this rule
    private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";
    // Constants
    private static final String ALL_DATA_ATTACK = "alldata";
    private static final String CRASH_ATTACK = "crash";
    private static final String SLEEP_ATTACK = "sleep";
    private static final String JSON_ATTACK = "json";
    private static final String AUTH_BYPASS_ATTACK = "authbypass";
    private static final String ZAP_QUERYSTRING = "[$ZAP]";
    private static final String JSON_TOKEN = "$ZAP";
    // Variables
    private boolean isJsonPayload;
    private boolean doAllDataScan,
            doCrashScan,
            doTimedScan,
            doJsonScan,
            getMoreConfidence,
            doAuthBypass;
    private int SLEEP_SHORT_TIME, SLEEP_LONG_TIME;
    private static final String INSERT_SHORT_TIME = "INSERT_SHORT_TIME",
            INSERT_LONG_TIME = "INSERT_LONG_TIME";
    private static final int DELTA_TIME = 1500;
    // Packages of attack rules
    private static final String[] ALL_DATA_PARAM_INJECTION =
            new String[] {"[$ne]", "[$regex]", "[$gt]"};
    private static final String[] ALL_DATA_VALUE_INJECTION = new String[] {"", ".*", "0"};
    private static final String[] CRASH_INJECTION = new String[] {"\"", "'", "//", "});", ");"};
    private static final String[][] SLEEP_INJECTION = {
        // Attacking $where clause
        // function() { var x = md5( some_input ); return this.password == x;}
        {
            "'); sleep(" + INSERT_SHORT_TIME + "); print('",
            "'); sleep(" + INSERT_LONG_TIME + "); print('"
        },
        {
            "\"); sleep(" + INSERT_SHORT_TIME + "); print(\"",
            "\"); sleep(" + INSERT_LONG_TIME + "); print(\""
        },
        {
            "0); sleep(" + INSERT_SHORT_TIME + "); print(\"",
            "0); sleep(" + INSERT_LONG_TIME + "); print(\""
        },
        // function() { var x = this.value == some_input; return x;}
        {
            "'; sleep(" + INSERT_SHORT_TIME + "); var x='",
            "'; sleep(" + INSERT_LONG_TIME + "); var x='"
        },
        {
            "\"; sleep(" + INSERT_SHORT_TIME + "); var x=\"",
            "\"; sleep(" + INSERT_LONG_TIME + "); var x=\""
        },
        {"0; sleep(" + INSERT_SHORT_TIME + ")", "0; sleep(" + INSERT_LONG_TIME + ")"},
        // function() { return this.value == some_input }
        {
            "zap' || sleep(" + INSERT_SHORT_TIME + ") && 'zap'=='zap",
            "zap' || sleep(" + INSERT_LONG_TIME + ") && 'zap'=='zap"
        },
        {
            "zap\" || sleep(" + INSERT_SHORT_TIME + ") && \"zap\"==\"zap",
            "zap\" || sleep(" + INSERT_LONG_TIME + ") && \"zap\"==\"zap"
        },
        {"0 || sleep(" + INSERT_SHORT_TIME + ")", "0 || sleep(" + INSERT_LONG_TIME + ")"},
        // function() { return this.value == some_function(some_imput) }
        {
            "zap') || sleep(" + INSERT_SHORT_TIME + ") && hex_md5('zap",
            "zap') || sleep(" + INSERT_LONG_TIME + ") && md5('zap"
        },
        {
            "zap\") || sleep(" + INSERT_SHORT_TIME + ") && md5(\"zap",
            "zap\") || sleep(" + INSERT_LONG_TIME + ") && md5(\"zap"
        },
        {"0)  || sleep(" + INSERT_SHORT_TIME, "0) || sleep(" + INSERT_LONG_TIME},
        // Attacking mapReduce clause (only for old versions of mongodb)
        {
            "_id);}, function(inj) { sleep("
                    + INSERT_SHORT_TIME
                    + ");return 1;}, { out: 'x'}); "
                    + "db.injection.mapReduce(function() { emit(1,1",
            "_id);}, function(inj) { sleep("
                    + INSERT_LONG_TIME
                    + "); return 1;}, { out: 'x'}); "
                    + "db.injection.mapReduce(function() { emit(1,1"
        }
    };
    private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};
    // Error messages that addressing to a well-known vulnerability
    private final Pattern[] errorPatterns = {
        Pattern.compile(
                "RuntimeException: SyntaxError: unterminated string literal",
                Pattern.CASE_INSENSITIVE),
        Pattern.compile("MongoResultException", Pattern.CASE_INSENSITIVE)
    };
    // Log prints
    private static final String JSON_EX_LOG = "trying to convert the payload in json format";
    private static final String IO_EX_LOG = "trying to send an http message";
    private static final String URI_EX_LOG = "trying to get the message's Uri";
    private static final String STOP_LOG = "Stopping the scan due to a user request";
    private static final Logger LOG = Logger.getLogger(MongoDbInjection.class);

    @Override
    public int getCweId() {
        return 943;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    public int getId() {
        return 40033;
    }

    public Tech getTech() {
        // TODO change in Tech.MongoDB as soon as available
        return Tech.Db;
    }

    @Override
    public boolean targets(TechSet technologies) {
        // TODO change in Tech.MongoDB as soon as available
        return technologies.includes(Tech.Db);
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
    public String[] getDependency() {
        return new String[] {};
    }

    public String getExtraInfo(String attack) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
    }

    @Override
    public void init() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initialising MongoDB penertration tests");
        }
        if (this.getAttackStrength() == AttackStrength.LOW) {
            SLEEP_SHORT_TIME = 1000;
            SLEEP_LONG_TIME = 2000;
            doCrashScan = false;
            doAllDataScan = true;
            doTimedScan = true;
            doJsonScan = true;
            getMoreConfidence = false;
            doAuthBypass = true;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            SLEEP_SHORT_TIME = 1000;
            SLEEP_LONG_TIME = 3000;
            doCrashScan = true;
            doAllDataScan = true;
            doTimedScan = true;
            doJsonScan = true;
            getMoreConfidence = true;

            doAuthBypass = true;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            SLEEP_SHORT_TIME = 1000;
            SLEEP_LONG_TIME = 3000;
            doCrashScan = true;
            doAllDataScan = true;
            doTimedScan = true;
            doJsonScan = true;
            getMoreConfidence = true;
            doAuthBypass = true;
        }
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        // TODO add TYPE_JSON control as soon as available
        isJsonPayload = originalParam.getType() == NameValuePair.TYPE_POST_DATA;
        // & originalParam.getType() == NameValuePair.TYPE_JSON;
        super.scan(msg, originalParam);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        boolean isBingo = false;
        List<Integer> rtt = new ArrayList<>();
        HttpMessage msgInjAttack, counterProofMsg;
        String bodyInjAttack,
                bodyCounterProof,
                bodyBase = getBaseMsg().getResponseBody().toString();

        if (!inScope(getTech())) {
            return;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                    "\nScannning URL ["
                            + msg.getRequestHeader().getMethod()
                            + "] ["
                            + msg.getRequestHeader().getURI()
                            + "] on param: ["
                            + param
                            + "] with value: ["
                            + value
                            + "] for MongoDB Injection");
        }
        // injection attack to url-encoded query parameters
        if (doAllDataScan) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "\nStarting with the url-encoded query injection package of attack rules:");
            }
            int index = 0;
            for (String valueInj : ALL_DATA_VALUE_INJECTION) {
                String paramInj = param + ALL_DATA_PARAM_INJECTION[index++];
                if (isStop()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(STOP_LOG);
                    }
                    return;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("\nTrying with the value: " + paramInj + valueInj);
                }
                try {
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, paramInj, valueInj);
                    sendAndReceive(msgInjAttack, false);
                    rtt.add(msgInjAttack.getTimeElapsedMillis());
                    bodyInjAttack = msgInjAttack.getResponseBody().toString();
                    if (msgInjAttack.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        // Get more confidence
                        if (getMoreConfidence) {
                            counterProofMsg = getNewMsg();
                            setParameter(counterProofMsg, param + ZAP_QUERYSTRING, valueInj);
                            sendAndReceive(counterProofMsg, false);
                            bodyCounterProof = counterProofMsg.getResponseBody().toString();
                            if (bodyBase.equals(bodyCounterProof)) {
                                bingo(
                                        Alert.RISK_HIGH,
                                        Alert.CONFIDENCE_HIGH,
                                        getName(),
                                        getDescription(),
                                        null,
                                        param,
                                        paramInj + valueInj,
                                        getExtraInfo(ALL_DATA_ATTACK),
                                        getSolution(),
                                        msgInjAttack);
                                isBingo = true;
                                break;
                            }
                        } else {
                            bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    getName(),
                                    getDescription(),
                                    null,
                                    param,
                                    paramInj + valueInj,
                                    getExtraInfo(ALL_DATA_ATTACK),
                                    getSolution(),
                                    msgInjAttack);
                            isBingo = true;
                            break;
                        }
                    }
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + URI_EX_LOG);
                    }
                    return;
                }
            }
        }
        // search for not-handled errors
        if (doCrashScan) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "\nStarting with the not-handled error injection package of attack rules:");
            }
            Pattern[] filteredPattern = new Pattern[errorPatterns.length];
            int i = 0;
            for (Pattern pattern : errorPatterns) {
                Matcher matcher = pattern.matcher(msg.getResponseBody().toString());
                if (!matcher.find()) {
                    filteredPattern[i++] = pattern;
                }
            }
            for (String valueInj : CRASH_INJECTION) {
                if (isStop()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(STOP_LOG);
                    }
                    return;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("\nTrying with the value: " + valueInj);
                }
                try {
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, param, valueInj);
                    sendAndReceive(msgInjAttack, false);
                    rtt.add(msgInjAttack.getTimeElapsedMillis());
                    for (Pattern pattern : filteredPattern) {
                        Matcher matcher =
                                pattern.matcher(msgInjAttack.getResponseBody().toString());
                        if (matcher.find()) {
                            bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    getName(),
                                    getDescription(),
                                    null,
                                    param,
                                    valueInj,
                                    getExtraInfo(CRASH_ATTACK),
                                    getSolution(),
                                    msgInjAttack);
                            isBingo = true;
                            break;
                        }
                    }
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + URI_EX_LOG);
                    }
                    return;
                }
            }
        }
        // injection attack to $Where and $mapReduce cluases
        // The $where clause executes associated js function one time for each tuple --> sleep time
        // = interval * nTuples
        if (doTimedScan) {
            if (isStop()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(STOP_LOG);
                }
                return;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("\nStarting with the javascript code injection package of attack rules:");
            }
            int aveRtt = getAveRtts(rtt),
                    index = 0,
                    timeShort = SLEEP_SHORT_TIME,
                    timeLong = SLEEP_LONG_TIME;
            String phase = null;
            boolean hadTimeout = false;
            String sleepValueToInj;
            while (index < SLEEP_INJECTION.length) {
                if (isStop()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(STOP_LOG);
                    }
                    return;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("\nTrying  with the value: " + SLEEP_INJECTION[index][0]);
                }
                try {
                    msgInjAttack = getNewMsg();
                    sleepValueToInj =
                            SLEEP_INJECTION[index][0].replaceFirst(
                                    INSERT_SHORT_TIME, Integer.toString(timeShort));
                    phase = INSERT_SHORT_TIME;
                    setParameter(msgInjAttack, param, sleepValueToInj);
                    sendAndReceive(msgInjAttack, false);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "\nTrying for a longer time with the value: "
                                        + SLEEP_INJECTION[index][1]);
                    }
                    if (msgInjAttack.getTimeElapsedMillis() >= aveRtt + DELTA_TIME) {
                        phase = INSERT_LONG_TIME;
                        sleepValueToInj =
                                SLEEP_INJECTION[index][1].replaceFirst(
                                        INSERT_LONG_TIME, Integer.toString(timeLong));
                        msgInjAttack = getNewMsg();
                        setParameter(msgInjAttack, param, sleepValueToInj);
                        sendAndReceive(msgInjAttack, false);
                        if (msgInjAttack.getTimeElapsedMillis() >= aveRtt + DELTA_TIME) {
                            bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_HIGH,
                                    getName(),
                                    getDescription(),
                                    null,
                                    param,
                                    SLEEP_INJECTION[index][1],
                                    getExtraInfo(SLEEP_ATTACK),
                                    getSolution(),
                                    msgInjAttack);
                            break;
                        }
                    }
                    if (hadTimeout) {
                        bingo(
                                Alert.RISK_HIGH,
                                Alert.CONFIDENCE_LOW,
                                getName(),
                                getDescription(),
                                null,
                                param,
                                SLEEP_INJECTION[index][1],
                                getExtraInfo(SLEEP_ATTACK),
                                getSolution(),
                                msgInjAttack);
                        break;
                    }
                    index++;
                } catch (SocketTimeoutException ex) {
                    hadTimeout = true;
                    if (phase == INSERT_LONG_TIME) {
                        // Timeout: 40s --> 14 <= n. tuples < 40
                        timeShort /= 3;
                        timeLong /= 3;
                    } else {
                        // n. tuples >= 40
                        timeShort /= 10;
                        timeLong /= 10;
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + IO_EX_LOG
                                        + "due to a socket timeout, trying with the lowest interval("
                                        + timeLong
                                        + ")");
                    }
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + IO_EX_LOG);
                    }
                    return;
                }
            }
        }
        // json query injection
        if (doJsonScan && isJsonPayload) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("\nStarting with the json query injection package of attack rules:");
            }
            for (String[] jpv : JSON_INJECTION) {
                try {
                    if (isStop()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(STOP_LOG);
                        }
                        return;
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("\nTrying with the value: " + jpv[0]);
                    }
                    String valueInj = getParamJsonString(param, jpv);
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, param, valueInj);
                    sendAndReceive(msgInjAttack);
                    bodyInjAttack = msgInjAttack.getResponseBody().toString();
                    if (msgInjAttack.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        // Get more confidence
                        if (getMoreConfidence) {
                            String secondVal =
                                    getParamJsonString(param, new String[] {JSON_TOKEN, jpv[1]});
                            counterProofMsg = getNewMsg();
                            counterProofMsg
                                    .getRequestHeader()
                                    .setHeader(HttpRequestHeader.CONTENT_TYPE, "application/json");
                            counterProofMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
                            setParameter(counterProofMsg, param, secondVal);
                            sendAndReceive(counterProofMsg, false);
                            bodyCounterProof = counterProofMsg.getResponseBody().toString();
                            if (bodyBase.equals(bodyCounterProof)) {
                                bingo(
                                        Alert.RISK_HIGH,
                                        Alert.CONFIDENCE_HIGH,
                                        getName(),
                                        getDescription(),
                                        null,
                                        param,
                                        jpv[0] + jpv[1],
                                        getExtraInfo(JSON_ATTACK),
                                        getSolution(),
                                        msgInjAttack);
                                isBingo = true;
                                break;
                            }
                        } else {
                            bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    getName(),
                                    getDescription(),
                                    null,
                                    param,
                                    jpv[0] + jpv[1],
                                    getExtraInfo(JSON_ATTACK),
                                    getSolution(),
                                    msgInjAttack);
                            isBingo = true;
                            break;
                        }
                    }
                } catch (JSONException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + JSON_EX_LOG);
                    }
                    return;
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + URI_EX_LOG);
                    }
                    return;
                }
            }
        }
        // check for the authentication page bypass
        if (doAuthBypass && isBingo) {
            if (isStop()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(STOP_LOG);
                }
                return;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "\nA vulnerability has been reported, check if it concerns an authentication page");
            }
            ExtensionAuthentication extAuth =
                    (ExtensionAuthentication)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionAuthentication.NAME);
            if (extAuth != null) {
                URI requestUri = getBaseMsg().getRequestHeader().getURI();
                try {
                    List<Context> contextList =
                            extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());
                    for (Context context : contextList) {
                        URI loginUri = extAuth.getLoginRequestURIForContext(context);
                        if (loginUri != null) {
                            if (requestUri.getScheme().equals(loginUri.getScheme())
                                    && requestUri.getHost().equals(loginUri.getHost())
                                    && requestUri.getPort() == loginUri.getPort()
                                    && requestUri.getPath().equals(loginUri.getPath())) {
                                bingo(
                                        Alert.RISK_HIGH,
                                        Alert.CONFIDENCE_MEDIUM,
                                        getName(),
                                        getDescription(),
                                        null,
                                        param,
                                        "",
                                        getExtraInfo(AUTH_BYPASS_ATTACK),
                                        getSolution(),
                                        getBaseMsg());
                                break;
                            }
                        }
                    }
                } catch (URIException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when "
                                        + URI_EX_LOG);
                    }
                }
            }
        }
    }

    private int getAveRtts(List<Integer> rtt) {
        double sum = 0;
        for (Integer i : rtt) {
            sum += i;
        }
        return (int) sum / rtt.size();
    }

    private String getParamJsonString(String param, String[] params) throws JSONException {
        JSONObject internal = new JSONObject(), external = new JSONObject();
        internal.put(params[0], params[1]);
        external.put(param, internal);
        return external.toString();
    }
}
