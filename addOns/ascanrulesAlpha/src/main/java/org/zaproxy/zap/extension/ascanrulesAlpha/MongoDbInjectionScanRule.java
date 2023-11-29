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
import java.net.SocketException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The MongoInjection scan rule identifies MongoDB injection vulnerabilities
 *
 * @author l.casciaro
 */
public class MongoDbInjectionScanRule extends AbstractAppParamPlugin {

    // Prefix for internationalised messages used by this rule
    private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";
    // Constants
    private static final String RULE_SLEEP_TIME = RuleConfigParam.RULE_COMMON_SLEEP_TIME;
    private static final String ALL_DATA_ATTACK = "alldata";
    private static final String CRASH_ATTACK = "crash";
    private static final String SLEEP_ATTACK = "sleep";
    private static final String JSON_ATTACK = "json";
    private static final String AUTH_BYPASS_ATTACK = "authbypass";
    private static final String JSON_TOKEN = "$ZAP";
    private static final int BLIND_REQUEST_LIMIT = 4;
    private static final int DEFAULT_TIME_SLEEP_SEC = 5;
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;
    // Packages of attack rules
    private static final String[] ALL_DATA_PARAM_INJECTION =
            new String[] {"[$ne]", "[$regex]", "[$gt]", "[$eq]"};
    private static final String[] ALL_DATA_VALUE_INJECTION = new String[] {"", ".*", "0", ""};
    private static final String[] CRASH_INJECTION = new String[] {"\"", "'", "//", "});", ");"};
    private static final String[] SLEEP_INJECTION = {
        // Attacking $where clause
        // function() { var x = md5( some_input ); return this.password == x;}
        "\"); sleep({0}); print(\"",
        "'; sleep({0}); print(\'",
        "0); sleep({0}); print(\"",
        // function() { var x = this.value == some_input; return x;}
        "'; sleep({0}); var x='",
        "\"; sleep({0}); var x=\"",
        "0; sleep({0})",
        // function() { return this.value == some_input }
        "zap' || sleep({0}) && 'zap'=='zap",
        "zap\" || sleep({0}) && \"zap\"==\"zap",
        "0 || sleep({0})",
        // function() { return this.value == some_function(some_imput) }
        "zap') || sleep({0}) && hex_md5('zap",
        "zap\") || sleep({0}) && md5(\"zap",
        "0)  || sleep({0})",
        // Attacking mapReduce clause (only for old versions of mongodb)
        "_id);}, function(inj) { sleep({0});return 1;}, { out: 'x'}); db.injection.mapReduce(function() { emit(1,1"
    };
    private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};
    // Log prints
    private static final String JSON_EX_LOG = "trying to convert the payload in json format";
    private static final String URI_EX_LOG = "trying to get the message's Uri";
    private static final String STOP_LOG = "Stopping the scan due to a user request";
    private static final Logger LOGGER = LogManager.getLogger(MongoDbInjectionScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);
    private int timeSleepSeconds;
    // Error messages that addressing to a well-known vulnerability
    private final Pattern[] errorPatterns = {
        Pattern.compile(
                "RuntimeException: SyntaxError: unterminated string literal",
                Pattern.CASE_INSENSITIVE),
        Pattern.compile("MongoResultException", Pattern.CASE_INSENSITIVE)
    };
    // Variables
    private boolean isJsonPayload;
    private boolean doAllDataScan;
    private boolean doCrashScan;
    private boolean doTimedScan;
    private boolean doJsonScan;
    private boolean getMoreConfidence;
    private boolean doAuthBypass;

    @Override
    public int getCweId() {
        return 943;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public int getId() {
        return 40033;
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MongoDB);
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
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

    public String getExtraInfo(String attack) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void init() {
        try {
            timeSleepSeconds = this.getConfig().getInt(RULE_SLEEP_TIME, DEFAULT_TIME_SLEEP_SEC);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_SLEEP_TIME,
                    this.getConfig().getString(RULE_SLEEP_TIME));
        }
        LOGGER.debug("Initialising MongoDB penetration tests");
        switch (this.getAttackStrength()) {
            case LOW:
                doCrashScan = false;
                doAllDataScan = true;
                doTimedScan = true;
                doJsonScan = true;
                getMoreConfidence = false;
                doAuthBypass = true;
                break;
            default:
                doCrashScan = true;
                doAllDataScan = true;
                doTimedScan = true;
                doJsonScan = true;
                getMoreConfidence = true;
                doAuthBypass = true;
                break;
        }
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        isJsonPayload = originalParam.getType() == NameValuePair.TYPE_JSON;
        super.scan(msg, originalParam);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        boolean isBingo = false;
        HttpMessage msgInjAttack;
        HttpMessage counterProofMsg;
        String bodyBase = getBaseMsg().getResponseBody().toString();

        LOGGER.debug(
                "Scanning URL [{}] [{}] on param: [{}] with value: [{}] for MongoDB Injection",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                param,
                value);
        // injection attack to url-encoded query parameters
        if (doAllDataScan && !isJsonPayload) {
            LOGGER.debug("Starting with boolean based attack payloads:");
            int index = 0;
            for (String valueInj : ALL_DATA_VALUE_INJECTION) {
                String paramInj = param + ALL_DATA_PARAM_INJECTION[index++];
                if (isStop()) {
                    LOGGER.debug(STOP_LOG);
                    return;
                }

                LOGGER.debug("Trying with the value: {} {}", paramInj, valueInj);
                try {
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, paramInj, valueInj);
                    sendAndReceive(msgInjAttack, false);
                    String bodyInjAttack = msgInjAttack.getResponseBody().toString();
                    if (msgInjAttack.getResponseHeader().getStatusCode()
                            != getBaseMsg().getResponseHeader().getStatusCode()) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        counterProofMsg = getNewMsg();
                        setParameter(counterProofMsg, param + "[$eq]", value);
                        sendAndReceive(counterProofMsg, false);
                        String bodyCounterProof = counterProofMsg.getResponseBody().toString();
                        if (bodyBase.equals(bodyCounterProof)) {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_HIGH)
                                    .setParam(param)
                                    .setAttack(paramInj + valueInj)
                                    .setOtherInfo(getExtraInfo(ALL_DATA_ATTACK))
                                    .setMessage(msgInjAttack)
                                    .raise();
                            isBingo = true;
                            break;
                        }
                    }
                } catch (IOException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            URI_EX_LOG);
                    return;
                }
            }
        }
        // search for not-handled errors
        if (!isBingo && doCrashScan) {
            LOGGER.debug("Starting with the not-handled error injection payloads:");
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
                    LOGGER.debug(STOP_LOG);
                    return;
                }
                LOGGER.debug("Trying with the value: {}", valueInj);
                try {
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, param, valueInj);
                    sendAndReceive(msgInjAttack, false);
                    for (Pattern pattern : filteredPattern) {
                        Matcher matcher =
                                pattern.matcher(msgInjAttack.getResponseBody().toString());
                        if (matcher.find()) {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(valueInj)
                                    .setOtherInfo(getExtraInfo(CRASH_ATTACK))
                                    .setMessage(msgInjAttack)
                                    .raise();
                            isBingo = true;
                            break;
                        }
                    }
                } catch (IOException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            URI_EX_LOG);
                    return;
                }
            }
        }
        // injection attack to $Where and $mapReduce clauses
        // The $where clause executes associated JS function one time for each tuple --> sleep time
        // = interval * nTuples
        if (!isBingo && doTimedScan) {
            if (isStop()) {
                LOGGER.debug(STOP_LOG);
                return;
            }
            LOGGER.debug("Starting with the javascript code injection payloads:");
            int index = 0;
            while (index < SLEEP_INJECTION.length) {
                if (isStop()) {
                    LOGGER.debug(STOP_LOG);
                    return;
                }
                String sleepPayload = SLEEP_INJECTION[index];
                AtomicReference<HttpMessage> message = new AtomicReference<>();
                String paramValue = sleepPayload.replace("{0}", String.valueOf(timeSleepSeconds));
                LOGGER.debug("Trying with the value: {}", sleepPayload);

                TimingUtils.RequestSender requestSender =
                        x -> {
                            HttpMessage timedMsg = getNewMsg();
                            message.set(timedMsg);
                            String finalPayload =
                                    value + sleepPayload.replace("{0}", String.valueOf(x));
                            setParameter(timedMsg, param, finalPayload);
                            LOGGER.debug("Testing [{}] = [{}]", param, finalPayload);

                            // send the request and retrieve the response
                            sendAndReceive(timedMsg, false);
                            return TimeUnit.MILLISECONDS.toSeconds(timedMsg.getTimeElapsedMillis());
                        };

                boolean isInjectable;
                try {
                    try {
                        // use TimingUtils to detect a response to sleep payloads
                        isInjectable =
                                TimingUtils.checkTimingDependence(
                                        BLIND_REQUEST_LIMIT,
                                        timeSleepSeconds,
                                        requestSender,
                                        TIME_CORRELATION_ERROR_RANGE,
                                        TIME_SLOPE_ERROR_RANGE);
                    } catch (SocketException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                message.get().getRequestHeader().getURI());
                        continue; // Something went wrong, move to next blind iteration
                    }

                    if (isInjectable) {
                        // We Found IT!
                        LOGGER.debug(
                                "[NOSQL Injection Found] on parameter [{}] with value [{}]",
                                param,
                                paramValue);

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(paramValue)
                                // just attach this alert to the last sent message
                                .setMessage(message.get())
                                .setOtherInfo(getExtraInfo(SLEEP_ATTACK))
                                .raise();
                        isBingo = true;
                        break;
                    }
                } catch (IOException ex) {
                    LOGGER.warn(
                            "Mongo DB Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                            param,
                            paramValue,
                            ex);
                }
                index++;
            }
        }
        // json query injection
        if (!isBingo && doJsonScan && isJsonPayload) {
            LOGGER.debug("Starting with the json injection payloads:");
            for (String[] jpv : JSON_INJECTION) {
                try {
                    if (isStop()) {
                        LOGGER.debug(STOP_LOG);
                        return;
                    }
                    LOGGER.debug("Trying with the value: {}", jpv[0]);
                    String valueInj = getParamJsonString(param, jpv);
                    msgInjAttack = getNewMsg();
                    setParameter(msgInjAttack, param, valueInj);
                    sendAndReceive(msgInjAttack);
                    String bodyInjAttack = msgInjAttack.getResponseBody().toString();
                    if (msgInjAttack.getResponseHeader().getStatusCode()
                            != getBaseMsg().getResponseHeader().getStatusCode()) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        // Get more confidence
                        if (getMoreConfidence) {
                            String secondVal =
                                    getParamJsonString(param, new String[] {JSON_TOKEN, jpv[1]});
                            counterProofMsg = getNewMsg();
                            setParameter(counterProofMsg, param, secondVal);
                            sendAndReceive(counterProofMsg, false);
                            String bodyCounterProof = counterProofMsg.getResponseBody().toString();
                            if (bodyBase.equals(bodyCounterProof)) {
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_HIGH)
                                        .setParam(param)
                                        .setAttack(jpv[0] + jpv[1])
                                        .setOtherInfo(getExtraInfo(JSON_ATTACK))
                                        .setMessage(msgInjAttack)
                                        .raise();
                                isBingo = true;
                                break;
                            }
                        } else {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(jpv[0] + jpv[1])
                                    .setOtherInfo(getExtraInfo(JSON_ATTACK))
                                    .setMessage(msgInjAttack)
                                    .raise();
                            isBingo = true;
                            break;
                        }
                    }
                } catch (JSONException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            JSON_EX_LOG);
                    return;
                } catch (IOException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            URI_EX_LOG);
                    return;
                }
            }
        }
        // check for the authentication page bypass
        if (doAuthBypass && isBingo) {
            if (isStop()) {
                LOGGER.debug(STOP_LOG);
                return;
            }
            LOGGER.debug(
                    "A vulnerability has been reported, check if it concerns an authentication page");
            ExtensionAuthentication extAuth =
                    (ExtensionAuthentication)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionAuthentication.NAME);
            if (extAuth != null) {
                URI requestUri = getBaseMsg().getRequestHeader().getURI();
                try {
                    List<Context> contextList =
                            extAuth.getModel()
                                    .getSession()
                                    .getContextsForUrl(requestUri.toString());
                    for (Context context : contextList) {
                        URI loginUri = extAuth.getLoginRequestURIForContext(context);
                        if (loginUri != null) {
                            if (requestUri.getScheme().equals(loginUri.getScheme())
                                    && requestUri.getHost().equals(loginUri.getHost())
                                    && requestUri.getPort() == loginUri.getPort()
                                    && requestUri.getPath().equals(loginUri.getPath())) {
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setOtherInfo(getExtraInfo(AUTH_BYPASS_ATTACK))
                                        .setMessage(getBaseMsg())
                                        .raise();
                                break;
                            }
                        }
                    }
                } catch (URIException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            URI_EX_LOG);
                }
            }
        }
    }

    private static String getParamJsonString(String param, String[] params) throws JSONException {
        JSONObject internal = new JSONObject(), external = new JSONObject();
        internal.put(params[0], params[1]);
        external.put(param, internal);
        return external.toString();
    }
}
