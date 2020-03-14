/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


/*
 * A ZAP extension which scans for mongo db vulnerabilities.
 */
public class MongoDbVulnScanner extends AbstractAppParamPlugin {

    private static Logger log = Logger.getLogger(MongoDbVulnScanner.class);

    private static String TIMING_ATTACK = "1';var time = new Date().getTime(); while (new Date().getTime() < time + 2000);'";

    @Override
    public int getId() {
        return 11111;
    }

    @Override
    public String getName() {
        return "MongoDbVulnScanner";
    }

    @Override
    public String getDescription() {
        return "The application generates a query intended to access or manipulate data in MongoDB, but it does not neutralize or incorrectly neutralizes " +
                "special elements that can modify the intended logic of the query.";
    }

    private enum FlawType {
        AUTH, DATA, JS
    }

    @Override
    @SuppressWarnings( "deprecation" )
    public void scan(HttpMessage msg, String param, String value) {
        if (Heuristics.isParameterPassword(param)) {
            setEscapedParameter(msg, param + "[$ne]", "");
            try {
                sendAndReceive(msg, false);
                if (msg.getResponseHeader().getStatusCode() >= 200 && msg.getResponseHeader().getStatusCode() < 400) {
                    if (msg.getResponseHeader().getStatusCode() >= 300) {
                        String location = "/";
                        //get location header
                        List<HttpHeaderField> header =
                                msg.getResponseHeader().getHeaders().stream().filter(h -> h.getName().equals(HttpRequestHeader.LOCATION))
                                        .collect(Collectors.toList());
                        location = header.get(0).getValue();
                        msg.setCookies(msg.getResponseHeader().getHttpCookies());
                        msg.getRequestHeader().setMethod("GET");
                        msg.getRequestHeader().setURI(new URI(this.getParent().getHostAndPort() + location));
                        this.sendAndReceive(msg, false);
                    }
                    if (Heuristics.isUserLoggedIn(msg.getResponseBody().toString())) {
                        this.bingo(Alert.RISK_HIGH,
                                Alert.CONFIDENCE_MEDIUM,
                                "Query Selector Injection (Authentication)",
                                this.getDescription(),
                                null,
                                param,
                                param + "[$ne]",
                                this.getOtherInfo(FlawType.AUTH),
                                this.getSolution(),
                                msg);
                    }
                }
                    } catch (IOException ex) {
                        log.error("caught exception sending request ", ex);
                    }
                } else {
                    setEscapedParameter(msg, param + "[$gt]", "");
                    try {
                        sendAndReceive(msg, false);
                        if (Heuristics.isJSONValid(msg.getResponseBody().toString())) {
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    "Query Selector Injection (Data)",
                                    getDescription(),
                                    null,
                                    param, param + "[$gt]",
                                    getOtherInfo(FlawType.DATA),
                                    getSolution(),
                                    msg);
                        }
                        setParameter(msg, param , TIMING_ATTACK);
                        long start = System.currentTimeMillis();
                        sendAndReceive(msg, false);
                        long finish = System.currentTimeMillis();
                        long timeElapsed = finish - start;
                        if (timeElapsed > 2500) {
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    "Timing Attack",
                                    getDescription(),
                                    null,
                                    param, TIMING_ATTACK,
                                    getOtherInfo(FlawType.JS),
                                    getSolution(),
                                    msg);
                        }
                    } catch (IOException ex) {
                log.error("caught exception sending request ", ex);;
            }
        }
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "Please ensure that you follow one or more of the following techniques \n"+
                "1. Input validation \n"+
                "2. Parametrized queries\n"+
                "3. Use Stored procedures \n"+
                "4. Use Character Escaping \n"+
                "5. Use a Web Application Firewall";
    }

    public String getOtherInfo(FlawType flawType) {
        String info = "";
        if (flawType == FlawType.AUTH) {
            info = "Malicious users can insert the payload '$ne' to username or password fields and get unauthorized access to the system. \n " +
                    " Please sanitize the input before passing it to the database ";
        } else if (flawType == FlawType.DATA) {
            info = "Malicious users can obtain access to unaintended data by inserting the malicious payload '$gt'";
        } else if (flawType == FlawType.JS) {
            info = "Malicious users can trigger javascript in MongoDb and this can lead to unintended behaviour and even server shutdown";
        }
        return info;
    }

    @Override
    public String getReference() {
        return "https://cwe.mitre.org/data/definitions/943.html";
    }


    /**
     * http://cwe.mitre.org/data/definitions/943.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 943;
    }

    /**
     * Seems no WASC defined for this
     *
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 19;
    }

}
