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
package org.zaproxy.zap.extension.mongodb;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.json.*;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


/*
 * A ZAP extension which scans for mongo db vulnerabilities.
 */
public class MongoDbVulnScanner extends AbstractAppParamPlugin {

    private static Logger log = Logger.getLogger(MongoDbVulnScanner.class);


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
        return "The application generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.";
    }

    @Override
    @SuppressWarnings( "deprecation" )
    public void scan(HttpMessage msg, String param, String value) {
        if (Heuristics.isParameterPassword(param)) {
            setEscapedParameter(msg, param + "[$ne]", "");
            try {
                sendAndReceive(msg, false);
                if (msg.getResponseHeader().getStatusCode() >= 200 && msg.getResponseHeader().getStatusCode() < 400) {
                    String location = "/";
                    if (msg.getResponseHeader().getStatusCode() >= 300) {
                        //get location header
                        List<HttpHeaderField> header =
                                msg.getResponseHeader().getHeaders().stream().filter(h -> h.getName().equals(HttpRequestHeader.LOCATION))
                                        .collect(Collectors.toList());
                        location = header.get(0).getValue();
                    }
                    msg.setCookies(msg.getResponseHeader().getHttpCookies());
                    msg.getRequestHeader().setMethod("GET");
                    msg.getRequestHeader().setURI(new URI(this.getParent().getHostAndPort() + location));
                    this.sendAndReceive(msg, false);
                    if (Heuristics.isUserLoggedIn(msg.getResponseBody().toString())) {
                        this.bingo(Alert.RISK_HIGH,
                                Alert.CONFIDENCE_MEDIUM,
                                "Query Selector Injection (Authentication)",
                                this.getDescription(),
                                null,
                                param,
                                param + "[$ne]",
                                this.getOtherInfo(),
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
                                    getOtherInfo(),
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
        return "Cast the values to a String before running the query against the database.";
    }

    public String getOtherInfo() {
        return "Depending on the capabilities of the query language, an attacker could inject additional logic into the query to:\n" +
                "\n" +
                "Modify the intended selection criteria, thus changing which data entities (e.g., records) are returned, modified, or otherwise manipulated\n" +
                "Append additional commands to the query\n" +
                "Return more entities than intended\n" +
                "Return fewer entities than intended\n" +
                "Cause entities to be sorted in an unexpected way\n" +
                "The ability to execute additional commands or change which entities are returned has obvious risks. But when the application logic depends on the order or number of entities, this can also lead to vulnerabilities. For example, if the application query expects to return only one entity that specifies an administrative user, but an attacker can change which entities are returned, this could cause the logic to return information for a regular user and incorrectly assume that the user has administrative privileges.\n" +
                "\n" +
                "While this weakness is most commonly associated with SQL injection, there are many other query languages that are also subject to injection attacks, including HTSQL, LDAP, DQL, XQuery, Xpath, and \"NoSQL\" languages.";
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
