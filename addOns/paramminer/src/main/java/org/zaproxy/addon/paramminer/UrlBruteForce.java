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
package org.zaproxy.addon.paramminer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.addon.paramminer.UrlGuesser.Method;
import org.zaproxy.addon.paramminer.UrlGuesser.Mode;
import org.zaproxy.addon.paramminer.UrlGuesser.Status;
import org.zaproxy.addon.paramminer.gui.ParamMinerHistoryTableModel;

public class UrlBruteForce implements Callable<ParamReasons> {
    private ComparableResponse base;
    private Method method;
    private Map<String, String> params;
    private Mode mode;
    private UrlGuesser guesser;
    private GuesserScan scan;
    private ParamMinerConfig config;
    private HttpSender httpSender;
    private boolean firstComparison;
    private ArrayList<String> paramsPresent;
    private List<String> wordlist;
    private List<ParamGuessResult> guessedParams;
    private List<Integer> ERRORCODES = Arrays.asList(400, 413, 418, 429, 503);
    private String baseValue;
    private static final Logger logger = LogManager.getLogger(UrlBruteForce.class);

    public UrlBruteForce(
            ComparableResponse base,
            String baseValue,
            Method method,
            Map<String, String> params,
            Mode mode,
            GuesserScan scan,
            UrlGuesser guesser,
            HttpSender sender,
            List<String> wordlist,
            List<ParamGuessResult> guessedParams) {
        /** For Mode.VERIFY, guessedParams cannot be null */
        this.base = base;
        this.baseValue = baseValue;
        this.method = method;
        this.params = params;
        this.mode = mode;
        this.guesser = guesser;
        this.httpSender = sender;
        this.wordlist = wordlist;
        this.scan = scan;
        this.guessedParams = guessedParams;
        config = scan.getConfig();
    }

    @Override
    public ParamReasons call() throws Exception {
        HttpMessage msg = new HttpMessage();
        String valueSent = requester(msg, method, params);
        ComparableResponse response = new ComparableResponse(msg, valueSent);
        Status status = errorHandler(base, response);
        if (status.equals(Status.KILL)) {
            return null;
        }
        ParamReasons res = compare(base, response, params);
        if (mode == Mode.VERIFY) {
            if (res != null) {
                for (String parameter : res.getParams().keySet()) {
                    ParamGuessResult paramGuessResult =
                            new ParamGuessResult(parameter, res.getReason(), msg);
                    guessedParams.add(paramGuessResult);
                }
            }
        }
        return res;
    }

    /**
     * Checks ths status codes of the response for succesful requests.
     *
     * @param base the base response
     * @param response the response to check
     * @return Status.OK if the response is valid, false otherwise.
     */
    public Status errorHandler(ComparableResponse base, ComparableResponse response) {
        int status = response.getStatusCode();
        if (ERRORCODES.contains(status)) {
            if (status == 503) {
                // TODO Display on out panel "Taget unable to process requests"
                return Status.KILL;
            } else if (status == 429 || status == 418) {
                // TODO Display on out panel "Target is rate limited"
                return Status.KILL;
            } else {
                if (base.getStatusCode() != response.getStatusCode()) {
                    return Status.KILL;
                } else {
                    return Status.OK;
                }
            }
        } else if (response.getBody().isEmpty() || response.getHeaders().size() == 0) {
            return Status.KILL;
        }
        return Status.OK;
    }

    public String requester(HttpMessage msg, Method method, Map<String, String> params) {
        ParamMinerHistoryTableModel table;
        if (method.equals(Method.GET)) {
            try {
                table = scan.getTableModel();
                // TODO Add right options so that http message can be loaded using right click menu.
                String uri = config.getUrl();
                String queryString = UrlUtils.createQueryString(params);
                HttpRequestHeader headers = new HttpRequestHeader(uri);
                headers.setMethod(HttpRequestHeader.GET);
                headers.setURI(new URI(uri + queryString, true));
                for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                    headers.setHeader(header.getName(), header.getValue());
                }
                msg.setRequestHeader(headers);
                httpSender.sendAndReceive(msg);
                table.addHistoryReference(
                        new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                return StringUtils.strip(queryString, "?");
            } catch (Exception e) {
                // TODO show proper error message on Output Panel (can be timeout or connection
                // refused)
                logger.debug(e);
            }
        } else if (method.equals(Method.XML)) {
            try {
                table = scan.getTableModel();
                // TODO Add right options so that http message can be loaded using right click menu.
                String uri = config.getUrl();
                HttpRequestHeader headers = new HttpRequestHeader(uri);
                headers.setMethod(HttpRequestHeader.POST);
                headers.setURI(new URI(uri, true));
                headers.setHeader(HttpHeader.CONTENT_TYPE, "application/xml");
                for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                    headers.setHeader(header.getName(), header.getValue());
                }
                String xmlPayload =
                        config.getUrlXmlIncludeString()
                                .replace("$ZAP$", UrlUtils.createXmlString(params));
                msg.setRequestHeader(headers);
                msg.setRequestBody(xmlPayload);
                httpSender.sendAndReceive(msg);
                table.addHistoryReference(
                        new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                return xmlPayload;
            } catch (Exception e) {
                // TODO show proper error message on Output Panel
                logger.debug(e);
            }
        } else if (method.equals(Method.JSON)) {
            try {
                table = scan.getTableModel();
                // TODO Add right options so that http message can be loaded using right click menu.
                String uri = config.getUrl();
                HttpRequestHeader headers = new HttpRequestHeader(uri);
                headers.setMethod(HttpRequestHeader.POST);
                headers.setURI(new URI(uri, true));
                headers.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
                for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                    headers.setHeader(header.getName(), header.getValue());
                }
                String jsonPayload;
                if (!config.getUrlXmlIncludeString().isEmpty()) {
                    jsonPayload =
                            config.getUrlJsonIncludeString()
                                    .replace(
                                            "$ZAP$",
                                            StringUtils.strip(
                                                    StringUtils.strip(
                                                            UrlUtils.createJsonString(params), "{"),
                                                    "}"));
                } else {
                    jsonPayload = UrlUtils.createJsonString(params);
                }
                msg.setRequestHeader(headers);
                msg.setRequestBody(jsonPayload);
                httpSender.sendAndReceive(msg);
                table.addHistoryReference(
                        new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                return jsonPayload;
            } catch (Exception e) {
                // TODO show proper error message on Output Panel
                logger.debug(e);
            }
        } else if (method.equals(Method.POST)) {
            try {
                // TODO Add right options so that http message can be loaded using right click menu.
                String uri = config.getUrl();
                HttpRequestHeader headers = new HttpRequestHeader(uri);
                headers.setMethod(HttpRequestHeader.POST);
                headers.setURI(new URI(uri, true));
                for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                    headers.setHeader(header.getName(), header.getValue());
                }
                String postPayload = StringUtils.strip(UrlUtils.createQueryString(params), "?");
                msg.setRequestHeader(headers);
                msg.setRequestBody(postPayload);
                httpSender.sendAndReceive(msg);
                return postPayload;
            } catch (Exception e) {
                // TODO show proper error message on Output Panel
                logger.debug(e);
            }
        }
        return null;
    }

    /**
     * Comapres two responses and finds if a paramter is vulnerable or not.
     *
     * @param resp1 the base response which determines the factors.
     * @param resp2 the response to compare. this gnereally has the payload in request.
     * @return a ParamReasons object which contains the reasons for the choice and the map of
     *     params.
     */
    public ParamReasons compare(
            ComparableResponse resp1, ComparableResponse resp2, Map<String, String> params) {
        if (resp1.getStatusCode() != resp2.getStatusCode()
                || ComparableResponse.statusCodeHeuristic(resp1, resp2) < 1) {
            return new ParamReasons("http code", params);
        }

        if (ComparableResponse.headersCompareHeuristic(resp1, resp2) < 1) {
            return new ParamReasons("http headers", params);
        }

        if (resp1.getHeaders().get("Location") != resp2.getHeaders().get("Location")) {
            return new ParamReasons("redirect", params);
        }

        if (ComparableResponse.bodyTreesStructureHeuristic(resp1, resp2) < 1) {
            return new ParamReasons("body heuristic mismatch", params);
        }

        if (ComparableResponse.lineCountHeuristic(resp1, resp2) < 1) {
            return new ParamReasons("line count mismatch", params);
        }

        if (ComparableResponse.wordCountHeuristic(resp1, resp2) < 1) {
            return new ParamReasons("word count mismatch", params);
        }

        // TODO Use Jericho source for plaintext comparison.
        if (!resp1.getBody().equals(resp2.getBody())) {
            return new ParamReasons("text mismatch", params);
        }

        if (!resp1.getBody().contains(resp1.getValueSent())) {
            if (this.firstComparison) {
                this.firstComparison = false;
                this.paramsPresent = new ArrayList<String>();
                for (String param : wordlist) {
                    if (resp1.getBody().contains(param)) {
                        this.paramsPresent.add(param);
                    }
                }
            }
            if (paramsPresent.size() > 0) {
                for (String param : params.keySet()) {
                    if (param.length() < 5) {
                        continue;
                    }
                    if (!paramsPresent.contains(param)) {
                        Pattern searchParamPattern =
                                Pattern.compile("['\"\\s]" + param + "['\"\\s]");
                        if (searchParamPattern.matcher(resp2.getBody()).find()) {
                            return new ParamReasons("parameter name reflection", params);
                        }
                    }
                }
            }
        }

        if (!resp1.getBody().contains(baseValue)) {
            for (String values : params.values()) {
                if (resp2.getBody().contains(values)) {
                    Pattern searchValuePattern = Pattern.compile("['\"\\s]" + values + "['\"\\s]");
                    if (searchValuePattern.matcher(resp2.getBody()).find()) {
                        return new ParamReasons("parameter value reflection", params);
                    }
                }
            }
        }

        return null;
    }
}
