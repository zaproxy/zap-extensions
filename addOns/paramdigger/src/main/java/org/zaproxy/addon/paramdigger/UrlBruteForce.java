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
package org.zaproxy.addon.paramdigger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
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
import org.zaproxy.addon.paramdigger.ParamGuessResult.Reason;
import org.zaproxy.addon.paramdigger.UrlGuesser.Mode;
import org.zaproxy.addon.paramdigger.UrlGuesser.Status;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.utils.ThreadUtils;

public class UrlBruteForce implements Callable<ParamReasons> {
    private ComparableResponse base;
    private Method method;
    private Map<String, String> params;
    private Mode mode;
    private UrlGuesser guesser;
    private GuesserScan scan;
    private ParamDiggerConfig config;
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
        this.firstComparison = true;
    }

    @Override
    public ParamReasons call() throws Exception {
        HttpMessage msg = new HttpMessage();
        String valueSent = requester(msg, method, params);
        if (valueSent == null) {
            return null;
        }
        ComparableResponse response = new ComparableResponse(msg, valueSent);
        Status status = errorHandler(base, response);

        if (status.equals(Status.KILL)) {
            return null;
        }

        ParamReasons res = compare(base, response, params);
        if (mode == Mode.VERIFY && !res.isEmpty()) {
            for (String parameter : res.getParams().keySet()) {
                ParamGuessResult paramGuessResult =
                        new ParamGuessResult(parameter, res.getReasons(), msg);
                guessedParams.add(paramGuessResult);
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
            }

            if (status == 429 || status == 418) {
                // TODO Display on out panel "Target is rate limited"
                return Status.KILL;
            }
            if (ERRORCODES.contains(base.getStatusCode())) {
                return Status.KILL;
            }

            if (base.getStatusCode() != response.getStatusCode()) {
                return Status.KILL;
            }
        }

        if (response.getBody().isEmpty() || response.getHeaders().isEmpty()) {
            return Status.KILL;
        }
        return Status.OK;
    }

    /**
     * Makes Requests to target for a given msg, method and params.
     *
     * @param msg the HttpMessage to store the response in.
     * @param method the method to use.
     * @param params the params to use.
     * @return the value sent. This is the payload created by using the params.
     */
    public String requester(HttpMessage msg, Method method, Map<String, String> params) {
        ParamDiggerHistoryTableModel table;
        switch (method) {
            case GET:
                try {
                    table = scan.getTableModel();
                    String uri = config.getUrl();
                    String queryString = Utils.createQueryString(params);
                    HttpRequestHeader headers = new HttpRequestHeader();
                    if (uri.contains("?")) {
                        uri = uri.substring(0, uri.indexOf("?"));
                    }
                    headers.setMethod(HttpRequestHeader.GET);
                    headers.setURI(new URI(uri + queryString, true));
                    headers.setVersion(HttpHeader.HTTP11);
                    for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                        headers.setHeader(header.getName(), header.getValue());
                    }
                    msg.setRequestHeader(headers);
                    httpSender.sendAndReceive(msg);
                    ThreadUtils.invokeAndWaitHandled(
                            () -> {
                                try {
                                    table.addHistoryReference(
                                            new HistoryReference(
                                                    Model.getSingleton().getSession(), 23, msg));
                                } catch (Exception e) {
                                    logger.error(e, e);
                                }
                            });
                    return StringUtils.strip(queryString, "?");
                } catch (Exception e) {
                    // TODO show proper error message on Output Panel (can be timeout or connection
                    // refused)
                    logger.error(e, e);
                }
                break;

            case XML:
                try {
                    table = scan.getTableModel();
                    String uri = config.getUrl();
                    if (uri.contains("?")) {
                        uri = uri.substring(0, uri.indexOf("?"));
                    }
                    HttpRequestHeader headers = new HttpRequestHeader();
                    headers.setMethod(HttpRequestHeader.POST);
                    headers.setURI(new URI(uri, true));
                    headers.setVersion(HttpHeader.HTTP11);
                    headers.setHeader(HttpHeader.CONTENT_TYPE, "application/xml");
                    for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                        headers.setHeader(header.getName(), header.getValue());
                    }
                    String xmlPayload =
                            config.getUrlXmlIncludeString()
                                    .replace("$ZAP$", Utils.createXmlString(params));
                    msg.setRequestHeader(headers);
                    msg.setRequestBody(xmlPayload);
                    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                    httpSender.sendAndReceive(msg);
                    table.addHistoryReference(
                            new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                    return xmlPayload;
                } catch (Exception e) {
                    // TODO show proper error message on Output Panel
                    logger.error(e, e);
                }
                break;

            case JSON:
                try {
                    table = scan.getTableModel();
                    String uri = config.getUrl();
                    if (uri.contains("?")) {
                        uri = uri.substring(0, uri.indexOf("?"));
                    }
                    HttpRequestHeader headers = new HttpRequestHeader();
                    headers.setMethod(HttpRequestHeader.POST);
                    headers.setURI(new URI(uri, true));
                    headers.setVersion(HttpHeader.HTTP11);
                    headers.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
                    for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                        headers.setHeader(header.getName(), header.getValue());
                    }
                    String jsonPayload;
                    if (config.getUrlJsonIncludeString() != null
                            && !config.getUrlJsonIncludeString().isEmpty()) {
                        jsonPayload =
                                config.getUrlJsonIncludeString()
                                        .replace(
                                                "$ZAP$",
                                                StringUtils.strip(
                                                        StringUtils.strip(
                                                                Utils.createJsonString(params),
                                                                "{"),
                                                        "}"));
                    } else {
                        jsonPayload = Utils.createJsonString(params);
                    }
                    msg.setRequestHeader(headers);
                    msg.setRequestBody(jsonPayload);
                    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                    httpSender.sendAndReceive(msg);
                    table.addHistoryReference(
                            new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                    return jsonPayload;
                } catch (Exception e) {
                    // TODO show proper error message on Output Panel
                    logger.error(e, e);
                }
                break;

            case POST:
                try {
                    table = scan.getTableModel();
                    String uri = config.getUrl();
                    if (uri.contains("?")) {
                        uri = uri.substring(0, uri.indexOf("?"));
                    }
                    HttpRequestHeader headers = new HttpRequestHeader();
                    headers.setMethod(HttpRequestHeader.POST);
                    headers.setURI(new URI(uri, true));
                    headers.setVersion(HttpHeader.HTTP11);
                    for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                        headers.setHeader(header.getName(), header.getValue());
                    }
                    String postPayload = StringUtils.strip(Utils.createQueryString(params), "?");
                    msg.setRequestHeader(headers);
                    msg.setRequestBody(postPayload);
                    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                    httpSender.sendAndReceive(msg);
                    table.addHistoryReference(
                            new HistoryReference(Model.getSingleton().getSession(), 23, msg));
                    return postPayload;
                } catch (Exception e) {
                    // TODO show proper error message on Output Panel
                    logger.error(e);
                }
                break;

            default:
                break;
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

        ParamReasons reasons = new ParamReasons();
        if (resp1.getStatusCode() != resp2.getStatusCode()
                || ComparableResponse.statusCodeHeuristic(resp1, resp2)
                        < this.guesser.getStatusCodeThreshold()) {
            reasons.addReason(Reason.HTTP_CODE);
        }

        if (ComparableResponse.headersCompareHeuristic(resp1, resp2)
                < this.guesser.getHttpHeadersThreshold()) {
            // TODO Add "which" headers were a mismatch
            reasons.addReason(Reason.HTTP_HEADERS);
        }

        if (!Objects.equals(
                resp1.getHeaders().get("Location"), resp2.getHeaders().get("Location"))) {
            reasons.addReason(Reason.REDIRECT);
        }

        if (ComparableResponse.bodyTreesStructureHeuristic(resp1, resp2)
                < this.guesser.getBodyTreesStructureHeuristicThreshold()) {
            reasons.addReason(Reason.BODY_HEURISTIC_MISMATCH);
        }

        if (ComparableResponse.lineCountHeuristic(resp1, resp2)
                < this.guesser.getLineCountHeuristicThreshold()) {
            reasons.addReason(Reason.LINE_COUNT);
        }

        if (ComparableResponse.wordCountHeuristic(resp1, resp2)
                < this.guesser.getWordCountHeuristic()) {
            reasons.addReason(Reason.WORD_COUNT);
        }

        Source source1 = new Source(resp1.getBody());
        Source source2 = new Source(resp2.getBody());
        if (!source1.toString().equals(source2.toString())) {
            reasons.addReason(Reason.TEXT);
        }

        if (!resp1.getBody().contains(resp1.getValueSent())) {
            if (this.firstComparison) {
                this.firstComparison = false;
                this.paramsPresent = new ArrayList<>();
                for (String param : wordlist) {
                    if (resp2.getBody().contains(param)) {
                        this.paramsPresent.add(param);
                    }
                }
            } else if (!paramsPresent.isEmpty()) {
                for (String param : params.keySet()) {
                    if (param.length() < 5) {
                        continue;
                    }
                    if (!paramsPresent.contains(param)) {
                        Pattern searchParamPattern =
                                Pattern.compile("['\"\\s]" + param + "['\"\\s]");
                        if (searchParamPattern.matcher(resp2.getBody()).find()) {
                            reasons.addReason(Reason.PARAM_NAME_REFLECTION);
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
                        reasons.addReason(Reason.PARAM_VALUE_REFLECTION);
                    }
                }
            }
        }

        if (!reasons.isEmpty()) {
            reasons.setParams(params);
        }

        return reasons;
    }
}
