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

import java.io.IOException;
import java.net.HttpCookie;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.utils.ThreadUtils;

public class HeaderGuesser implements Runnable {

    private int id;
    private GuesserScan scan;
    private HttpSender httpSender;
    private ExecutorService executor;
    private ParamDiggerConfig config;

    private static final String DEFAULTWORDLISTPATH =
            Constant.getZapHome() + "/wordlists/header_list.txt";
    private Path defaultWordListFile;
    private List<String> defaultWordList;

    private Path customWordListFile;
    private List<String> customWordList;
    private List<String> wordlist;

    private CacheController cacheController;
    private SecureRandom random;
    private HttpMessage baseBusted;
    private List<ParamReasons> allReasons;
    private List<ParamReasons> allPrimaryReasons;
    private static final Logger LOGGER = LogManager.getLogger(HeaderGuesser.class);
    private static final int RANDOM_SEED = 10000000;
    private static final String POISON_DEFINITION = "paramdigger.results.poison.definition";
    private static final String POISON_DEFINITION_FIRST =
            "paramdigger.results.poison.definition.first";
    private static List<Integer> ERROR_CODES = List.of(400, 413, 418, 429, 503);

    private static final int PORT = 31337;
    private static final String[] PORTS = {":" + PORT, ":@" + PORT, " " + PORT};

    private static final String[] X_FORWARDED_HEADERS = {"X-Forwarded-Host", "X-Forwarded-Scheme"};
    private static final String X_FORWARDED_HEADERS_IDENTIFIER =
            "X-Forwarded-Host and  X-Forwarded-Scheme";

    private static final String FORWARDED = "Forwarded";

    private static final String X_FORWARDED_PORT = "X-Forwarded-Port";
    private static final String FPORT = "" + PORT;

    public HeaderGuesser(
            int id, GuesserScan scan, HttpSender httpSender, ExecutorService executor) {
        this.id = id;
        this.scan = scan;
        this.httpSender = httpSender;
        this.executor = executor;
        this.config = scan.getConfig();

        if (config.getUsePredefinedHeaderWordlists()) {
            defaultWordListFile = Paths.get(DEFAULTWORDLISTPATH);
            defaultWordList = Utils.read(defaultWordListFile);
        }
        if (config.getUseCustomHeaderWordlists()) {
            customWordListFile = Paths.get(config.getCustomHeaderWordlistPath());
            customWordList = Utils.read(customWordListFile);
        }

        if (defaultWordList != null && customWordList != null) {
            Set<String> set = new HashSet<>();
            set.addAll(defaultWordList);
            set.addAll(customWordList);
            wordlist = new ArrayList<>();

            for (String param : set) {
                wordlist.add(param);
            }
        } else if (customWordList == null && defaultWordList != null) {
            wordlist = defaultWordList;
        } else {
            wordlist = customWordList;
        }
        this.scan.setMaximum(1);
        this.cacheController = new CacheController(this.httpSender, this.scan);
        this.random = new SecureRandom();
        this.allReasons = new ArrayList<>();
        this.allPrimaryReasons = new ArrayList<>();
        this.scan.setMaximum(4);
    }

    @Override
    public void run() {
        for (Method method : config.getHeaderGuessMethods()) {
            startGuess(method, wordlist);
        }

        for (ParamReasons reasons : allPrimaryReasons) {
            for (String identifiers : reasons.getParams().keySet()) {
                String customIdentifier =
                        Constant.messages.getString(
                                POISON_DEFINITION_FIRST,
                                identifiers,
                                reasons.getParams().get(identifiers));
                scan.addParamGuessResult(
                        new ParamGuessResult(
                                customIdentifier, reasons.getReasons(), reasons.getRef()));
            }
        }

        for (ParamReasons reasons : allReasons) {
            for (String identifiers : reasons.getParams().keySet()) {
                String customIdentifier =
                        Constant.messages.getString(
                                POISON_DEFINITION,
                                identifiers,
                                reasons.getParams().get(identifiers));
                scan.addParamGuessResult(
                        new ParamGuessResult(
                                customIdentifier, reasons.getReasons(), reasons.getRef()));
            }
        }
        completeGuess();
    }

    public void startGuess(Method method, List<String> wordlist) {
        forwardingHeaderGuess(method);
        bruteForceHeaderGuess(method, wordlist);
    }

    private void completeGuess() {
        if (scan.getProgress() != scan.getMaximum()) {
            scan.setProgress(scan.getMaximum());
        }
        scan.completed();
    }

    private void bruteForceHeaderGuess(Method method, List<String> wordlist) {
        // TODO Add bruteforcing task to be executed after crafted attacks
    }

    private void forwardingHeaderGuess(Method method) {
        // Try Host Header first
        for (int i = 0; i < PORTS.length; i++) {
            forwardTemplate(
                    new String[] {HttpRequestHeader.HOST},
                    new String[] {PORTS[i]},
                    HttpRequestHeader.HOST,
                    PORTS[i],
                    method);
        }
        this.scan.notifyListenersProgress();

        // Try X-Forwarded Headers
        String poison = "" + random.nextInt(RANDOM_SEED);
        // Try X-Forwarded-Host
        forwardTemplate(
                new String[] {X_FORWARDED_HEADERS[0]},
                new String[] {poison},
                X_FORWARDED_HEADERS[0],
                poison,
                method);
        this.scan.notifyListenersProgress();

        // Try X-Forwarded-Scheme along with X-Forwarded-Host
        poison = "" + random.nextInt(RANDOM_SEED);
        String[] values = {poison, "nothttps"};
        forwardTemplate(
                X_FORWARDED_HEADERS, values, X_FORWARDED_HEADERS_IDENTIFIER, poison, method);
        this.scan.notifyListenersProgress();

        // Try Forwarded Header
        String fValues = "host=" + random.nextInt(RANDOM_SEED);
        forwardTemplate(
                new String[] {FORWARDED}, new String[] {fValues}, FORWARDED, poison, method);
        this.scan.notifyListenersProgress();

        // Try X-Forwarded-Port
        forwardTemplate(
                new String[] {X_FORWARDED_PORT},
                new String[] {FPORT},
                X_FORWARDED_PORT,
                FPORT,
                method);
        this.scan.notifyListenersProgress();
    }

    private void forwardTemplate(
            String[] headers, String[] values, String identifier, String poison, Method method) {
        try {
            HttpMessage msg1 = this.makeRequests(config.getUrl(), method, headers, values, false);
            this.checkFirstRequestPoisoning(msg1, identifier, poison);
            HttpMessage msg2 = this.makeRequests(config.getUrl(), method, headers, values, true);
            this.checkPoisoning(msg1, msg2, identifier, poison);
        } catch (Exception e) {
            LOGGER.error(e, e);
        }
    }

    private void checkPoisoning(
            HttpMessage msg1, HttpMessage msg2, String identifier, String poison)
            throws IOException {
        ComparableResponse response1 = new ComparableResponse(msg1, poison);
        ComparableResponse response = new ComparableResponse(baseBusted, null);
        ComparableResponse response2 = new ComparableResponse(msg2, poison);

        if (isFalsePositive(response, response2)
                || isFalsePositive(response1, response2)
                || isFalsePositive(response, response1)) {
            return;
        }

        if (poison != null && !poison.isEmpty() && identifier != null && !identifier.isEmpty()) {
            Map<String, String> params = new HashMap<>();
            params.put(identifier, poison);
            List<HttpHeaderField> headers1 = msg1.getResponseHeader().getHeaders();
            List<HttpHeaderField> headers2 = msg2.getResponseHeader().getHeaders();

            List<String> headerNames = new ArrayList<>();

            for (HttpHeaderField header : headers2) {
                if (header.getValue().contains(poison) && headers1.contains(header)) {
                    for (HttpHeaderField header1 : headers1) {
                        if (header1.getValue().equals(header.getValue())) {
                            headerNames.add(header.getName());
                        }
                    }
                }
            }

            boolean bodyReflection = false;

            if ((ComparableResponse.inputReflectionHeuristic(response1, response2) < 1)
                    && (ComparableResponse.inputReflectionHeuristic(response1, response) <= 1.0)) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.POISON_REFLECTION_IN_BODY);
                ParamReasons paramReasons = new ParamReasons(reasons, params, msg2.getHistoryRef());
                allReasons.add(paramReasons);
                bodyReflection = true;
            }

            if (!headerNames.isEmpty()) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.POISON_REFLECTION_IN_HEADER);
                for (String headerName : headerNames) {
                    params.put(headerName, poison);
                    ParamReasons paramReasons =
                            new ParamReasons(reasons, params, msg2.getHistoryRef());
                    allReasons.add(paramReasons);
                }
            }

            if (msg1.getResponseHeader().getStatusCode()
                            != baseBusted.getResponseHeader().getStatusCode()
                    && msg1.getResponseHeader().getStatusCode()
                            == msg2.getResponseHeader().getStatusCode()) {
                /* This means we might have a redirect or a DoS.
                 * To verify we send two reqeuests using the busting request from cache controller.
                 * If the response is the same as recieved from the cache controller, we have a DoS or a redirect.
                 * If the response is different, we have a false positive.
                 */
                HttpMessage temp;
                for (int i = 0; i < 2; i++) {
                    HttpRequestHeader header = this.baseBusted.getRequestHeader();
                    temp = new HttpMessage(header);
                    try {
                        httpSender.sendAndReceive(temp);
                        this.baseBusted = temp;
                        if (msg1.getResponseHeader().getStatusCode()
                                        != baseBusted.getResponseHeader().getStatusCode()
                                && msg1.getResponseHeader().getStatusCode()
                                        == msg2.getResponseHeader().getStatusCode()) {
                            List<Reason> reasons = new ArrayList<>();
                            reasons.add(Reason.HTTP_CODE);
                            ParamReasons paramReasons =
                                    new ParamReasons(reasons, params, msg2.getHistoryRef());
                            allReasons.add(paramReasons);
                            break;
                        }
                    } catch (Exception e) {
                        LOGGER.error(e, e);
                    }
                }
            }

            if (ComparableResponse.lineCountHeuristic(response1, response) < 1
                    && ComparableResponse.lineCountHeuristic(response2, response1) <= 1.0) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.LINE_COUNT);
                ParamReasons paramReasons = new ParamReasons(reasons, params, msg2.getHistoryRef());
                allReasons.add(paramReasons);
            }
            if (ComparableResponse.bodyTreesStructureHeuristic(response1, response) < 1
                    && ComparableResponse.bodyTreesStructureHeuristic(response2, response1) <= 1.0
                    && !bodyReflection) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.BODY_HEURISTIC_MISMATCH);
                ParamReasons paramReasons = new ParamReasons(reasons, params, msg2.getHistoryRef());
                allReasons.add(paramReasons);
            }
        }
    }

    private void checkFirstRequestPoisoning(HttpMessage msg1, String identifier, String poison) {
        Map<String, String> params = new HashMap<>();
        params.put(identifier, poison);
        ComparableResponse baseBustedCompRes = new ComparableResponse(this.baseBusted, null);
        ComparableResponse suspect = new ComparableResponse(msg1, poison);

        if (isFalsePositive(baseBustedCompRes, suspect)) {
            return;
        }

        if (poison != null && !poison.isEmpty()) {
            boolean bodyReflection = false;
            if (ComparableResponse.inputReflectionHeuristic(baseBustedCompRes, suspect) < 1) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.POISON_REFLECTION_IN_BODY);
                ParamReasons paramReasons = new ParamReasons(reasons, params, msg1.getHistoryRef());
                this.allPrimaryReasons.add(paramReasons);
                bodyReflection = true;
            }

            /* This just checks for a reflection of poison. Should somehow check with baseBusted Headers for difference. */
            List<HttpHeaderField> headers = msg1.getResponseHeader().getHeaders();
            for (HttpHeaderField header : headers) {
                if (header.getValue().contains(poison)) {
                    List<Reason> reasons = new ArrayList<>();
                    reasons.add(Reason.POISON_REFLECTION_IN_HEADER);
                    ParamReasons paramReason =
                            new ParamReasons(reasons, params, msg1.getHistoryRef());
                    this.allPrimaryReasons.add(paramReason);
                }
            }

            if (ComparableResponse.lineCountHeuristic(baseBustedCompRes, suspect) < 1) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.LINE_COUNT);
                ParamReasons paramReason = new ParamReasons(reasons, params, msg1.getHistoryRef());
                this.allPrimaryReasons.add(paramReason);
            }
            if (ComparableResponse.bodyTreesStructureHeuristic(baseBustedCompRes, suspect) < 1
                    && !bodyReflection) {
                List<Reason> reasons = new ArrayList<>();
                reasons.add(Reason.BODY_HEURISTIC_MISMATCH);
                ParamReasons paramReasons = new ParamReasons(reasons, params, msg1.getHistoryRef());
                this.allPrimaryReasons.add(paramReasons);
            }
        }
    }

    private HttpMessage makeRequests(
            String url, Method method, String[] headers, String[] values, boolean secondRequest)
            throws IOException {

        if (headers.length != values.length) {
            return null;
        }
        ParamDiggerHistoryTableModel table = scan.getTableModel();
        HttpRequestHeader reqHeaders = new HttpRequestHeader();

        if (cacheController.isCached(method)) {
            if (this.baseBusted == null) {
                this.baseBusted = cacheController.getBustedResponse();
            }

            if (cacheController.getCache().isCacheBusterIsHttpMethod() && !secondRequest) {
                reqHeaders.setMethod(cacheController.getCache().getCacheBusterName());
            } else {
                setMethod(reqHeaders, method);
            }

            if (cacheController.getCache().isCacheBusterIsParameter()) {
                String newUrl =
                        Utils.addCacheBusterParameter(
                                url,
                                cacheController.getCache().getCacheBusterName(),
                                Integer.toString(random.nextInt(RANDOM_SEED)));
                reqHeaders.setURI(new URI(newUrl, true));
            } else {
                reqHeaders.setURI(new URI(url, true));
            }

            if (cacheController.getCache().isCacheBusterIsHeader()) {
                reqHeaders.setHeader(
                        cacheController.getCache().getCacheBusterName(),
                        Integer.toString(random.nextInt(RANDOM_SEED)));
            }

            if (cacheController.getCache().isCacheBusterIsCookie()) {
                HttpCookie cookie =
                        new HttpCookie(
                                cacheController.getCache().getCacheBusterName(),
                                Integer.toString(random.nextInt(RANDOM_SEED)));
                List<HttpCookie> cookies = new ArrayList<>();
                cookies.add(cookie);
                reqHeaders.setCookies(cookies);
            }
        } else {
            /**
             * No caching detected by our cache controller. But that doesn't mean there aren't any
             * caching mechanisms working on the site.
             */
            setMethod(reqHeaders, method);
            reqHeaders.setURI(new URI(url, true));
            getBase(method);
        }
        reqHeaders.setVersion(HttpHeader.HTTP11);

        for (int i = 0; i < headers.length; i++) {
            if (!headers[i].equalsIgnoreCase(HttpRequestHeader.HOST)) {
                reqHeaders.setHeader(headers[i], values[i]);
            }
        }

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(reqHeaders);

        for (int i = 0; i < headers.length; i++) {
            if (headers[i].equalsIgnoreCase(HttpRequestHeader.HOST)) {
                String host = new URI(url, true).getHost();
                msg.setUserObject(Collections.singletonMap("host", host + values[i]));
            }
        }

        httpSender.sendAndReceive(msg);

        ThreadUtils.invokeAndWaitHandled(
                () -> {
                    try {
                        table.addHistoryReference(
                                new HistoryReference(
                                        Model.getSingleton().getSession(),
                                        HistoryReference.TYPE_PARAM_DIGGER,
                                        msg));
                    } catch (Exception e) {
                        LOGGER.error(e, e);
                    }
                });

        return msg;
    }

    /**
     * This method is used to skip out the comparisons which are not useful for us (generally false
     * positives). For example, if the response is empty or the status code is within the error
     * codes, we skip out the comparison.
     *
     * @param base a ComparableResponse object of the base HttpMessage.
     * @param suspect a ComparableResponse object of the suspect HttpMessage.
     * @return true if the comparison should be skipped, false otherwise.
     */
    private boolean isFalsePositive(ComparableResponse base, ComparableResponse suspect) {
        int baseStatus = base.getStatusCode();
        int suspectStatus = suspect.getStatusCode();
        if (ERROR_CODES.contains(baseStatus) || ERROR_CODES.contains(suspectStatus)) {
            return true;
        }
        if (suspect.getHeaders().isEmpty() || suspect.getBody().isEmpty()) {
            return true;
        }
        return false;
    }

    private void setMethod(HttpRequestHeader reqHeaders, Method method) {
        switch (method) {
            case GET:
                reqHeaders.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                reqHeaders.setMethod(HttpRequestHeader.POST);
                break;
            default:
                throw new IllegalArgumentException("Method not supported!");
        }
    }

    /**
     * This method is used to set the base busted response, when the CacheController hasn't detected
     * any caching, but there is a possible caching mechanism working on the site.
     *
     * @param method the HTTP method to be used for the request.
     * @throws NullPointerException
     * @throws IOException
     */
    private void getBase(Method method) throws NullPointerException, IOException {
        if (this.baseBusted == null) {
            HttpRequestHeader baseReqHeaders = new HttpRequestHeader();
            setMethod(baseReqHeaders, method);
            baseReqHeaders.setURI(new URI(config.getUrl(), true));
            baseReqHeaders.setVersion(HttpHeader.HTTP11);
            HttpMessage baseMsg = new HttpMessage();
            baseMsg.setRequestHeader(baseReqHeaders);
            httpSender.sendAndReceive(baseMsg);
            this.baseBusted = baseMsg;
        }
    }
}
