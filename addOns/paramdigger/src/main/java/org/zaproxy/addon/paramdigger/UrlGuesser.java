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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.http.ComparableResponse;

public class UrlGuesser implements Runnable {

    public enum Mode {
        VERIFY,
        BRUTEFORCE,
    }

    public enum Status {
        OK,
        RETRY,
        KILL,
    }

    private HttpSender httpSender;
    private int id;
    // TODO should pass id to bruteforce task
    private ParamDiggerConfig config;
    private GuesserScan scan;

    private static final String DEFAULTWORDLISTPATH =
            Constant.getZapHome() + "/wordlists/small_list.txt";
    private Path defaultWordListFile;
    private List<String> defaultWordList;

    private Path customWordListFile;
    private List<String> customWordList;

    private List<String> wordlist;
    private final ExecutorService executor;
    private List<ParamGuessResult> paramGuessResults;
    private final String INIT_PARAM_1 = "zap";
    private final String INIT_VALUE_1 = "123";
    private final String INIT_PARAM_2 = "pow";
    private final String INIT_VALUE_2 = "4321";

    private float statusCodeThreshold;
    private float httpHeadersThreshold;
    private float bodyTreesStructureHeuristicThreshold;
    private float lineCountHeuristicThreshold;
    private float wordCountHeuristic;

    private static final Logger logger = LogManager.getLogger(UrlGuesser.class);

    public UrlGuesser(int id, GuesserScan scan, HttpSender httpSender, ExecutorService executor) {
        this.id = id;
        this.config = scan.getConfig();
        this.scan = scan;
        this.httpSender = httpSender;
        this.executor = executor;

        if (config.getUsePredefinedUrlWordlists()) {
            defaultWordListFile = Paths.get(DEFAULTWORDLISTPATH);
            defaultWordList = Utils.read(defaultWordListFile);
        }
        if (config.getUseCustomUrlWordlists()) {
            customWordListFile = Paths.get(config.getCustomUrlWordlistPath());
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
    }

    @Override
    public void run() {
        try {
            if (config.getUrlGetRequest()) {
                startGuess(Method.GET, wordlist);
            }
            if (config.getUrlPostRequest()) {
                startGuess(Method.POST, wordlist);
            }
            if (config.getUrlXmlRequest()) {
                startGuess(Method.XML, wordlist);
            }
            if (config.getUrlJsonRequest()) {
                startGuess(Method.JSON, wordlist);
            }
            // TODO show paramGuessResults in GUI(OutputTab)
        } catch (Exception e) {
            // TODO Add exception message using Constants
            logger.error(e, e);
        }
        for (ParamGuessResult paramGuessResult : paramGuessResults) {
            scan.addParamGuessResult(paramGuessResult);
        }
        completeGuess();
    }

    private void completeGuess() {
        if (scan.getProgress() != scan.getMaximum()) {
            scan.setProgress(scan.getMaximum());
        }
        scan.completed();
    }

    private void startGuess(Method method, List<String> wordlist) {
        ComparableResponse primary = firstRequest(method, INIT_PARAM_1, INIT_VALUE_1);
        ComparableResponse base = firstRequest(method, INIT_PARAM_2, INIT_VALUE_2);

        // Set threshold values
        this.statusCodeThreshold = ComparableResponse.statusCodeHeuristic(primary, base);
        this.httpHeadersThreshold = ComparableResponse.headersCompareHeuristic(primary, base);
        this.bodyTreesStructureHeuristicThreshold =
                ComparableResponse.bodyTreesStructureHeuristic(primary, base);
        this.lineCountHeuristicThreshold = ComparableResponse.lineCountHeuristic(primary, base);
        this.wordCountHeuristic = ComparableResponse.wordCountHeuristic(primary, base);

        this.scan.notifyListenersProgress();
        // TODO Add heuristic method to mine parameters from base response.

        List<Map<String, String>> paramGroups =
                Utils.slice(Utils.populate(wordlist), config.getUrlGuessChunkSize());
        this.scan.setMaximum(paramGroups.size());
        List<Map<String, String>> usableParams = new ArrayList<>();

        // BruteForcing step
        while (!paramGroups.isEmpty()) {
            if (this.scan.isStopped()) {
                return;
            }
            paramGroups = narrowDownParams(base, method, paramGroups);
            paramGroups = Utils.confirmUsableParameters(paramGroups, usableParams);
            this.scan.setMaximum(paramGroups.size());
            this.scan.notifyListenersProgress();
            logger.debug("param groups size: {}", paramGroups.size());
        }

        logger.debug("Usable parameters: {}", usableParams.size());
        this.scan.setMaximum(usableParams.size());
        paramGuessResults = Collections.synchronizedList(new ArrayList<>());

        // Confirmation step
        List<Future<ParamReasons>> reasons = new ArrayList<>();
        for (Map<String, String> paramVerify : usableParams) {
            if (this.scan.isStopped()) {
                return;
            }

            this.scan.notifyListenersProgress();
            reasons.add(
                    executor.submit(
                            new UrlBruteForce(
                                    base,
                                    INIT_VALUE_2,
                                    method,
                                    paramVerify,
                                    Mode.VERIFY,
                                    scan,
                                    this,
                                    this.httpSender,
                                    wordlist,
                                    paramGuessResults)));
        }
        for (Future<ParamReasons> future : reasons) {
            try {
                ParamReasons paramReasons = future.get();
            } catch (Exception e) {
                // TODO display exception message in GUI
                logger.error(e, e);
            }
        }
    }

    private List<Map<String, String>> narrowDownParams(
            ComparableResponse base, Method method, List<Map<String, String>> paramGroups) {
        List<Map<String, String>> narrowedParamGroups = new ArrayList<>();
        List<Future<ParamReasons>> futures = new ArrayList<>();

        for (Map<String, String> param : paramGroups) {
            if (this.scan.isStopped()) {
                return narrowedParamGroups;
            }
            futures.add(
                    executor.submit(
                            new UrlBruteForce(
                                    base,
                                    INIT_VALUE_2,
                                    method,
                                    param,
                                    Mode.BRUTEFORCE,
                                    scan,
                                    this,
                                    this.httpSender,
                                    wordlist,
                                    null)));
        }

        for (Future<ParamReasons> future : futures) {
            try {
                ParamReasons narrowedParam = future.get();
                if (narrowedParam != null && !narrowedParam.isEmpty()) {
                    List<Map<String, String>> slices = Utils.slice(narrowedParam.getParams(), 2);
                    for (Map<String, String> slice : slices) {
                        narrowedParamGroups.add(slice);
                    }
                    this.scan.notifyListenersProgress();
                }
            } catch (Exception e) {
                // TODO Display proper error message to user
                logger.error(e, e);
            }
        }
        return narrowedParamGroups;
    }

    public ComparableResponse firstRequest(Method method, String param, String value) {
        HttpMessage msg = new HttpMessage();
        Map<String, String> initialParam = new HashMap<>();
        initialParam.put(param, value);

        UrlBruteForce initialBruter =
                new UrlBruteForce(
                        null,
                        value,
                        method,
                        initialParam,
                        Mode.BRUTEFORCE,
                        scan,
                        this,
                        this.httpSender,
                        wordlist,
                        null);

        String valueSent = initialBruter.requester(msg, method, initialParam);
        return new ComparableResponse(msg, valueSent);
    }

    public float getStatusCodeThreshold() {
        return statusCodeThreshold;
    }

    public float getHttpHeadersThreshold() {
        return httpHeadersThreshold;
    }

    public float getBodyTreesStructureHeuristicThreshold() {
        return bodyTreesStructureHeuristicThreshold;
    }

    public float getLineCountHeuristicThreshold() {
        return lineCountHeuristicThreshold;
    }

    public float getWordCountHeuristic() {
        return wordCountHeuristic;
    }
}
