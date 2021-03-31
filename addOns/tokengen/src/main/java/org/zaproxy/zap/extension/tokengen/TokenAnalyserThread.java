/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import com.fasteasytrade.JRandTest.IO.OutputDestination;
import com.fasteasytrade.JRandTest.IO.RandomStream;
import com.fasteasytrade.JRandTest.Tests.Base;
import com.fasteasytrade.JRandTest.Tests.Count16Bits;
import com.fasteasytrade.JRandTest.Tests.Count1Bit;
import com.fasteasytrade.JRandTest.Tests.Count2Bits;
import com.fasteasytrade.JRandTest.Tests.Count3Bits;
import com.fasteasytrade.JRandTest.Tests.Count4Bits;
import com.fasteasytrade.JRandTest.Tests.Count8Bits;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.tokengen.TokenAnalysisTestResult.Result;

public class TokenAnalyserThread extends Thread {

    public static final int NUM_TESTS = 9; // Change manually if you add any tests!

    private CharacterFrequencyMap cfm = null;
    private List<TokenAnalyserListenner> listenners = new ArrayList<>();
    private OutputDestination outputDestination = null;
    private boolean cancelled = false;

    private static Logger log = LogManager.getLogger(TokenAnalyserThread.class);

    private ResourceBundle messages;

    public TokenAnalyserThread(ResourceBundle messages) {
        this.messages = messages;
    }

    @Override
    public void run() {
        log.debug("run");

        if (cfm == null) {
            log.debug("Cant run no map :(");
            return;
        }

        // Analyse the tokens
        TokenAnalysisTestResult result;

        // Maximum theoretical entropy
        double maxEntropy = cfm.getMaxTheoreticalEntropy();
        result = new TokenAnalysisTestResult(TokenAnalysisTestResult.Type.MAX_ENTROPY);
        if (maxEntropy >= 80) {
            result.setResult(TokenAnalysisTestResult.Result.PASS);
            result.setSummary(messages.getString("tokengen.analyse.summary.excellent"));
        } else if (maxEntropy >= 60) {
            result.setResult(TokenAnalysisTestResult.Result.HIGH);
            result.setSummary(messages.getString("tokengen.analyse.summary.good"));
        } else if (maxEntropy >= 40) {
            result.setResult(TokenAnalysisTestResult.Result.MEDIUM);
            result.setSummary(messages.getString("tokengen.analyse.summary.robust"));
        } else if (maxEntropy >= 20) {
            result.setResult(TokenAnalysisTestResult.Result.LOW);
            result.setSummary(messages.getString("tokengen.analyse.summary.vulnerable"));
        } else {
            result.setResult(TokenAnalysisTestResult.Result.FAIL);
            result.setSummary(messages.getString("tokengen.analyse.summary.deterministic"));
        }
        if (cancelled) {
            return;
        }
        List<String> entDetails = new ArrayList<>();
        entDetails.add(messages.getString("tokengen.analyse.detail.maxentropy") + " " + maxEntropy);
        result.setDetails(entDetails);
        this.notifyListenners(result);
        if (cancelled) {
            return;
        }

        // Character uniformity
        this.notifyListenners(cfm.checkCharacterUniformity());
        if (cancelled) {
            return;
        }

        // Character transitions
        this.notifyListenners(cfm.checkCharacterTransitions());
        if (cancelled) {
            return;
        }

        TokenRandomStream trs = new TokenRandomStream(cfm);

        runTest(new Count1Bit(), trs, TokenAnalysisTestResult.Type.COUNT_1_BIT);
        runTest(new Count2Bits(), trs, TokenAnalysisTestResult.Type.COUNT_2_BITS);
        runTest(new Count3Bits(), trs, TokenAnalysisTestResult.Type.COUNT_3_BITS);
        runTest(new Count4Bits(), trs, TokenAnalysisTestResult.Type.COUNT_4_BITS);
        runTest(new Count8Bits(), trs, TokenAnalysisTestResult.Type.COUNT_8_BITS);
        runTest(new Count16Bits(), trs, TokenAnalysisTestResult.Type.COUNT_16_BITS);
    }

    private void runTest(Base test, RandomStream rs, TokenAnalysisTestResult.Type type) {
        if (cancelled) {
            return;
        }
        try {
            TokenAnalysisTestResult result = new TokenAnalysisTestResult(type);
            test.registerInput(rs);
            test.addOutputDestination(this.outputDestination);
            test.runTest();
            result.setDetails(test.getDetails());
            result.setFailures(test.getErrors());
            result.setResult(Result.valueOf(test.getResult().name()));
            test.help(); // This outputs a summary to the specified outputDestination
            this.notifyListenners(result);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private void notifyListenners(TokenAnalysisTestResult result) {
        log.debug("notifyListenners {} {}", result.getType(), result.getResult().name());

        for (TokenAnalyserListenner listenner : listenners) {
            listenner.notifyTestResult(result);
        }
    }

    public void addListenner(TokenAnalyserListenner listenner) {
        this.listenners.add(listenner);
    }

    public void setCfm(CharacterFrequencyMap cfm) {
        this.cfm = cfm;
    }

    public void cancel() {
        this.cancelled = true;
    }

    public void addOutputDestination(OutputDestination outputDestination) {
        this.outputDestination = outputDestination;
    }
}
