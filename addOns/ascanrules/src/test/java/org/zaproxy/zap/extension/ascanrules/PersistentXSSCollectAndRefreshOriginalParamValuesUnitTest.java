/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link PersistentXSSCollectAndRefreshOriginalParamValues}. */
public class PersistentXSSCollectAndRefreshOriginalParamValuesUnitTest
        extends SinkDetectionUnitTest<PersistentXSSCollectAndRefreshOriginalParamValues> {

    @Override
    protected PersistentXSSCollectAndRefreshOriginalParamValues createScanner() {
        return new PersistentXSSCollectAndRefreshOriginalParamValues();
    }

    @Test
    public void shouldAddSentValueToSeenValues() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_POSTDATA);
        String testInputLocation = "/sinksDetectionSaveFormParameterInput";
        this.nano.addHandler(new HandlerStoresPostParamXxxx(testInputLocation, new String[] {""}));

        HttpMessage srcMsg = this.getHttpMessage("POST", testInputLocation, baseHtmlResponse);
        String reqBody = "xxxx=test";
        srcMsg.setRequestBody(reqBody);
        srcMsg.getRequestHeader().setContentLength(reqBody.length());
        srcMsg.getRequestHeader().addHeader("Content-Type", "application/x-www-form-urlencoded");

        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        Set<String> x = storage.getSeenValuesContainedInString("test");
        assert (x.size() == 1);
        assert (x.contains("test"));
    }

    @Test
    public void shouldNotAddPathParamIfThresholdHigh() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        String testInputLocation = "/sinksDetectionSavePathParameterInput/";
        this.nano.addHandler(new HandlerStoresPathParam(testInputLocation, new String[] {""}));
        HttpMessage srcMsg = this.getHttpMessage(testInputLocation + "xxxx/name");

        this.rule.setAlertThreshold(Plugin.AlertThreshold.HIGH);
        this.rule.setAttackStrength(Plugin.AttackStrength.HIGH);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        Set<String> x = storage.getSeenValuesContainedInString("xxxx");
        assert (x.size() == 0);
    }

    @Test
    public void shouldNotAddPathParamIfAttackStrengthLow() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        String testInputLocation = "/sinksDetectionSavePathParameterInput/";
        this.nano.addHandler(new HandlerStoresPathParam(testInputLocation, new String[] {""}));
        HttpMessage srcMsg = this.getHttpMessage(testInputLocation + "xxxx/name");

        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        Set<String> x = storage.getSeenValuesContainedInString("xxxx");
        assert (x.size() == 0);
    }

    @Test
    public void shouldNotAddPathParamIfAttackStrengthMedium() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        String testInputLocation = "/sinksDetectionSavePathParameterInput/";
        this.nano.addHandler(new HandlerStoresPathParam(testInputLocation, new String[] {""}));
        HttpMessage srcMsg = this.getHttpMessage(testInputLocation + "xxxx/name");

        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.MEDIUM);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        Set<String> x = storage.getSeenValuesContainedInString("xxxx");
        assert (x.size() == 0);
    }
}
