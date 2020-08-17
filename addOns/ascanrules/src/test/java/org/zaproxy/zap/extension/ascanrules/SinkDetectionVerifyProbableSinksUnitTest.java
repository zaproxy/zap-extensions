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
import org.zaproxy.addon.commonlib.ParamSinksUtils;

/** Unit test for {@link SinkDetectionVerifyProbableSinks}. */
public class SinkDetectionVerifyProbableSinksUnitTest
        extends SinkDetectionUnitTest<SinkDetectionVerifyProbableSinks> {

    final String[] storedValue = new String[] {""};

    @Override
    protected SinkDetectionVerifyProbableSinks createScanner() {
        return new SinkDetectionVerifyProbableSinks();
    }

    private void checkIfMsgHasDstMsgAsSink(HttpMessage srcMsg, HttpMessage dstMsg) {
        Set<Integer> ids = ParamSinksUtils.getSinksIdsForSource(srcMsg, "xxxx");
        assert (ids != null);
        assert (ids.size() == 1);
        int id0 = ids.iterator().next();
        HttpMessage m = ParamSinksUtils.getMessage(id0);
        assert (dstMsg.getRequestHeader()
                .getURI()
                .getEscapedURI()
                .equals(m.getRequestHeader().getURI().getEscapedURI()));
    }

    @Test
    public void shouldAddSinkWhenFormParamIsReflected() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_POSTDATA);
        String testInputLocation = "/sinksDetectionSaveFormParameterInput";
        this.nano.addHandler(new HandlerStoresPostParamXxxx(testInputLocation, storedValue));
        String testSinkLocation = "/sinksDetectionParameterSink";
        this.nano.addHandler(new SinkLocationHandler(testSinkLocation, storedValue));

        HttpMessage srcMsg = this.getHttpMessage("POST", testInputLocation, baseHtmlResponse);
        String reqBody = "xxxx=test";
        srcMsg.setRequestBody(reqBody);
        srcMsg.getRequestHeader().setContentLength(reqBody.length());
        srcMsg.getRequestHeader().addHeader("Content-Type", "application/x-www-form-urlencoded");

        HttpMessage dstMsg = this.getHttpMessage(testSinkLocation);

        storage.addPossibleSinkForValue("test", dstMsg);
        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        checkIfMsgHasDstMsgAsSink(srcMsg, dstMsg);
    }

    @Test
    public void shouldAddSinkWhenQueryParamIsReflected() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_QUERYSTRING);
        String testInputLocation = "/sinksDetectionSaveQueryParameterInput";
        this.nano.addHandler(new HandlerStoresQueryParamXxxx(testInputLocation, storedValue));
        String testSinkLocation = "/sinksDetectionParameterSink";
        this.nano.addHandler(new SinkLocationHandler(testSinkLocation, storedValue));

        HttpMessage srcMsg = this.getHttpMessage(testInputLocation + "?xxxx=test");
        HttpMessage dstMsg = this.getHttpMessage(testSinkLocation);

        storage.addPossibleSinkForValue("test", dstMsg);
        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        checkIfMsgHasDstMsgAsSink(srcMsg, dstMsg);
    }

    @Test
    public void shouldAddSinkWhenPathParamIsReflected() throws HttpMalformedHeaderException {
        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        String testInputLocation = "/sinksDetectionSavePathParameterInput/";
        this.nano.addHandler(new HandlerStoresPathParam(testInputLocation, storedValue));
        String testSinkLocation = "/sinksDetectionParameterSink";
        this.nano.addHandler(new SinkLocationHandler(testSinkLocation, storedValue));

        HttpMessage srcMsg = this.getHttpMessage(testInputLocation + "xxxx/name");
        HttpMessage dstMsg = this.getHttpMessage(testSinkLocation);

        storage.addPossibleSinkForValue("xxxx", dstMsg);
        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(srcMsg, this.parent);
        this.rule.scan();

        checkIfMsgHasDstMsgAsSink(srcMsg, dstMsg);
    }
}
