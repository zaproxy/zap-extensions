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

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link PersistentXSSFindPossibleSinks}. */
public class PersistentXSSFindPossibleSinksUnitTest
        extends SinkDetectionUnitTest<PersistentXSSFindPossibleSinks> {

    @Override
    protected PersistentXSSFindPossibleSinks createScanner() {
        return new PersistentXSSFindPossibleSinks();
    }

    final String[] storedValue = new String[] {""};

    @Test
    public void shouldAddPossibleSinkWhenSentValueInResponse() throws HttpMalformedHeaderException {
        storage.addSeenValue("test");
        storedValue[0] = "test";

        String testSinkLocation = "/sinksDetectionParameterSink";
        this.nano.addHandler(new SinkLocationHandler(testSinkLocation, storedValue));
        HttpMessage dstMsg = this.getHttpMessage(testSinkLocation);

        this.rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(dstMsg, this.parent);
        this.rule.scan();

        List<HttpMessage> x = storage.getPossibleSinksForValue("test");
        assert (x != null);
        assert (x.size() == 1);
        assert (dstMsg.getRequestHeader()
                .getURI()
                .getEscapedURI()
                .equals(x.get(0).getRequestHeader().getURI().getEscapedURI()));
    }
}
