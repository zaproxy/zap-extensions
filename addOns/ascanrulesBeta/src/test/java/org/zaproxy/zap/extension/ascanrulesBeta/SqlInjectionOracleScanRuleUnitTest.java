/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/** Unit test for {@link SqlInjectionOracleScanRule}. */
public class SqlInjectionOracleScanRuleUnitTest
        extends ActiveScannerTest<SqlInjectionOracleScanRule> {

    @Override
    protected SqlInjectionOracleScanRule createScanner() {
        return new SqlInjectionOracleScanRule();
    }

    @Test
    public void shouldTargetOracleTech() throws Exception {
        // Given
        TechSet techSet = techSet(Tech.Oracle);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonOracleTechs() throws Exception {
        // Given
        TechSet techSet = techSetWithout(Tech.Oracle);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }
}
