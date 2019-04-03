/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Unit test for {@link CodeInjectionPlugin}.
 */
public class CodeInjectionPluginUnitTest extends ActiveScannerAppParamTest<CodeInjectionPlugin> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
        case LOW:
            return recommendMax + 2;
        case MEDIUM:
        default:
            return recommendMax;
        case HIGH:
            return recommendMax;
        case INSANE:
            return recommendMax;
        }
    }

    @Override
    protected CodeInjectionPlugin createScanner() {
        return new CodeInjectionPlugin();
    }

    @Test
    public void shouldTargetAspTech() {
        // Given
        TechSet techSet = techSet(Tech.ASP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldTargetPhpTech() {
        // Given
        TechSet techSet = techSet(Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonAspPhpTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.ASP, Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

}