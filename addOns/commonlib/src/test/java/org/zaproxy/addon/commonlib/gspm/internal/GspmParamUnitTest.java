/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.gspm.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link GspmParam}. */
class GspmParamUnitTest {

    private ZapXmlConfiguration config;
    private GspmParam param;

    @BeforeEach
    void setUp() {
        config = new ZapXmlConfiguration();
        param = new GspmParam();
        param.load(config);
    }

    @Test
    void shouldHaveNoStateByDefault() {
        assertThat(param.getState(), is(nullValue()));
    }

    @Test
    void shouldPersistEditedState() {
        // Given
        GspmParam.State state = new GspmParam.State("Policy", true, "[{\"name\":\"a, b\"}]", null);
        // When
        param.setState(state);
        // Then
        GspmParam other = new GspmParam();
        other.load(config);
        assertThat(other.getState(), is(equalTo(state)));
    }

    @Test
    void shouldNotPersistRuleSetsIfNotEdited() {
        // Given
        param.setState(new GspmParam.State("Policy", true, "[]", null));
        // When
        param.setState(new GspmParam.State("Other", false, null, null));
        // Then
        assertThat(config.getString("commonlib.gspm.ascanDialog.ruleSets"), is(nullValue()));
        GspmParam other = new GspmParam();
        other.load(config);
        assertThat(other.getState(), is(equalTo(new GspmParam.State("Other", false, null, null))));
    }

    @Test
    void shouldPersistDefaultPolicyOfState() {
        // Given
        GspmParam.State state = new GspmParam.State("Policy", false, null, "Dev Full");
        // When
        param.setState(state);
        // Then
        GspmParam other = new GspmParam();
        other.load(config);
        assertThat(other.getState(), is(equalTo(state)));
    }

    @Test
    void shouldNotHaveImportedPassiveRulesByDefault() {
        assertThat(param.isPassiveImported(), is(equalTo(false)));
    }

    @Test
    void shouldPersistPassiveImported() {
        // When
        param.setPassiveImported();
        // Then
        assertThat(param.isPassiveImported(), is(equalTo(true)));
        GspmParam other = new GspmParam();
        other.load(config);
        assertThat(other.isPassiveImported(), is(equalTo(true)));
    }
}
