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
package org.zaproxy.addon.wstgmapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Unit tests for {@link WstgMapperParam}.
 *
 * <p>These checks focus on how the add-on binds its persisted config to session sidecar files so
 * the dashboard keeps data with the right ZAP session.
 */
class WstgMapperParamTest {

    private WstgMapperParam param;

    @BeforeEach
    void setUp() {
        param = new WstgMapperParam();
        param.load(new ZapXmlConfiguration());
    }

    @Test
    void shouldBindUnsavedSessionsToDefaultSidecar() {
        param.bindToSessionFile(null);

        assertThat(param.getConfig().getFile(), notNullValue());
        assertThat(param.getConfig().getFile().getName(), is("wstgmapper-default.xml"));
    }

    @Test
    void shouldBindSavedSessionsToSessionSpecificSidecar() {
        param.bindToSessionFile("/tmp/example.session");

        assertThat(
                param.getConfig().getFile().getPath(), is("/tmp/example.session.wstgmapper.xml"));
    }
}
