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

import org.junit.jupiter.api.Test;

/**
 * Packaging-level smoke tests for {@link ExtensionWstgMapper}.
 *
 * <p>This class focuses on lightweight resource checks that can catch broken repacks without
 * needing to boot the full ZAP UI or event stack during unit tests.
 */
class ExtensionWstgMapperTest {

    @Test
    void shouldPackageAddonIconResource() {
        assertThat(
                ExtensionWstgMapper.class.getResource(
                        "/org/zaproxy/addon/wstgmapper/resources/icon/wstg.png"),
                notNullValue());
    }

    @Test
    void shouldIdentifyWhetherSessionIsPersisted() {
        assertThat(ExtensionWstgMapper.hasPersistedSession(null), is(false));
        assertThat(ExtensionWstgMapper.hasPersistedSession(""), is(false));
        assertThat(ExtensionWstgMapper.hasPersistedSession("/tmp/example.session"), is(true));
    }

    @Test
    void shouldResolveUnsavedSessionSidecarFile() {
        assertThat(
                ExtensionWstgMapper.getUnsavedSessionFile().getName(),
                is("wstgmapper-default.xml"));
    }

    @Test
    void shouldResolveSavedSessionSidecarFile() {
        assertThat(
                ExtensionWstgMapper.getWstgMapperSessionFile("/tmp/example.session").getPath(),
                is("/tmp/example.session.wstgmapper.xml"));
    }
}
