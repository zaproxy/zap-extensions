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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/** Unit test for {@link ScanOptions}. */
class ScanOptionsUnitTest {

    @Test
    void shouldHaveDefaultHrefType() {
        assertThat(
                ScanOptions.builder().build().getHrefType(),
                is(HistoryReference.TYPE_CLIENT_SPIDER));
    }

    @Test
    void shouldHaveDefaultTmpHrefType() {
        assertThat(
                ScanOptions.builder().build().getTmpHrefType(),
                is(HistoryReference.TYPE_CLIENT_SPIDER_TEMPORARY));
    }

    @Test
    void shouldHaveDefaultThreadPrefix() {
        assertThat(
                ScanOptions.builder().build().getThreadPrefix(), is("ZAP-ClientSpiderThreadPool-"));
    }

    @Test
    void shouldHaveExternalControlDisabledByDefault() {
        assertThat(ScanOptions.builder().build().isExternalControl(), is(false));
    }

    @Test
    void shouldAllowExternalControlToBeEnabled() {
        assertThat(
                ScanOptions.builder().setExternalControl(true).build().isExternalControl(),
                is(true));
    }

    @Test
    void shouldRejectNullThreadPrefix() {
        assertThrows(
                IllegalArgumentException.class, () -> ScanOptions.builder().setThreadPrefix(null));
    }

    @Test
    void shouldRejectBlankThreadPrefix() {
        assertThrows(
                IllegalArgumentException.class, () -> ScanOptions.builder().setThreadPrefix("  "));
    }

    @Test
    void shouldCopyAllFieldsWithToBuilder() {
        // Given
        Context context = mock(Context.class);
        User user = mock(User.class);
        ScanOptions original =
                ScanOptions.builder()
                        .setContext(context)
                        .setUser(user)
                        .setSubtreeOnly(true)
                        .setExternalControl(true)
                        .setHrefType(99)
                        .setTmpHrefType(100)
                        .setThreadPrefix("custom-prefix-")
                        .build();

        // When
        ScanOptions copy = original.toBuilder().build();

        // Then
        assertThat(copy.getContext(), is(context));
        assertThat(copy.getUser(), is(user));
        assertThat(copy.isSubtreeOnly(), is(true));
        assertThat(copy.isExternalControl(), is(true));
        assertThat(copy.getHrefType(), is(99));
        assertThat(copy.getTmpHrefType(), is(100));
        assertThat(copy.getThreadPrefix(), is("custom-prefix-"));
    }
}
