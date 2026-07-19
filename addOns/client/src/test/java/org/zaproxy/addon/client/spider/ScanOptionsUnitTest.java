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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/** Unit test for {@link ScanOptions}. */
class ScanOptionsUnitTest {

    @Test
    void shouldHaveDefaults() {
        ScanOptions options = ScanOptions.builder().build();
        assertThat(options.getHrefType(), is(HistoryReference.TYPE_CLIENT_SPIDER));
        assertThat(options.getTmpHrefType(), is(HistoryReference.TYPE_CLIENT_SPIDER_TEMPORARY));
        assertThat(options.getThreadPrefix(), is("ZAP-ClientSpiderThreadPool-"));
        assertThat(options.isExternalControl(), is(false));
        assertThat(options.getIncludeExtensions(), is(empty()));
        assertThat(options.getExcludeExtensions(), is(empty()));
        assertThat(options.getHttpSender(), is(nullValue()));
    }

    @Test
    void shouldAllowHttpSenderToBeSet() {
        HttpSender httpSender = new HttpSender(HttpSender.CLIENT_SPIDER_INITIATOR);
        assertThat(
                ScanOptions.builder().setHttpSender(httpSender).build().getHttpSender(),
                is(httpSender));
    }

    @Test
    void shouldAllowExtensionListsToBeSet() {
        ScanOptions options =
                ScanOptions.builder()
                        .setIncludeExtensions(List.of("zap-browser-extension"))
                        .setExcludeExtensions(List.of("other-extension"))
                        .build();
        assertThat(options.getIncludeExtensions(), is(List.of("zap-browser-extension")));
        assertThat(options.getExcludeExtensions(), is(List.of("other-extension")));
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
                        .setIncludeExtensions(List.of("included-ext"))
                        .setExcludeExtensions(List.of("excluded-ext"))
                        .setHttpSender(new HttpSender(99))
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
        assertThat(copy.getIncludeExtensions(), is(List.of("included-ext")));
        assertThat(copy.getExcludeExtensions(), is(List.of("excluded-ext")));
        assertThat(copy.getHttpSender(), is(original.getHttpSender()));
    }
}
