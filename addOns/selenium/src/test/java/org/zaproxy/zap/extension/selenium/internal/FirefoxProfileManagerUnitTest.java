/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Unit test for {@link FirefoxProfileManager}. */
class FirefoxProfileManagerUnitTest {

    @Test
    void shouldReturnProfiles() throws IOException {
        // Given
        Path path = Files.createTempDirectory("fx-profiles-test1");
        Files.createDirectory(path.resolve("a2c4d6f8.profile2"));
        Files.createDirectory(path.resolve("6jkd903j.profile1"));
        // Add invalid profiles as well
        Files.createDirectory(path.resolve("1b3d5f.not-a-profile"));
        Files.createFile(path.resolve("a2c4d6f8.file-not-dir"));
        FirefoxProfileManager fpm = new FirefoxProfileManager();
        fpm.setProfilesDirectory(path);

        // When
        List<String> profiles = fpm.getProfiles();

        // Then
        assertThat(profiles.size(), is(equalTo(2)));
        assertThat(profiles.get(0), is(equalTo("profile1")));
        assertThat(profiles.get(1), is(equalTo("profile2")));
    }

    @Test
    void shouldGetProfileDirectory() throws IOException {
        // Given
        Path path = Files.createTempDirectory("fx-profiles-test2");
        Path p1 = Files.createDirectory(path.resolve("6jkd903j.profile1"));
        FirefoxProfileManager fpm = new FirefoxProfileManager();
        fpm.setProfilesDirectory(path);

        // When
        Path f = fpm.getProfileDirectory("profile1");

        // Then
        assertThat(p1.toString(), is(equalTo(f.toString())));
    }

    @Test
    void shouldReturnNullIfNoProfileDirectory() throws IOException {
        // Given
        Path path = Files.createTempDirectory("fx-profiles-test3");
        Files.createDirectory(path.resolve("6jkd903j.profile1"));
        FirefoxProfileManager fpm = new FirefoxProfileManager();
        fpm.setProfilesDirectory(path);

        // When
        Path f = fpm.getProfileDirectory("profile");

        // Then
        assertThat(f, is(nullValue()));
    }

    @Test
    void shouldCreateProfile() throws IOException {
        // Given
        Path path = Files.createTempDirectory("fx-profiles-test4");
        Runtime runtime = mock(Runtime.class);
        Process process = mock(Process.class);
        given(runtime.exec(any(String[].class))).willReturn(process);

        FirefoxProfileManager fpm = new FirefoxProfileManager();
        fpm.setProfilesDirectory(path);
        fpm.setRuntime(runtime);

        // When
        fpm.getOrCreateProfile("profile1");

        // Then
        verify(runtime, times(1)).exec(any(String[].class));
    }

    @Test
    void shouldNotCreateExistingProfile() throws IOException {
        // Given
        Path path = Files.createTempDirectory("fx-profiles-test5");
        Path pPath = Files.createDirectory(path.resolve("jfns83ko.profile1"));
        Runtime runtime = mock(Runtime.class);
        Process process = mock(Process.class);
        given(runtime.exec(any(String[].class))).willReturn(process);

        FirefoxProfileManager fpm = new FirefoxProfileManager();
        fpm.setProfilesDirectory(path);
        fpm.setRuntime(runtime);

        // When
        Path f = fpm.getOrCreateProfile("profile1");

        // Then
        verify(runtime, times(0)).exec(any(String[].class));
        assertThat(pPath.toString(), is(equalTo(f.toString())));
    }
}
