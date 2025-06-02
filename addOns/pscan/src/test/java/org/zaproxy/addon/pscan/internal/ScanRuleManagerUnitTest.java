/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.pscan.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.pscan.PassiveScanner;

/** Unit test for {@link ScanRuleManager}. */
class ScanRuleManagerUnitTest {

    private ScanRuleManager manager;

    @BeforeEach
    void setUp() throws Exception {
        manager = new ScanRuleManager();
    }

    @Test
    void shouldHaveNoScannersByDefault() {
        assertThat(manager.getScanners(), is(empty()));
    }

    @Test
    void shouldAddPassiveScanner() {
        // Given
        PassiveScanner scanner = mock(PassiveScanner.class);
        // When
        boolean scannerAdded = manager.add(scanner);
        // Then
        assertThat(manager.getScanners(), contains(scanner));
        assertThat(scannerAdded, is(equalTo(true)));
    }

    @Test
    void shouldIgnorePassiveScannerWithSameName() {
        // Given
        PassiveScanner scanner1 = mock(PassiveScanner.class);
        when(scanner1.getName()).thenReturn("PassiveScanner 1");
        PassiveScanner otherScannerWithSameName = mock(PassiveScanner.class);
        when(otherScannerWithSameName.getName()).thenReturn("PassiveScanner 1");
        // When
        manager.add(scanner1);
        boolean otherScannerAdded = manager.add(otherScannerWithSameName);
        // Then
        assertThat(manager.getScanners(), contains(scanner1));
        assertThat(otherScannerAdded, is(equalTo(false)));
    }

    @Test
    void shouldRemovePassiveScanner() {
        // Given
        PassiveScanner scanner1 = mock(PassiveScanner.class);
        manager.add(scanner1);
        PassiveScanner scanner2 = mock(TestPassiveScanner.class);
        when(scanner2.getName()).thenReturn("TestPassiveScanner");
        manager.add(scanner2);
        // When
        boolean removed = manager.remove(scanner2.getClass().getName());
        // Then
        assertThat(manager.getScanners(), contains(scanner1));
        assertThat(removed, is(equalTo(true)));
    }

    @Test
    void shouldNotRemovePassiveScannerNotAdded() {
        // Given
        PassiveScanner scanner = mock(PassiveScanner.class);
        // When
        boolean removed = manager.remove(scanner.getClass().getName());
        // Then
        assertThat(removed, is(equalTo(false)));
    }

    @Test
    void shouldSetAutoTagScanners() {
        // Given
        List<RegexAutoTagScanner> scanners = new ArrayList<>();
        RegexAutoTagScanner scanner1 = mock(RegexAutoTagScanner.class);
        when(scanner1.getName()).thenReturn("RegexAutoTagScanner 1");
        scanners.add(scanner1);
        RegexAutoTagScanner scanner2 = mock(RegexAutoTagScanner.class);
        when(scanner2.getName()).thenReturn("RegexAutoTagScanner 2");
        scanners.add(scanner2);
        // When
        manager.setAutoTagScanners(scanners);
        // Then
        assertThat(manager.getScanners(), contains(scanner1, scanner2));
    }

    @Test
    void shouldRemovePreviousAutoTagScannersButNotPassiveScanners() {
        // Given
        RegexAutoTagScanner scanner1 = mock(RegexAutoTagScanner.class);
        when(scanner1.getName()).thenReturn("RegexAutoTagScanner 1");
        manager.add(scanner1);
        PassiveScanner scanner2 = mock(PassiveScanner.class);
        when(scanner2.getName()).thenReturn("PassiveScanner 1");
        manager.add(scanner2);
        List<RegexAutoTagScanner> scanners = new ArrayList<>();
        RegexAutoTagScanner scanner3 = mock(RegexAutoTagScanner.class);
        when(scanner3.getName()).thenReturn("RegexAutoTagScanner 2");
        scanners.add(scanner3);
        // When
        manager.setAutoTagScanners(scanners);
        // Then
        assertThat(manager.getScanners(), contains(scanner2, scanner3));
    }

    @Test
    void shouldIgnoreAutoTagScannerWithSameName() {
        // Given
        List<RegexAutoTagScanner> scanners = new ArrayList<>();
        RegexAutoTagScanner scanner1 = mock(RegexAutoTagScanner.class);
        when(scanner1.getName()).thenReturn("RegexAutoTagScanner 1");
        scanners.add(scanner1);
        RegexAutoTagScanner otherScannerWithSameName = mock(RegexAutoTagScanner.class);
        when(otherScannerWithSameName.getName()).thenReturn("RegexAutoTagScanner 1");
        scanners.add(otherScannerWithSameName);
        // When
        manager.setAutoTagScanners(scanners);
        // Then
        assertThat(manager.getScanners(), contains(scanner1));
    }

    @Test
    void shouldAllowToChangeListWhileIterating() {
        // Given
        PassiveScanner scanner1 = mock(PassiveScanner.class);
        manager.add(scanner1);
        TestPassiveScanner scanner2 = mock(TestPassiveScanner.class);
        when(scanner2.getName()).thenReturn("TestPassiveScanner");
        manager.add(scanner2);
        // When / Then
        assertDoesNotThrow(
                () ->
                        manager.getScanners()
                                .forEach(
                                        e -> {
                                            manager.remove(e);
                                            manager.add(e);
                                        }));
        assertThat(manager.getScanners(), contains(scanner1, scanner2));
    }

    @Test
    void shouldAllowToChangeListWhileIteratingAfterSettingAutoTagScanners() {
        // Given
        PassiveScanner scanner1 = mock(PassiveScanner.class);
        manager.add(scanner1);
        RegexAutoTagScanner scanner2 = mock(RegexAutoTagScanner.class);
        when(scanner2.getName()).thenReturn("RegexAutoTagScanner");
        List<RegexAutoTagScanner> autoTagScanners = new ArrayList<>();
        autoTagScanners.add(scanner2);
        manager.setAutoTagScanners(autoTagScanners);
        // When / Then
        assertDoesNotThrow(
                () ->
                        manager.getScanners()
                                .forEach(
                                        e -> {
                                            if (!(e instanceof RegexAutoTagScanner)) {
                                                manager.remove(e);
                                                manager.add(e);
                                            }
                                        }));
        assertThat(manager.getScanners(), contains(scanner2, scanner1));
    }

    /** An interface to mock {@code PassiveScanner}s with different class name. */
    private static interface TestPassiveScanner extends PassiveScanner {
        // Nothing to do.
    }
}
