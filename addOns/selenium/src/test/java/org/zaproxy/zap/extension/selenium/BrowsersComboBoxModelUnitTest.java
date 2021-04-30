/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Unit test for {@link BrowsersComboBoxModel}. */
class BrowsersComboBoxModelUnitTest {

    private static BrowserUI FIREFOX;
    private static List<BrowserUI> browsers;

    @BeforeAll
    static void setUp() throws Exception {
        FIREFOX = new BrowserUI("Firefox", Browser.FIREFOX);

        browsers = new ArrayList<>(3);
        browsers.add(FIREFOX);
        browsers.add(new BrowserUI("Opera", Browser.OPERA));
        browsers.add(new BrowserUI("Safari", Browser.SAFARI));
    }

    @Test
    void shouldThrowExceptionWhenCreatingBrowsersComboBoxModelWithNullList() {
        // Given
        List<BrowserUI> browsers = null;
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> new BrowsersComboBoxModel(browsers));
    }

    @Test
    void shouldThrowExceptionWhenCreatingBrowsersComboBoxModelWithEmptyList() {
        // Given
        List<BrowserUI> browsers = Collections.emptyList();
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> new BrowsersComboBoxModel(browsers));
    }

    @Test
    void shouldCreateBrowsersComboBoxModelWithNonEmptyList() {
        assertDoesNotThrow(() -> new BrowsersComboBoxModel(browsers));
    }

    @Test
    void shouldGetSizeAsNumberOfBrowsersPassedInConstructor() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When
        int retrievedSize = browsersComboBoxModel.getSize();
        // Then
        assertThat(retrievedSize, is(equalTo(browsers.size())));
    }

    @Test
    void shouldGetElementsAtSamePositionAsBrowsersPassedInConstructor() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        for (int index = 0; index < browsers.size(); index++) {
            // When
            BrowserUI retrievedItem = browsersComboBoxModel.getElementAt(index);
            // Then
            assertThat(retrievedItem, is(equalTo(browsers.get(index))));
        }
    }

    @Test
    void shouldGetFirstItemSelectedAfterConstruction() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When
        BrowserUI selectedItem = browsersComboBoxModel.getSelectedItem();
        // Then
        assertThat(selectedItem, is(equalTo(browsers.get(0))));
    }

    @Test
    void shouldNotBeAffectedByModificationsOfListPassedInConstructor() {
        // Given
        List<BrowserUI> mutableList = new ArrayList<>(browsers);
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(mutableList);
        // When
        mutableList.clear();
        // Then
        for (int index = 0; index < browsers.size(); index++) {
            BrowserUI retrievedItem = browsersComboBoxModel.getElementAt(index);
            assertThat(retrievedItem, is(equalTo(browsers.get(index))));
        }
    }

    @Test
    void shouldThrowExceptionWhenSelectingItemWithNonBrowserUIObject() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> browsersComboBoxModel.setSelectedItem("NonBrowserUI"));
    }

    @Test
    void shouldSetSelectedItemWithBrowserUI() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When
        browsersComboBoxModel.setSelectedItem(FIREFOX);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldNotChangeSelectionWhenSettingNonContainedBrowserUI() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedItem(FIREFOX);
        // When
        browsersComboBoxModel.setSelectedItem(new BrowserUI("SomeName", Browser.CHROME));
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldThrowExceptionWhenSelectingItemWithEmptyBrowserId() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When / Then
        assertThrows(
                IllegalArgumentException.class, () -> browsersComboBoxModel.setSelectedBrowser(""));
    }

    void shouldSetSelectedItemWithBrowserId() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When
        browsersComboBoxModel.setSelectedBrowser(Browser.FIREFOX.getId());
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldNotChangeSelectionWhenSettingNonContainedBrowserId() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedItem(FIREFOX);
        // When
        browsersComboBoxModel.setSelectedBrowser(Browser.CHROME.getId());
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldNotChangeSelectionWhenUsingNonExistentBrowserId() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedItem(FIREFOX);
        // When
        browsersComboBoxModel.setSelectedBrowser("NonExistentBrowserId");
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldSetSelectedItemWithBrowser() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        // When
        browsersComboBoxModel.setSelectedBrowser(Browser.FIREFOX);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldNotChangeSelectionWhenSettingNonContainedBrowser() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedItem(FIREFOX);
        // When
        browsersComboBoxModel.setSelectedBrowser(Browser.CHROME);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(FIREFOX)));
    }

    @Test
    void shouldClearSelectionWhenSettingNullBrowserId() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedBrowser(Browser.FIREFOX);
        // When
        browsersComboBoxModel.setSelectedBrowser((String) null);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(null)));
    }

    @Test
    void shouldClearSelectionWhenSettingNullBrowser() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedBrowser(Browser.FIREFOX);
        // When
        browsersComboBoxModel.setSelectedBrowser((Browser) null);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(null)));
    }

    @Test
    void shouldClearSelectionWhenSettingNullItem() {
        // Given
        BrowsersComboBoxModel browsersComboBoxModel = new BrowsersComboBoxModel(browsers);
        browsersComboBoxModel.setSelectedBrowser(Browser.FIREFOX);
        // When
        browsersComboBoxModel.setSelectedItem(null);
        // Then
        assertThat(browsersComboBoxModel.getSelectedItem(), is(equalTo(null)));
    }
}
