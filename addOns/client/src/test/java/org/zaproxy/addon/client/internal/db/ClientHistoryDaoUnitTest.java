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
package org.zaproxy.addon.client.internal.db;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mockStatic;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.zaproxy.addon.client.internal.ReportedElement;
import org.zaproxy.addon.client.internal.ReportedEvent;
import org.zaproxy.addon.client.internal.ReportedObject;

/** Unit tests for {@link ClientHistoryDao}. */
class ClientHistoryDaoUnitTest {

    private static final int OBJECT_TYPE_ELEMENT = 1;
    private static final int OBJECT_TYPE_EVENT = 2;

    private static final Date TIMESTAMP = new Date(1700000000000L);
    private static final String TYPE = "nodeAdded";
    private static final String TAG_NAME = "A";
    private static final String ELEMENT_ID = "link1";
    private static final String NODE_NAME = "A";
    private static final String URL = "https://example.com";
    private static final String XPATH = "/html/body/a";
    private static final String HREF = "https://example.com/page";
    private static final String TEXT = "Click here";

    @Test
    void shouldConvertReportedElementToEntry() {
        // Given
        String tagType = "text";
        int formId = 5;
        ReportedElement element =
                new ReportedElement(
                        TIMESTAMP,
                        TYPE,
                        TAG_NAME,
                        ELEMENT_ID,
                        NODE_NAME,
                        URL,
                        XPATH,
                        HREF,
                        TEXT,
                        tagType,
                        formId);

        // When
        ClientHistoryEntry entry = ClientHistoryDao.toEntry(element);

        // Then
        assertThat(entry.getTimestamp(), is(equalTo(TIMESTAMP.toInstant())));
        assertThat(entry.getType(), is(equalTo(TYPE)));
        assertThat(entry.getObjectType(), is(equalTo(OBJECT_TYPE_ELEMENT)));
        assertThat(entry.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(entry.getElementId(), is(equalTo(ELEMENT_ID)));
        assertThat(entry.getNodeName(), is(equalTo(NODE_NAME)));
        assertThat(entry.getUrl(), is(equalTo(URL)));
        assertThat(entry.getXpath(), is(equalTo(XPATH)));
        assertThat(entry.getHref(), is(equalTo(HREF)));
        assertThat(entry.getText(), is(equalTo(TEXT)));
        assertThat(entry.getTagType(), is(equalTo(tagType)));
        assertThat(entry.getFormId(), is(equalTo(formId)));
    }

    @Test
    void shouldConvertReportedEventToEntry() {
        // Given
        int count = 3;
        ReportedEvent event =
                new ReportedEvent(
                        TIMESTAMP,
                        TYPE,
                        TAG_NAME,
                        ELEMENT_ID,
                        NODE_NAME,
                        URL,
                        XPATH,
                        HREF,
                        TEXT,
                        count);

        // When
        ClientHistoryEntry entry = ClientHistoryDao.toEntry(event);

        // Then
        assertThat(entry.getTimestamp(), is(equalTo(TIMESTAMP.toInstant())));
        assertThat(entry.getType(), is(equalTo(TYPE)));
        assertThat(entry.getObjectType(), is(equalTo(OBJECT_TYPE_EVENT)));
        assertThat(entry.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(entry.getElementId(), is(equalTo(ELEMENT_ID)));
        assertThat(entry.getNodeName(), is(equalTo(NODE_NAME)));
        assertThat(entry.getUrl(), is(equalTo(URL)));
        assertThat(entry.getXpath(), is(equalTo(XPATH)));
        assertThat(entry.getHref(), is(equalTo(HREF)));
        assertThat(entry.getText(), is(equalTo(TEXT)));
        assertThat(entry.getCount(), is(equalTo(count)));
    }

    @Test
    void shouldConvertEntryToReportedElement() {
        // Given
        String tagType = "submit";
        int formId = 2;
        ClientHistoryEntry entry = createEntry(OBJECT_TYPE_ELEMENT);
        entry.setTagType(tagType);
        entry.setFormId(formId);

        // When
        ReportedObject result = ClientHistoryDao.toReportedObject(entry);

        // Then
        assertThat(result, is(instanceOf(ReportedElement.class)));
        ReportedElement element = (ReportedElement) result;
        assertThat(element.getTimestamp(), is(equalTo(TIMESTAMP)));
        assertThat(element.getType(), is(equalTo(TYPE)));
        assertThat(element.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(element.getId(), is(equalTo(ELEMENT_ID)));
        assertThat(element.getNodeName(), is(equalTo(NODE_NAME)));
        assertThat(element.getUrl(), is(equalTo(URL)));
        assertThat(element.getXpath(), is(equalTo(XPATH)));
        assertThat(element.getHref(), is(equalTo(HREF)));
        assertThat(element.getText(), is(equalTo(TEXT)));
        assertThat(element.getTagType(), is(equalTo(tagType)));
        assertThat(element.getFormId(), is(equalTo(formId)));
    }

    @Test
    void shouldConvertEntryToReportedEvent() {
        // Given
        int count = 7;
        ClientHistoryEntry entry = createEntry(OBJECT_TYPE_EVENT);
        entry.setCount(count);

        // When
        ReportedObject result = ClientHistoryDao.toReportedObject(entry);

        // Then
        assertThat(result, is(instanceOf(ReportedEvent.class)));
        ReportedEvent event = (ReportedEvent) result;
        assertThat(event.getTimestamp(), is(equalTo(TIMESTAMP)));
        assertThat(event.getType(), is(equalTo(TYPE)));
        assertThat(event.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(event.getId(), is(equalTo(ELEMENT_ID)));
        assertThat(event.getNodeName(), is(equalTo(NODE_NAME)));
        assertThat(event.getUrl(), is(equalTo(URL)));
        assertThat(event.getXpath(), is(equalTo(XPATH)));
        assertThat(event.getHref(), is(equalTo(HREF)));
        assertThat(event.getText(), is(equalTo(TEXT)));
        assertThat(event.getCount(), is(equalTo(count)));
    }

    @Test
    void shouldDefaultCountToZeroWhenNull() {
        // Given
        ClientHistoryEntry entry = createEntry(OBJECT_TYPE_EVENT);
        entry.setCount(null);

        // When
        ReportedObject result = ClientHistoryDao.toReportedObject(entry);

        // Then
        assertThat(result, is(instanceOf(ReportedEvent.class)));
        assertThat(((ReportedEvent) result).getCount(), is(equalTo(0)));
    }

    @Test
    void shouldDefaultFormIdToMinusOneWhenNull() {
        // Given
        ClientHistoryEntry entry = createEntry(OBJECT_TYPE_ELEMENT);
        entry.setFormId(null);

        // When
        ReportedObject result = ClientHistoryDao.toReportedObject(entry);

        // Then
        assertThat(result, is(instanceOf(ReportedElement.class)));
        assertThat(((ReportedElement) result).getFormId(), is(equalTo(-1)));
    }

    @Test
    void shouldConvertUnknownObjectTypeToReportedElement() {
        // Given
        ClientHistoryEntry entry = createEntry(99);

        // When
        ReportedObject result = ClientHistoryDao.toReportedObject(entry);

        // Then
        assertThat(result, is(instanceOf(ReportedElement.class)));
    }

    @Test
    void shouldNotThrowWhenPersistingWithNullPmf() {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            ReportedObject reportedObject =
                    new ReportedElement(
                            TIMESTAMP,
                            TYPE,
                            TAG_NAME,
                            ELEMENT_ID,
                            NODE_NAME,
                            URL,
                            XPATH,
                            HREF,
                            TEXT,
                            "text",
                            -1);

            // When / Then
            assertDoesNotThrow(() -> ClientHistoryDao.persist(reportedObject));
        }
    }

    @Test
    void shouldReturnEmptyListWhenLoadingWithNullPmf() {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            // When
            List<ReportedObject> result = ClientHistoryDao.loadAll();

            // Then
            assertThat(result, is(empty()));
        }
    }

    @Test
    void shouldNotThrowWhenDeletingWithNullPmf() {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            // When / Then
            assertDoesNotThrow(() -> ClientHistoryDao.deleteAll());
        }
    }

    private static ClientHistoryEntry createEntry(int objectType) {
        ClientHistoryEntry entry = new ClientHistoryEntry();
        entry.setTimestamp(Instant.ofEpochMilli(TIMESTAMP.getTime()));
        entry.setType(TYPE);
        entry.setObjectType(objectType);
        entry.setTagName(TAG_NAME);
        entry.setElementId(ELEMENT_ID);
        entry.setNodeName(NODE_NAME);
        entry.setUrl(URL);
        entry.setXpath(XPATH);
        entry.setHref(HREF);
        entry.setText(TEXT);
        return entry;
    }
}
