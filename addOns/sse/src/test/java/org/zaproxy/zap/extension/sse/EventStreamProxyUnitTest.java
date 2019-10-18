/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sse;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedWriter;
import java.io.IOException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;

/**
 * Various examples were taken from the official documentation: {@link
 * http://www.w3.org/TR/eventsource/#processField}.
 *
 * @throws IOException
 */
@RunWith(MockitoJUnitRunner.class)
public class EventStreamProxyUnitTest extends BaseEventStreamTest {

    @BeforeClass
    public static void beforeClass() {
        // ServerSentEvent relies on this attribute to be initialized
        Constant.messages = Mockito.mock(I18N.class);
    }

    @Test
    public void shouldForwardEventWhenAllObserversReturnTrue() throws IOException {
        // Given
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // create mock observer
        EventStreamObserver mockObserver = Mockito.mock(EventStreamObserver.class);
        when(mockObserver.onServerSentEvent(Mockito.any(ServerSentEvent.class))).thenReturn(true);
        proxy.addObserver(mockObserver);

        // When
        proxy.processEvent("data:blub");

        // Then
        verify(writer, times(1)).write(Mockito.any(String.class));
    }

    @Test
    public void shouldNotForwardEventWhenAtLeastOneObserverReturnsFalse() throws IOException {
        // Given
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // create mock observer
        EventStreamObserver mockObserver = Mockito.mock(EventStreamObserver.class);
        when(mockObserver.onServerSentEvent(Mockito.any(ServerSentEvent.class))).thenReturn(false);
        proxy.addObserver(mockObserver);

        // When
        proxy.processEvent("data:blub");

        // Then
        verify(writer, never()).write(Mockito.any(String.class));
    }

    @Test
    public void shouldForwardEventWithoutObservers() throws IOException {
        // Given
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        proxy.processEvent("data:blub");

        // Then
        verify(writer, times(1)).write(Mockito.any(String.class));
    }

    @Test
    public void shouldInformObserversWithRightObjectFromSingleEventLine() throws IOException {
        // Given
        final String data = "blub";
        final String eventStream = "data:" + data;
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is(data));
        assertThat(event.getEventType(), is(""));
        assertThat(event.getId(), is(1));
        assertThat(event.getRawEvent(), is(eventStream));
    }

    @Test
    public void shouldInformObserversWithRightObjectFromMultipleEventLines() throws IOException {
        // Given
        final String eventStream = "data: YHOO\ndata: +2\ndata: 10";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is("YHOO\n+2\n10"));
    }

    @Test
    public void shouldNotIgnoreCommentsButForwardInContrastToSpecification() throws IOException {
        // Given
        final String eventStream = ": test stream";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getRawEvent(), is(": test stream"));
    }

    @Test
    public void shouldProcessLastEventId() throws IOException {
        // Given
        final String eventStream = "data: first event\nid: 2";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is("first event"));
        assertThat(event.getLastEventId(), is("2"));
        assertThat(event.getId(), is(1));
    }

    @Test
    public void shouldProcessEmptyLastEventId() throws IOException {
        // Given
        final String eventStream = "data:second event\nid";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is("second event"));
        assertThat(event.getLastEventId(), is(""));
    }

    @Test
    public void shouldRemoveFirstWhitespaceFromLineAfterColon() throws IOException {
        // Given
        final String eventStream = "data:  third event";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is(" third event"));
    }

    @Test
    public void shouldReturnEmptyObjectWhenCalledWithEmptyData() throws IOException {
        // Given
        final String eventStream = "data";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is(""));
        assertThat(event.getEventType(), is(""));
    }

    @Test
    public void shouldReturnANewlineOfData() throws IOException {
        // Given
        final String eventStream = "data\ndata";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is("\n"));
        assertThat(event.getEventType(), is(""));
    }

    @Test
    public void shouldExtractEventType() throws IOException {
        // Given
        final String eventStream = "event: server-time\ndata: 1357651178";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getData(), is("1357651178"));
        assertThat(event.getEventType(), is("server-time"));
    }

    @Test
    public void shouldExtractRetryTime() throws IOException {
        // Given
        final String eventStream = "retry: 10000";
        BufferedWriter writer = Mockito.mock(BufferedWriter.class);
        EventStreamProxy proxy = new EventStreamProxy(getMockHttpMessage(), null, writer);

        // When
        ServerSentEvent event = proxy.processEvent(eventStream);

        // Then
        assertThat(event.getReconnectionTime(), is(Integer.valueOf(10000)));
    }
}
