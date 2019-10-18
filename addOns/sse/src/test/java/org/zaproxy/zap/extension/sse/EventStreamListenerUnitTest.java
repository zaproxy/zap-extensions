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

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

/** Unit test for {@link EventStreamListener}. */
@RunWith(MockitoJUnitRunner.class)
public class EventStreamListenerUnitTest {

    @Test
    public void shouldFireProcessEventOnce() throws IOException {
        // Given
        final String event1 = "data:blub";

        // When
        BufferedReader readerMock = getReaderMockForStream(prepareEventStreamLines(event1));
        EventStreamProxy proxyMock = Mockito.mock(EventStreamProxy.class);

        EventStreamListener listener = new EventStreamListener(proxyMock, readerMock);
        listener.run();

        // Then
        verify(proxyMock, times(1)).processEvent(event1);
    }

    @Test
    public void shouldFireProcessEventMultipleTimes() throws IOException {
        // Given
        final String event1 = ": test stream";
        final String event2 = "data: first event\nid: 1";
        final String event3 = "data:second event\nid";
        final String event4 = "data:  third event";

        // When
        BufferedReader readerMock =
                getReaderMockForStream(prepareEventStreamLines(event1, event2, event3, event4));
        EventStreamProxy proxyMock = Mockito.mock(EventStreamProxy.class);

        EventStreamListener listener = new EventStreamListener(proxyMock, readerMock);
        listener.run();

        // Then
        InOrder inOrder = inOrder(proxyMock);
        inOrder.verify(proxyMock).processEvent(event1);
        inOrder.verify(proxyMock).processEvent(event2);
        inOrder.verify(proxyMock).processEvent(event3);
        inOrder.verify(proxyMock).processEvent(event4);
    }

    @Test
    public void shouldFireProcessEventOnceForComplexEvent() throws IOException {
        // Given
        final String event1 = "event: foo\ndata: first event\nid: 1";

        // When
        BufferedReader readerMock = getReaderMockForStream(prepareEventStreamLines(event1));
        EventStreamProxy proxyMock = Mockito.mock(EventStreamProxy.class);

        EventStreamListener listener = new EventStreamListener(proxyMock, readerMock);
        listener.run();

        // Then
        verify(proxyMock, times(1)).processEvent(event1);
    }

    @Test
    public void shouldNotFireProcessEventForAnIncompleteEvent() throws IOException {
        // Given
        LinkedList<String> streamLines = new LinkedList<String>();
        streamLines.add("data:blub");
        streamLines.add("id: 9982");

        // When
        BufferedReader readerMock = getReaderMockForStream(streamLines);
        EventStreamProxy proxyMock = Mockito.mock(EventStreamProxy.class);

        EventStreamListener listener = new EventStreamListener(proxyMock, readerMock);
        listener.run();

        // Then
        verify(proxyMock, never()).processEvent(Mockito.anyString());
    }

    @Test
    public void shouldFireProcessEventOnAnEmptyEvent() throws IOException {
        // Given
        LinkedList<String> streamLines = new LinkedList<String>();
        streamLines.add("");

        // When
        BufferedReader readerMock = getReaderMockForStream(streamLines);
        EventStreamProxy proxyMock = Mockito.mock(EventStreamProxy.class);

        EventStreamListener listener = new EventStreamListener(proxyMock, readerMock);
        listener.run();

        // Then
        verify(proxyMock, times(1)).processEvent("");
    }

    /**
     * Helper method that creates a Mock which returns one line of given events each time {@link
     * BufferedReader#readLine()} is called.
     *
     * @param streamLines
     * @return
     * @throws IOException
     */
    private BufferedReader getReaderMockForStream(final List<String> streamLines)
            throws IOException {
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);

        when(readerMock.readLine())
                .thenAnswer(
                        new Answer<String>() {
                            List<String> stream = streamLines;

                            @Override
                            public String answer(InvocationOnMock invocation) {
                                if (!stream.isEmpty()) {
                                    return stream.remove(0);
                                }
                                return null;
                            }
                        });
        return readerMock;
    }

    /**
     * Helper method that joins several events into one stream.
     *
     * @param events
     * @return
     */
    private List<String> prepareEventStreamLines(String... events) {
        List<String> streamLines = new LinkedList<>();
        for (String event : events) {
            streamLines.addAll(Arrays.asList(event.split("\n")));
            streamLines.add("");
        }
        return streamLines;
    }
}
