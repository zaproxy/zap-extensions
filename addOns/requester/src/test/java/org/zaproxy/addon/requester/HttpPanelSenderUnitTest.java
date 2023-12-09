package org.zaproxy.addon.requester;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;


import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.requester.internal.HttpPanelSender;

class HttpPanelSenderUnitTest {

    private static final String URI = "http://example.com";
    private HttpMessage msg;

    @BeforeEach
    void init() throws IOException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI(URI, false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Test
    void shouldLowercaseheaderNames() {
        // Given
        msg.getRequestHeader().addHeader("X-Foo", "bar");
        msg.getRequestHeader().addHeader("X-Client", "Foo-bar 1.1.0");
        msg.getRequestHeader().addHeader("X-Client","Foo-not-bar 2.0");
        // When
        HttpPanelSender.testLowerCaseHeaderNames(msg);
        // Then
        assertThat(msg.getRequestHeader().getHeaders().size(), is(equalTo(3)));
        assertThat(msg.getRequestHeader().getHeaders(),
                containsInAnyOrder(new HttpHeaderField("x-foo", "bar"),
                        new HttpHeaderField("x-client", "Foo-bar 1.1.0"), new HttpHeaderField("x-client","Foo-not-bar 2.0")));
    }
}