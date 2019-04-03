package org.zaproxy.zap.extension.sse;

import static org.mockito.Mockito.when;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.BeforeClass;
import org.mockito.Mockito;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.I18N;

public abstract class BaseEventStreamTest {

    @BeforeClass
    public static void beforeClass() {
        // ServerSentEvent relies on this attribute to be initialized
        Constant.messages = Mockito.mock(I18N.class);
    }
    
    protected HttpMessage getMockHttpMessage() throws URIException {
        HistoryReference mockHistoryRef = Mockito.mock(HistoryReference.class);
        
        HttpRequestHeader mockReqHeader = Mockito.mock(HttpRequestHeader.class);
        when(mockReqHeader.getURI()).thenReturn(new URI("http", "example.com", "/", ""));
        
        HttpMessage mockMessage = Mockito.mock(HttpMessage.class);
        when(mockMessage.getHistoryRef()).thenReturn(mockHistoryRef);
        when(mockMessage.getRequestHeader()).thenReturn(mockReqHeader);
        
        return mockMessage;
    }
}
