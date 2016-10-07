package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CharsetMismatchScannerTest extends PassiveScannerTest {
	
	private HttpMessage msg;
	private HttpResponseHeader responseHeader;
	
	@Before
	public void before() throws URIException {
		
		HttpRequestHeader requestHeader = new HttpRequestHeader();
		requestHeader.setURI(new URI("http://does.not.matter.com"));
		
		responseHeader = mock(HttpResponseHeader.class);
		
		msg = new HttpMessage();
		msg.setRequestHeader(requestHeader);
		msg.setResponseHeader(responseHeader);
	}
	
	@Override
	protected PluginPassiveScanner createScanner() {
		return new CharsetMismatchScanner();
	}
	
	@Test
	public void shouldPassAsThereIsNoHeader() {
			
		msg.setResponseBody("not relevant");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
	
	@Test
	public void shouldPassAsThereIsNoBody() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	

		msg.setResponseBody("");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
	
	@Test
	public void shouldPassAsThereIsNoHtmlOrXml() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		
		msg.setResponseBody("not relevant");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
		
	@Test
	public void shouldPassAsThereIsNoMetaElement() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("text/html");	

		msg.setResponseBody("not relevant");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
	
	@Test
	public void shouldRaiseAlertTheBodyCharsetDoesNotMatchHeaderCharSet() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("text/html");	

		msg.setResponseBody("<META http-equiv=\"Content-Type\" content=\"text/html; charset=EUC-JP\">");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(1, alertsRaised.size());
		assertEquals("Charset Mismatch (Header Versus Meta Content-Type Charset)", alertsRaised.get(0).getAlert());
		assertEquals(-1, alertsRaised.get(0).getAlertId());
		assertEquals("", alertsRaised.get(0).getAttack());
		assertEquals(15, alertsRaised.get(0).getWascId());
	}
	
	@Test
	public void shouldPassAsTheBodyCharsetDoesMatchesHeaderCharSet() {
		when(responseHeader.getCharset()).thenReturn("euc-jp");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("text/html");	

		msg.setResponseBody("<META http-equiv=\"Content-Type\" content=\"text/html; charset=EUC-JP\">");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
	
	@Test
	public void shouldRaisAlertAsBothBodyCharsetDoNoMatcheOnLowThresHold() {
		when(responseHeader.getCharset()).thenReturn("utf-16");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("text/html");	

		msg.setResponseBody("<META http-equiv=\"Content-Type\" content=\"text/html; charset=EUC-JP\">"
				+ "<META charset=\"utf-16\">");
		rule.setDefaultLevel(AlertThreshold.LOW);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(2, alertsRaised.size());
	}	
	
	@Test
	public void shouldRaiseAlertAsTheContentTypeIsMissingFromTheContentAttribute() {
		when(responseHeader.getCharset()).thenReturn("utf-16");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("text/html");	

		msg.setResponseBody("<META charset=\"utf-16\">");
		rule.setDefaultLevel(AlertThreshold.LOW);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(1, alertsRaised.size());
		assertEquals("Charset Mismatch (Meta Content-Type Charset Missing)", alertsRaised.get(0).getAlert());
	}
	
	@Test
	public void shouldRaiseAlertTheBodyCharsetDoesNotMatchHeaderCharSetx() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("application/xhtml+xml");	

		msg.setResponseBody("<META charset=\"utf-16\">");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(1, alertsRaised.size());
		assertEquals("Charset Mismatch (Header Versus Meta Charset)", alertsRaised.get(0).getAlert());
	}
	
	@Test
	public void shouldPassAsCharsetDoesMatchHeaderCharSet() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("application/xhtml");	

		msg.setResponseBody("<META charset=\"utf-8\">");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}

	@Test
	public void shouldPassAsXMLHasSameCharsetAsHeader() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("something-not-html");
		when(responseHeader.isXml()).thenReturn(true);

		msg.setResponseBody("<?xml encoding=\"utf-8\" ?>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(0, alertsRaised.size());
	}
	
	@Test
	public void shouldRaiseAlertAsXMLHasDifferentCharsetAsHeader() {
		when(responseHeader.getCharset()).thenReturn("utf-8");	
		when(responseHeader.getHeader(HttpHeader.CONTENT_TYPE)).thenReturn("something-not-html");
		when(responseHeader.isXml()).thenReturn(true);

		msg.setResponseBody("<?xml encoding=\"utf-16\" ?>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertEquals(1, alertsRaised.size());
		assertEquals("Charset Mismatch ", alertsRaised.get(0).getAlert());
	}
}
