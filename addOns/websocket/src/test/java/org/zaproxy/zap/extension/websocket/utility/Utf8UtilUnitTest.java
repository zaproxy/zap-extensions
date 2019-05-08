package org.zaproxy.zap.extension.websocket.utility;

import org.junit.Test;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class Utf8UtilUnitTest {

	@Test
	public void shouldEncodeEmptyBytesToEmptyString() throws Exception {
		// given
		byte[] utf8 = new byte[0];
		// when
		String s = Utf8Util.encodePayloadToUtf8(utf8);
		// then
		assertThat(s, is(equalTo("")));
	}

	@Test(expected = InvalidUtf8Exception.class)
	public void shouldFailOnGivenInvalidUtf8Bytes() throws Exception {
		// given
		byte[] invalidUtf8 = new byte[] {-1};
		// when
		Utf8Util.encodePayloadToUtf8(invalidUtf8);
		// then InvalidUtf8Exception
	}

	@Test
	public void shouldEncodeSimpleUtf8Bytes() throws Exception {
		// given
		byte[] utf8 = new byte[]{49,50,51};
		// when
		String s = Utf8Util.encodePayloadToUtf8(utf8);
		// then
		assertThat(s, is(equalTo("123")));
	}

}
