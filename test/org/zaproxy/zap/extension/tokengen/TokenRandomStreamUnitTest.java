package org.zaproxy.zap.extension.tokengen;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class TokenRandomStreamUnitTest {

	@Mock
	CharacterFrequencyMap characterFrequencyMap;

	TokenRandomStream stream;

	@Before
	public void setUp() throws Exception {
		stream = new TokenRandomStream(characterFrequencyMap);
	}

	@Test
	public void shouldAlwaysReturnMinusOneWhenStreamIsClosed() throws Exception {
		// Given
		stream.closeInputStream();
		// When/Then
		assertThat(stream.readByte(), is((byte) -1));
		assertThat(stream.readInt(), is(-1));
		assertThat(stream.readLong(), is(-1L));
	}

	// TODO Add more tests

}
