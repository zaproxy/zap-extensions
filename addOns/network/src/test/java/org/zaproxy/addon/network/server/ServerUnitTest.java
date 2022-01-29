/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.server;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link Server}. */
class ServerUnitTest {

    @Test
    void shouldStartWithLoopbackAddressAndSpecificedPort() throws IOException {
        // Given
        ServerImpl server = new ServerImpl();
        int port = 1234;
        // When
        server.start(port);
        // Then
        assertThat(server.isStarted(), is(equalTo(true)));
        assertThat(server.getAddress(), is(equalTo(Server.DEFAULT_ADDRESS)));
        assertThat(server.getPort(), is(equalTo(port)));
    }

    @Test
    void shouldStartWithAnyPortAndSpecificedAddress() throws IOException {
        // Given
        ServerImpl server = new ServerImpl();
        String address = "127.0.0.2";
        // When
        server.start(address);
        // Then
        assertThat(server.isStarted(), is(equalTo(true)));
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.getPort(), is(equalTo(Server.ANY_PORT)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, Server.MAX_PORT + 1})
    void shouldThrowForInvalidPort(int port) throws Exception {
        Exception e = assertThrows(IllegalArgumentException.class, () -> Server.validatePort(port));
        assertThat(e.getMessage(), containsString("Invalid port"));
    }

    @ParameterizedTest
    @ValueSource(ints = {Server.ANY_PORT, 1, 10, 100, Server.MAX_PORT - 1, Server.MAX_PORT})
    void shouldAcceptValidPort(int port) throws Exception {
        assertDoesNotThrow(() -> Server.validatePort(port));
    }

    private static class ServerImpl implements Server {

        private String address;
        private int port = -1;
        private boolean started;

        @Override
        public int start(String address, int port) throws IOException {
            started = true;
            this.address = address;
            this.port = port;
            return port;
        }

        @Override
        public void stop() {}

        public String getAddress() {
            return address;
        }

        public int getPort() {
            return port;
        }

        public boolean isStarted() {
            return started;
        }

        @Override
        public void close() {}
    }
}
