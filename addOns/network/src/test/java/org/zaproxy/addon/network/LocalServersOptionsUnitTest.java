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
package org.zaproxy.addon.network;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link LocalServersOptions}. */
class LocalServersOptionsUnitTest {

    private static final String ALIAS_KEY = "network.localServers.aliases.alias";
    private static final String PASS_THROUGH_KEY = "network.localServers.passThroughs.passThrough";

    private LocalServersOptions options;

    @BeforeEach
    void setUp() {
        options = new LocalServersOptions();
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(options.getConfigVersionKey(), is(equalTo("network.localServers[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        assertThat(options.getPassThroughs(), is(empty()));
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(true)));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertThat(options.getPassThroughs(), is(empty()));
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveAlias(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <confirmRemove>"
                                + value
                                + "</confirmRemove>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveAlias() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <confirmRemove>not boolean</confirmRemove>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(true)));
    }

    @Test
    void shouldAddAlias() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Alias alias = new Alias("example.org", true);
        // When
        options.addAlias(alias);
        // Then
        assertThat(options.getAliases(), hasSize(1));
        assertThat(config.getProperty(ALIAS_KEY + ".name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + ".enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfAddingNullAlias() {
        // Given
        Alias alias = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addAlias(alias));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldSetAliasEnabled() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.setAliasEnabled("example.org", false);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(false)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseIfAliasNotChanged() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.setAliasEnabled("other.example.org", false);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfSettingNullNameEnabled() {
        // Given
        String name = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setAliasEnabled(name, true));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldRemoveAlias() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.removeAlias("example.org");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getAliases(), hasSize(1));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(nullValue()));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(nullValue()));
    }

    @Test
    void shouldReturnFalseIfAliasNotRemoved() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.removeAlias("other.example.org");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfRemovingNullName() {
        // Given
        String name = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removeAlias(name));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldSetAndPersistConfirmRemoveAlias() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setConfirmRemoveAlias(false);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(false)));
        assertThat(
                config.getBoolean("network.localServers.aliases.confirmRemove"),
                is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWithAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name>example.org</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getAliases(), hasSize(2));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("example.org")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
        assertThat(options.getAliases().get(1).getName(), is(equalTo("example.com")));
        assertThat(options.getAliases().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldSetAndPersistAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name>example.org</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        options.load(config);
        List<Alias> aliases = options.getAliases();
        options.load(new ZapXmlConfiguration());
        // When
        options.setAliases(aliases);
        // Then
        assertThat(options.getAliases(), hasSize(2));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("example.org")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
        assertThat(options.getAliases().get(1).getName(), is(equalTo("example.com")));
        assertThat(options.getAliases().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name></name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>valid.example.com</name>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getAliases(), hasSize(1));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("valid.example.com")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemovePassThrough(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <confirmRemove>"
                                + value
                                + "</confirmRemove>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemovePassThrough() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <confirmRemove>not boolean</confirmRemove>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(true)));
    }

    @Test
    void shouldAddPassThrough() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        // When
        options.addPassThrough(passThrough);
        // Then
        assertThat(options.getPassThroughs(), hasSize(1));

        assertThat(config.getProperty(PASS_THROUGH_KEY + ".authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + ".enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfAddingNullPassThrough() {
        // Given
        PassThrough passThrough = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addPassThrough(passThrough));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldSetPassThroughEnabled() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.setPassThroughEnabled("example.org", false);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(false)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseIfPassThroughNotChanged() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.setPassThroughEnabled("other.example.org", false);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfSettingNullAuthorityEnabled() {
        // Given
        String authority = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> options.setPassThroughEnabled(authority, true));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldRemovePassThrough() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.removePassThrough("example.org");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getPassThroughs(), hasSize(1));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(nullValue()));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(nullValue()));
    }

    @Test
    void shouldReturnFalseIfPassThroughNotRemoved() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.removePassThrough("other.example.org");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfRemovingNullAuthority() {
        // Given
        String authority = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removePassThrough(authority));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldSetAndPersistConfirmRemovePassThrough() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setConfirmRemovePassThrough(false);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(false)));
        assertThat(
                config.getBoolean("network.localServers.passThroughs.confirmRemove"),
                is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWithPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.org</authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("example.org")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getPassThroughs().get(1).getAuthority().pattern(),
                is(equalTo("example.com")));
        assertThat(options.getPassThroughs().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldSetAndPersistPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.org</authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        options.load(config);
        List<PassThrough> passThroughs = options.getPassThroughs();
        options.load(new ZapXmlConfiguration());
        // When
        options.setPassThroughs(passThroughs);
        // Then
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("example.org")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getPassThroughs().get(1).getAuthority().pattern(),
                is(equalTo("example.com")));
        assertThat(options.getPassThroughs().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority></authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>*</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>valid.example.com</authority>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getPassThroughs(), hasSize(1));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("valid.example.com")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
    }

    private static ZapXmlConfiguration configWith(String value) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<config>\n"
                        + value
                        + "\n</config>";
        try {
            config.load(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return config;
    }
}
