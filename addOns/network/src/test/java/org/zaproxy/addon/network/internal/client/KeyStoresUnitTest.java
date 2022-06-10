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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link KeyStores}. */
class KeyStoresUnitTest {

    private KeyStores keyStores;

    @BeforeEach
    void setUp() throws Exception {
        keyStores = new KeyStores();
    }

    @Test
    void shouldNotHaveActiveCertificateByDefault() {
        assertThat(keyStores.getActiveCertificate(), is(nullValue()));
    }

    @Test
    void shouldSetActiveCertificate() {
        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        // When
        keyStores.setActiveCertificate(certificate);
        // Then
        assertThat(keyStores.getActiveCertificate(), is(sameInstance(certificate)));
    }

    @Test
    void shouldResetActiveCertificate() {

        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        // When
        keyStores.setActiveCertificate(certificate);
        keyStores.setActiveCertificate(null);
        // Then
        assertThat(keyStores.getActiveCertificate(), is(nullValue()));
    }

    @Test
    void shouldInvalidateSessionCertificateOnReset() {

        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        // When
        keyStores.setActiveCertificate(certificate);
        keyStores.setActiveCertificate(null);
        // Then
        verify(certificate).invalidateSession();
    }

    @Test
    void shouldNotifyChangeListenersOnActiveCertificateSet() {
        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        keyStores.addChangeListener(listener1);
        keyStores.addChangeListener(listener2);
        // When
        keyStores.setActiveCertificate(certificate);
        // Then
        verify(listener1).stateChanged(any(ChangeEvent.class));
        verify(listener2).stateChanged(any(ChangeEvent.class));
    }

    @Test
    void shouldNotNotifyChangeListenersOnSameActiveCertificateSet() {
        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        keyStores.addChangeListener(listener1);
        keyStores.addChangeListener(listener2);
        // When
        keyStores.setActiveCertificate(certificate);
        keyStores.setActiveCertificate(certificate);
        // Then
        verify(listener1, times(1)).stateChanged(any(ChangeEvent.class));
        verify(listener2, times(1)).stateChanged(any(ChangeEvent.class));
    }

    @Test
    void shouldNotifyChangeListenersOnDifferentActiveCertificateSet() {
        // Given
        CertificateEntry certificate1 = mock(CertificateEntry.class);
        CertificateEntry certificate2 = mock(CertificateEntry.class);
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        keyStores.addChangeListener(listener1);
        keyStores.addChangeListener(listener2);
        // When
        keyStores.setActiveCertificate(certificate1);
        keyStores.setActiveCertificate(certificate2);
        // Then
        verify(listener1, times(2)).stateChanged(any(ChangeEvent.class));
        verify(listener2, times(2)).stateChanged(any(ChangeEvent.class));
    }

    @Test
    void shouldNotifyChangeListenersOnActiveCertificateReset() {
        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        keyStores.addChangeListener(listener1);
        keyStores.addChangeListener(listener2);
        // When
        keyStores.setActiveCertificate(certificate);
        keyStores.setActiveCertificate(null);
        // Then
        verify(listener1, times(2)).stateChanged(any(ChangeEvent.class));
        verify(listener2, times(2)).stateChanged(any(ChangeEvent.class));
    }

    @Test
    void shouldRemoveChangeListener() {
        // Given
        CertificateEntry certificate = mock(CertificateEntry.class);
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        keyStores.addChangeListener(listener1);
        keyStores.addChangeListener(listener2);
        // When
        keyStores.removeChangeListener(listener2);
        keyStores.setActiveCertificate(certificate);
        // Then
        verify(listener1).stateChanged(any(ChangeEvent.class));
        verifyNoInteractions(listener2);
    }
}
