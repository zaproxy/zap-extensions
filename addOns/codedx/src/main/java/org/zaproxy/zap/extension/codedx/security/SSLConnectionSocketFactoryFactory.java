/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.codedx.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.zaproxy.zap.extension.codedx.CodeDxExtension;


public class SSLConnectionSocketFactoryFactory {

	private static Map<String, SSLConnectionSocketFactory> dialogFactoriesByHost = new HashMap<>();
	private static Map<String, SSLConnectionSocketFactory> fingerprintFactoriesByHost = new HashMap<>();

	/**
	 * Returns a SSLConnectionSocketFactory for the given host. When a SSL
	 * connection is created with the returned socket factory, if the server's
	 * certificate appears to be invalid, the user will be prompted to either
	 * reject temporarily accept, or permanently accept the certificate.
	 * Permanently accepted certificates will be stored in a
	 * <code>.truststore</code> file so the user won't need to prompted again
	 * for the same host.
	 * 
	 * @param host The host (URL component) that the socket factory will be used
	 *             to connect to
	 * @param extension
	 * @return A socket factory for the given host
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static SSLConnectionSocketFactory getFactory(
		String host,
		CodeDxExtension extension
	) throws IOException, GeneralSecurityException {
		SSLConnectionSocketFactory instance = dialogFactoriesByHost.get(host);
		if (instance == null) {
			initializeFactory(host, extension, null, false);
			return dialogFactoriesByHost.get(host);
		} else {
			return instance;
		}
	}

	/**
	 * Returns a SSLConnectionSocketFactory for the given host. When a SSL
	 * connection is created with the returned socket factory, if the server's
	 * certificate appears to be invalid, the user will be prompted to either
	 * reject temporarily accept, or permanently accept the certificate.
	 * Permanently accepted certificates will be stored in a
	 * <code>.truststore</code> file so the user won't need to prompted again
	 * for the same host.
	 *
	 * @param host The host (URL component) that the socket factory will be used
	 *             to connect to
	 * @param extension
	 * @param fingerprint Expected SHA1 fingerprint of an invalid certificate
	 * @param acceptPermanently
	 * @return A socket factory for the given host
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static SSLConnectionSocketFactory getFactory(
		String host,
		CodeDxExtension extension,
		String fingerprint,
		boolean acceptPermanently
	) throws IOException, GeneralSecurityException {
		SSLConnectionSocketFactory instance = fingerprintFactoriesByHost.get(host);
		if (instance == null) {
			initializeFactory(host, extension, fingerprint, acceptPermanently);
			return fingerprintFactoriesByHost.get(host);
		} else {
			return instance;
		}
	}

	/**
	 * Determines the location for the <code>truststore</code> file for the
	 * given host. Each {@link SSLConnectionSocketFactory} returned by
	 * {@link #initializeFactory(String, CodeDxExtension, String, boolean)}
	 * needs to have a file to store user-accepted invalid certificates;
	 * these files will be stored in the user's OS-appropriate "appdata"
	 * directory.
	 * 
	 * @param host A URL hostname, e.g. "www.google.com"
	 * @return The file where the trust store for the given host should be
	 *         stored
	 */
	private static File getTrustStoreForHost(String host) {
		String OS = System.getProperty("os.name").toUpperCase();
		Path env;
		if (OS.contains("WIN")){
			env = Paths.get(System.getenv("APPDATA"),"Code Dx","ZAP");
		}
		else if (OS.contains("MAC")){
			env = Paths.get(System.getProperty("user.home"),"Library","Application Support","Code Dx","ZAP");
		}
		else if (OS.contains("NUX")){
			env = Paths.get(System.getProperty("user.home"),".codedx","zap");
		}
		else{
			env = Paths.get(System.getProperty("user.dir"),"codedx","zap");
		}
		
		File keystoreDir = new File(env.toFile(),".usertrust");
		keystoreDir.mkdirs();

		// Host may only contain alphanumerics, dash, and dot.
		// Replace anything else with an underscore.
		String safeHost = host.replaceAll("[^a-zA-Z0-9\\-\\.]", "_");

		// <pluginstate>/.usertrust/<hostname>.truststore
		return new File(keystoreDir, safeHost + ".truststore");
	}
	
	/**
	 * Creates a new SSLConnectionSocketFactory with the behavior described in
	 * {@link #getFactory(String, CodeDxExtension)}. Instead of returning, this
	 * method registers the factory instance to the <code>factoriesByHost<code>
	 * map, as well as registering its <code>ExtraCertManager</code> to the
	 * <code>certManagersByHost</code> map. The cert manager registration is
	 * important in order to detect and purge trusted certificates on a per-host
	 * basis.
	 * 
	 * @param host
	 * @param extension
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private static void initializeFactory(
		String host,
		CodeDxExtension extension,
		String fingerprint,
		boolean acceptPermanently
	) throws IOException, GeneralSecurityException {
		// set up the certificate management
		File managedKeyStoreFile = getTrustStoreForHost(host);
		ExtraCertManager certManager = new SingleExtraCertManager(managedKeyStoreFile, "u9lwIfUpaN");

		// get the default hostname verifier that gets used by the modified one
		// and the invalid cert dialog
		HostnameVerifier defaultHostnameVerifier = new DefaultHostnameVerifier();

		
		InvalidCertificateStrategy invalidCertStrat;
		if(fingerprint == null){
			invalidCertStrat = new InvalidCertificateDialogStrategy(defaultHostnameVerifier, host, extension);
		} else {
			invalidCertStrat = new InvalidCertificateFingerprintStrategy(fingerprint, acceptPermanently);
		}

		/*
		 * Set up a composite trust manager that uses the default trust manager
		 * before delegating to the "reloadable" trust manager that allows users
		 * to accept invalid certificates.
		 */
		List<X509TrustManager> trustManagersForComposite = new LinkedList<>();
		X509TrustManager systemTrustManager = getDefaultTrustManager();
		ReloadableX509TrustManager customTrustManager = new ReloadableX509TrustManager(certManager, invalidCertStrat);
		trustManagersForComposite.add(systemTrustManager);
		trustManagersForComposite.add(customTrustManager);
		X509TrustManager trustManager = new CompositeX509TrustManager(trustManagersForComposite);

		// setup the SSLContext using the custom trust manager
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, new TrustManager[] { trustManager }, null);
		// the actual hostname verifier that will be used with the socket
		// factory
		Set<String> allowedHosts = new HashSet<>();
		allowedHosts.add(host);
		HostnameVerifier modifiedHostnameVerifier = new HostnameVerifierWithExceptions(defaultHostnameVerifier, allowedHosts);
		
		SSLConnectionSocketFactory factory = new SSLConnectionSocketFactory(sslContext, modifiedHostnameVerifier);
		// Register the `factory` and the `customTrustManager` under the given
		// `host`
		if(fingerprint == null){
			dialogFactoriesByHost.put(host, factory);
		} else {
			fingerprintFactoriesByHost.put(host, factory);
		}
	}

	private static X509TrustManager getDefaultTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory defaultFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		defaultFactory.init((KeyStore) null);

		TrustManager[] managers = defaultFactory.getTrustManagers();
		for (TrustManager mgr : managers) {
			if (mgr instanceof X509TrustManager) {
				return (X509TrustManager) mgr;
			}
		}

		return null;
	}
}
