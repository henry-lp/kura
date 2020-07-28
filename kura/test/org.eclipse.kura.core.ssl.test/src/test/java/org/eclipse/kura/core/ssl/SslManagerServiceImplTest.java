/*******************************************************************************
 * Copyright (c) 2017, 2019 Eurotech and/or its affiliates and others
 *
 *   All rights reserved. This program and the accompanying materials
 *   are made available under the terms of the Eclipse Public License v1.0
 *   which accompanies this distribution, and is available at
 *   http://www.eclipse.org/legal/epl-v10.html
 ******************************************************************************/
package org.eclipse.kura.core.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import org.eclipse.kura.KuraErrorCode;
import org.eclipse.kura.KuraException;
import org.eclipse.kura.core.testutil.TestUtil;
import org.eclipse.kura.crypto.CryptoService;
import org.eclipse.kura.system.SystemService;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;

public class SslManagerServiceImplTest {

    private static final String CERT_FILE_PATH = "target/test-classes/cert";
    private static final String KEY_STORE_PATH = "target/key.store";
    private static final String KEY_STORE_2_PATH = "target/key2.store";
    private static final char[] KEY_STORE_PASS = "pass".toCharArray();

    private void setupDefaultKeystore()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        // create a new keystore each time the tests should run

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, KEY_STORE_PASS);
        }
    }

    @Test(expected = KeyStoreException.class)
    public void testActivateNoKeystore()
            throws InterruptedException, NoSuchFieldException, GeneralSecurityException, IOException {
        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = mock(CryptoService.class);
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn("testPassword".toCharArray());

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", "target/key1.store");
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        verify(cs, times(0)).getKeyStorePassword("target/key1.store");

        svc.getSSLSocketFactory();
    }

    @Test
    public void testActivateFirstBootDefaultFromKuraProps() throws Throwable {

        char[] keystorePassword = "testPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(keystorePassword);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        synchronized (lock) {
            lock.wait(20000);
        }

        verify(ccMock, times(1)).getServiceReference();

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));

        svc.deactivate(ccMock);
    }

    @Test
    public void testActivateFirstBootDefaultFromKuraPropsAndUpdate() throws Throwable {

        char[] keystorePassword = "testPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(keystorePassword);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        synchronized (lock) {
            lock.wait(20000);
        }

        verify(ccMock, times(1)).getServiceReference();

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));

        properties.put("ssl.keystore.password", "updatedPassword");
        svc.updated(properties);

        assertTrue(Arrays.equals("updatedPassword".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));
    }

    @Test(expected = IOException.class)
    public void testActivateFirstBootDefaultFromKuraPropsAndUpdateFailPersistCryptoService() throws Throwable {

        char[] keystorePassword = "testPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(keystorePassword);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        synchronized (lock) {
            lock.wait(20000);
        }

        verify(ccMock, times(1)).getServiceReference();

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));

        properties.put("ssl.keystore.password", "passwordThatFailsToPersist");
        svc.updated(properties);

        svc.getSSLSocketFactory();
    }

    @Test(expected = IOException.class)
    public void testActivateFirstBootDefaultFromKuraPropsFailIfKeystoreChanged() throws Throwable {

        char[] keystorePassword = "testPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(keystorePassword);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        synchronized (lock) {
            lock.wait(20000);
        }

        verify(ccMock, times(1)).getServiceReference();

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));

        svc.deactivate(ccMock);

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        properties.put("ssl.keystore.password", new String(cs.getKeyStorePassword(KEY_STORE_PATH)));
        svc.activate(ccMock, properties);

        svc.getSSLSocketFactory();
    }

    @Test
    public void testActivateFirstBootDefaultFromCrypto() throws Throwable {

        char[] keystorePassword = "cryptoPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        synchronized (lock) {
            lock.wait(20000);
        }

        verify(ccMock, times(1)).getServiceReference();

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));
        assertFalse(Arrays.equals(keystorePassword, cs.getKeyStorePassword(KEY_STORE_PATH)));

        svc.deactivate(ccMock);
    }

    @Test(expected = IOException.class)
    public void testActivateFirstBootDefaultInvalid() throws Throwable {

        char[] keystorePassword = "wrongPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation and deactivation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        final Object lock = new Object();

        doAnswer(invocation -> {
            synchronized (lock) {
                lock.notifyAll();
            }

            throw new NullPointerException("test"); // break the scheduler loop
        }).when(ccMock).getServiceReference(); // called during changeDefaultKeystorePassword()

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        assertFalse(Arrays.equals("changeit".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));
        assertTrue(Arrays.equals("cryptoPassword".toCharArray(), cs.getKeyStorePassword(KEY_STORE_PATH)));

        svc.getSSLSocketFactory();
    }

    private CryptoService getBasicCryptoServiceImpl() throws KuraException {
        CryptoService result = new CryptoService() {

            private final Properties props = new Properties();

            @Override
            public String sha1Hash(String s) throws NoSuchAlgorithmException, UnsupportedEncodingException {
                throw new UnsupportedOperationException();
            }

            @Override
            public void setKeyStorePassword(String keyStorePath, String password) throws IOException {
                this.props.put(keyStorePath, password);
            }

            @Override
            public void setKeyStorePassword(String keyStorePath, char[] password) throws KuraException {
                if (Arrays.equals(password, "passwordThatFailsToPersist".toCharArray())) {
                    throw new KuraException(null);
                }
                this.props.put(keyStorePath, new String(password));
            }

            @Override
            public boolean isFrameworkSecure() {
                return false;
            }

            @Override
            public char[] getKeyStorePassword(String keyStorePath) {
                String persistedPassword = this.props.getProperty(keyStorePath);
                if (persistedPassword != null) {
                    return persistedPassword.toCharArray();
                }

                return null;
            }

            @Override
            public String encryptAes(String value) throws NoSuchAlgorithmException, NoSuchPaddingException,
                    InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
                throw new UnsupportedOperationException();
            }

            @Override
            public char[] encryptAes(char[] value) throws KuraException {
                throw new UnsupportedOperationException();
            }

            @Override
            public String encodeBase64(String stringValue)
                    throws NoSuchAlgorithmException, UnsupportedEncodingException {
                throw new UnsupportedOperationException();
            }

            @Override
            public String decryptAes(String encryptedValue) throws NoSuchAlgorithmException, NoSuchPaddingException,
                    InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
                throw new UnsupportedOperationException();
            }

            @Override
            public char[] decryptAes(char[] encryptedValue) throws KuraException {
                return encryptedValue;
            }

            @Override
            public String decodeBase64(String encodedValue)
                    throws NoSuchAlgorithmException, UnsupportedEncodingException {
                throw new UnsupportedOperationException();
            }
        };

        result.setKeyStorePassword(KEY_STORE_PATH, "cryptoPassword".toCharArray());
        return result;
    }

    @Test
    public void testUpdatePassFailures() throws KuraException, NoSuchFieldException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        // test password failures during update
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        when(csMock.decryptAes(enc)).thenThrow(new KuraException(KuraErrorCode.INVALID_PARAMETER, "test"));

        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(null);

        AtomicBoolean visited = new AtomicBoolean(false);
        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                visited.set(true);
            }
        };

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.updated(properties);

        assertTrue(visited.get());
    }

    @Test
    public void testUpdateNoPassOK() throws KuraException, NoSuchFieldException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        // test update with passwords not matching the keystore
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        char[] dec = "changeit".toCharArray();
        when(csMock.decryptAes(enc)).thenReturn(dec);

        char[] enc2 = "passs".toCharArray();
        char[] dec2 = "changeitt".toCharArray();
        when(csMock.decryptAes(enc2)).thenReturn(dec2);

        char[] origPass = "passs".toCharArray();
        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(origPass);

        AtomicBoolean visited = new AtomicBoolean(false);
        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                visited.set(true);
            }
        };

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.updated(properties);

        assertTrue(visited.get());

        verify(csMock, times(0)).setKeyStorePassword(anyString(), (char[]) anyObject());
    }

    @Test
    public void testUpdateSamePass() throws KuraException, NoSuchFieldException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        // test update with same old and new passwords
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        char[] dec = "pass".toCharArray();
        when(csMock.decryptAes(enc)).thenReturn(dec);

        char[] origPass = "pass".toCharArray();
        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(origPass);

        AtomicBoolean visited = new AtomicBoolean(false);
        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                visited.set(true);
            }
        };

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.updated(properties);

        assertTrue(visited.get());

        verify(csMock, times(1)).setKeyStorePassword(anyString(), (char[]) anyObject());
    }

    @Test
    public void testUpdateKeystorePathAndPassword() throws Throwable {

        char[] keystorePassword = "cryptoPassword".toCharArray();

        KeyStore store = KeyStore.getInstance("jks");

        store.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_PATH)) {
            store.store(os, keystorePassword);
        }

        // activation

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService cs = getBasicCryptoServiceImpl();
        svc.setCryptoService(cs);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);
        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "changeit");

        svc.activate(ccMock, properties);

        char[] keystorePassword2 = "userPassword".toCharArray();

        KeyStore store2 = KeyStore.getInstance("jks");

        store2.load(null, null);

        try (OutputStream os = new FileOutputStream(KEY_STORE_2_PATH)) {
            store2.store(os, keystorePassword);
        }

        properties.put("ssl.default.trustStore", KEY_STORE_2_PATH);
        properties.put("ssl.keystore.password", new String(keystorePassword2));

        svc.updated(properties);

        assertNotNull(svc.getSSLSocketFactory());

    }

    @Test
    public void testUpdateKeyEntiesPasswords() throws Throwable {
        // test keystore password update
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        // install a new private key and check it's really there

        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(1024);
        KeyPair pair = gen.generateKeyPair();
        Key key = pair.getPrivate();
		try (java.io.InputStream is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.CERT_FILE_PATH)) {
			java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(is);
			is.close();
			java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{ certificate };
			java.security.KeyStore store = java.security.KeyStore.getInstance("jks");
			is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PATH);
			store.load(is, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
			is.close();
			java.lang.String alias = "kuraTestAlias";
			store.setKeyEntry(alias, key, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS, chain);
			org.junit.Assert.assertTrue(store.isKeyEntry(alias));
			store.getKey(alias, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
			// update KS password
			char[] newPass = "new password".toCharArray();
			org.eclipse.kura.core.testutil.TestUtil.invokePrivate(svc, "updateKeyEntiesPasswords", store, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS, newPass);
			org.junit.Assert.assertTrue(store.isKeyEntry(alias));// key is still in there

			try {
				store.getKey(alias, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
				org.junit.Assert.fail("Old password shouldn't work anymore.");
			} catch (java.security.UnrecoverableKeyException e) {
				// expected
			}
			store.getKey(alias, newPass);
		}
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetSSLSocketFactory()
            throws KuraException, NoSuchFieldException, GeneralSecurityException, IOException {
        // test preparation of an SslSocketFactory
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        char[] dec = "pass".toCharArray();
        when(csMock.decryptAes(enc)).thenReturn(dec);

        char[] origPass = "pass".toCharArray();
        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(origPass);

        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                // OK
            }
        };

        ComponentContext ccMock = mock(ComponentContext.class);

        BundleContext bcMock = mock(BundleContext.class);
        when(ccMock.getBundleContext()).thenReturn(bcMock);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.activate(ccMock, properties);

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        SSLSocketFactory factory = svc.getSSLSocketFactory();

        Map<ConnectionSslOptions, SSLContext> sslContexts = (Map<ConnectionSslOptions, SSLContext>) TestUtil
                .getFieldValue(svc, "sslContexts");

        assertNotNull(factory);
        assertEquals(1, sslContexts.size());
        assertEquals(factory, sslContexts.values().iterator().next().getSocketFactory());

        svc.updated(properties);

        Map<ConnectionSslOptions, SSLContext> updatedSslContexts = (Map<ConnectionSslOptions, SSLContext>) TestUtil
                .getFieldValue(svc, "sslContexts");
        assertNotNull(updatedSslContexts);
        assertEquals(0, updatedSslContexts.size());
    }

    @Test
    public void testPrivateKey() throws Throwable {
        // test key installation
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        char[] dec = "pass".toCharArray();
        when(csMock.decryptAes(enc)).thenReturn(dec);

        char[] origPass = "pass".toCharArray();
        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(origPass);

        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                // OK
            }
        };

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        Map<ConnectionSslOptions, SSLContext> sslContexts = new ConcurrentHashMap<>();
        TestUtil.setFieldValue(svc, "sslContexts", sslContexts);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.updated(properties);

        // install a new private key and check it's really there

        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(1024);
        KeyPair pair = gen.generateKeyPair();
        Key key = pair.getPrivate();
		try (java.io.InputStream is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.CERT_FILE_PATH)) {
			java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(is);
			is.close();
			java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{ certificate };
			java.lang.String alias = "kuraTestAlias";
			svc.installPrivateKey(alias, ((java.security.PrivateKey) (key)), org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS, chain);
			java.security.KeyStore store = java.security.KeyStore.getInstance("jks");
			is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PATH);
			store.load(is, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
			is.close();
			org.junit.Assert.assertTrue(store.isKeyEntry(alias));
			// install another private key and check that getKeyStore only returns one, if alias is specified
			pair = gen.generateKeyPair();
			key = pair.getPrivate();
			svc.installPrivateKey("secondKey", ((java.security.PrivateKey) (key)), org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS, chain);
			java.security.KeyStore ks = ((java.security.KeyStore) (org.eclipse.kura.core.testutil.TestUtil.invokePrivate(svc, "getKeyStore", org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PATH, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS, alias)));
			org.junit.Assert.assertNotNull(ks);
			org.junit.Assert.assertTrue(ks.containsAlias(alias));
			java.util.Enumeration<java.lang.String> aliases = ks.aliases();// all lowercase aliases???

			org.junit.Assert.assertNotNull(aliases);
			java.util.List<java.lang.String> aliasList = new java.util.ArrayList<>();// only for size

			while (aliases.hasMoreElements()) {
				aliasList.add(aliases.nextElement());
			} 
			org.junit.Assert.assertEquals(1, aliasList.size());
		}
    }

    @Test
    public void testCertificates() throws NoSuchFieldException, GeneralSecurityException, IOException, KuraException {
        // test working with certificates
        setupDefaultKeystore();

        SslManagerServiceImpl svc = new SslManagerServiceImpl();

        CryptoService csMock = mock(CryptoService.class);
        svc.setCryptoService(csMock);

        SystemService ssMock = mock(SystemService.class);
        svc.setSystemService(ssMock);

        when(ssMock.getJavaKeyStorePassword()).thenReturn(new char[0]);

        char[] enc = "pass".toCharArray();
        char[] dec = "pass".toCharArray();
        when(csMock.decryptAes(enc)).thenReturn(dec);

        char[] origPass = "pass".toCharArray();
        when(csMock.getKeyStorePassword(KEY_STORE_PATH)).thenReturn(origPass);

        SslServiceListeners listener = new SslServiceListeners(null) {

            @Override
            public void onConfigurationUpdated() {
                // OK
            }
        };

        TestUtil.setFieldValue(svc, "sslServiceListeners", listener);

        Map<ConnectionSslOptions, SSLContext> sslContexts = new ConcurrentHashMap<>();
        TestUtil.setFieldValue(svc, "sslContexts", sslContexts);

        Map<String, Object> properties = new HashMap<>();
        properties.put("ssl.default.protocol", "TLSv1");
        properties.put("ssl.default.trustStore", KEY_STORE_PATH);
        properties.put("ssl.hostname.verification", "true");
        properties.put("ssl.keystore.password", "pass");

        svc.updated(properties);

        KeyStore store = KeyStore.getInstance("jks");
        store.load(is, KEY_STORE_PASS);
        is.close();

        // add a certificate
        X509Certificate[] certificates = svc.getTrustCertificates();

        org.junit.Assert.assertEquals(0, certificates.length);
		try (java.io.InputStream is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.CERT_FILE_PATH)) {
			java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(is);
			is.close();
			java.lang.String alias = "kura";
			svc.installTrustCertificate(alias, ((java.security.cert.X509Certificate) (certificate)));
			// does service return the new cert?
			java.security.cert.X509Certificate[] tcs = svc.getTrustCertificates();
			org.junit.Assert.assertEquals(1, tcs.length);
			java.security.cert.X509Certificate cert = tcs[0];
			org.junit.Assert.assertEquals(java.math.BigInteger.valueOf(0x4afb9c19), cert.getSerialNumber());
			// is it really in the keystore as well
			is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PATH);
			store.load(is, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
			is.close();
			cert = ((java.security.cert.X509Certificate) (store.getCertificate(alias)));
			org.junit.Assert.assertNotNull(cert);
			org.junit.Assert.assertEquals(java.math.BigInteger.valueOf(0x4afb9c19), cert.getSerialNumber());
			javax.security.auth.x500.X500Principal issuer = cert.getIssuerX500Principal();
			java.lang.String rfcNames = issuer.getName();
			org.junit.Assert.assertEquals("CN=kura", rfcNames);
			// delete the certificate
			svc.deleteTrustCertificate(alias);
			// does service stil return the deleted cert?
			tcs = svc.getTrustCertificates();
			org.junit.Assert.assertEquals(0, tcs.length);
			// is it really not in the keystore enymore
			is = new java.io.FileInputStream(org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PATH);
			store.load(is, org.eclipse.kura.core.ssl.SslManagerServiceImplTest.KEY_STORE_PASS);
			is.close();
			org.junit.Assert.assertFalse(store.isCertificateEntry(alias));
		}
    }
}
