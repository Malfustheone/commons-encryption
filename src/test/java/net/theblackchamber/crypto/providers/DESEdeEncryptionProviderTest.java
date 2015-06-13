/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Seamus Minogue
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package net.theblackchamber.crypto.providers;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.*;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.util.KeystoreUtils;

public class DESEdeEncryptionProviderTest {

	SecretKey key192;
	SecretKey key128;
	SecretKey badKeyAlg;

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void init() {
		try {
			File keyFile = tempFolder.newFile("keystore.keys");
			
			KeyConfig config = new KeyConfig(keyFile, "TEST", 192,
					SupportedKeyGenAlgorithms.DESede, "des-key-192");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 128,
					SupportedKeyGenAlgorithms.DESede, "des-key-128");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 192,
					SupportedKeyGenAlgorithms.AES, "des-key-badalg");
			KeystoreUtils.generateSecretKey(config);

			key192 = KeystoreUtils.getSecretKey(keyFile, "des-key-192", "TEST");
			key128 = KeystoreUtils.getSecretKey(keyFile, "des-key-128", "TEST");

			assertNotNull(key192);
			assertNotNull(key128);
			

			badKeyAlg = KeystoreUtils.getSecretKey(keyFile, "des-key-badalg",
					"TEST");

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	
	@Test
	public void testBadKeyAlgorithm() {

		try {

			DESEdeEncryptionProvider aesEncryptionProviderBad = new DESEdeEncryptionProvider(
					badKeyAlg);

			fail();

		} catch (Throwable t) {
			if (!(t instanceof UnsupportedAlgorithmException)) {
				fail();
			}
		}

	}

	@Test
	public void testEncrypt() {

		try {

			DESEdeEncryptionProvider aesEncryptionProvider = new DESEdeEncryptionProvider(key192);

			assertNotNull(aesEncryptionProvider.getKey());
			
			String clear = RandomStringUtils.randomAlphabetic(20);
			Set<String> crypts = new HashSet<String>();
			for (int i = 10; i < 10; i++) {
				String cipher = aesEncryptionProvider.encrypt(clear);
				assertTrue(!crypts.contains(cipher));
				crypts.add(cipher);
			}
			
			aesEncryptionProvider = new DESEdeEncryptionProvider(key128);

			assertNotNull(aesEncryptionProvider.getKey());
			
			 clear = RandomStringUtils.randomAlphabetic(20);
			crypts = new HashSet<String>();
			for (int i = 10; i < 10; i++) {
				String cipher = aesEncryptionProvider.encrypt(clear);
				assertTrue(!crypts.contains(cipher));
				crypts.add(cipher);
			}
			
			
			try {
				aesEncryptionProvider.encrypt("");
				fail();
			} catch (MissingParameterException mpe) {

			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testDecrypt() {
		try {
			DESEdeEncryptionProvider aesEncryptionProvider = new DESEdeEncryptionProvider(key192);

			assertNotNull(aesEncryptionProvider.getKey());
			
			String clear = RandomStringUtils.randomAlphabetic(20);

			String cipher = aesEncryptionProvider.encrypt(clear);

			String decrypted = aesEncryptionProvider.decrypt(cipher);

			assertTrue(StringUtils.equals(clear, decrypted));

			try {
				aesEncryptionProvider.decrypt("");
				fail();
			} catch (MissingParameterException mpe) {

			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

}
