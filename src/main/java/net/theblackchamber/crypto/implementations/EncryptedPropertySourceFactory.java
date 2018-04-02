package net.theblackchamber.crypto.implementations;

import java.io.IOException;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.spring31.properties.EncryptablePropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

public class EncryptionFactory implements PropertySourceFactory {

	@Override
	public PropertySource<?> createPropertySource(String arg0, EncodedResource arg1) throws IOException {
		
		EnvironmentStringPBEConfig config = new EnvironmentStringPBEConfig();
		
		config.setPasswordEnvName("JHEN_DECRYPT_ENV_PASSWORD");
		
		StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
		encryptor.setConfig(config);
		encryptor.setProvider(new BouncyCastleProvider());
		encryptor.setAlgorithm("PBEWITHSHA256AND128BITAES-CBC-BC");
		
		Properties props = new Properties();
		props.load(arg1.getInputStream());
		EncryptablePropertiesPropertySource encPropSource =
			      new EncryptablePropertiesPropertySource("encProps", props, encryptor);
		return encPropSource;
	}
 
}
