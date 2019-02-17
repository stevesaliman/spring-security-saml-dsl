package com.example;

import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	@Value("${security.saml2.metadata-url}")
	String metadataUrl;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		String signingAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		String signingDigest = SignatureConstants.ALGO_ID_DIGEST_SHA256;

		http
			.authorizeRequests()
				.antMatchers("/saml/**").permitAll()
				.anyRequest().authenticated()
				.and()
			.apply(saml())
				.signingAlgorithm("RSA", signingAlgorithm, signingDigest)
				.serviceProvider()
					.keyStore()
						.storeFilePath("saml/keystore.jks")
						.password("secret")
						.keyname("spring")
						.keyPassword("secret")
						.and()
				.maxAuthenticationAge(86400)
					.protocol("https")
					.hostname("localhost:8443")
					.basePath("/")
					.and()
				.identityProvider()
					.metadataFilePath(metadataUrl)
					.and();
	}
}
