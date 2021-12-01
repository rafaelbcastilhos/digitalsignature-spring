package com.brytecnologia.application;

import com.brytecnologia.handler.PostSignatureHandler;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@RestController
public class ApiController {
	@GetMapping("/")
	public String index() {
		return "Greetings from Spring Boot!";
	}

	@PostMapping("/signature")
	public String signature(
			@RequestParam("file") MultipartFile file,
			@RequestParam("pfx") MultipartFile pfx,
			@RequestParam("pfxPassword") String pfxPassword,
			@RequestParam("alias") String alias)
			throws UnrecoverableKeyException, CertificateException,
			IOException, KeyStoreException, NoSuchAlgorithmException,
			OperatorCreationException, CMSException {
		return new PostSignatureHandler().handleRequest(file, pfx, pfxPassword, alias);
	}

	@PostMapping("/verify")
	public String verify(){
		return "Post Verify";
	}
}
