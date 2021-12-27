package com.digitalsignature.application;

import com.digitalsignature.handler.PostSignatureHandler;
import com.digitalsignature.handler.PostVerifyHandler;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import java.io.FileNotFoundException;
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
			@RequestParam("alias") String alias) {
		try{
			return new PostSignatureHandler().handleRequest(file, pfx, pfxPassword, alias);
		} catch (FileNotFoundException e) {
			return "O(s) arquivo(s) não foram encontrados.";
		} catch (IOException e) {
			return "Não foi possível ler/escrever o arquivo.";
		} catch (OperatorCreationException e) {
			return "Não foi possível localizar os arquivos de provedor de seguranca.";
		} catch (CertificateException e) {
			return "Leitura de certificado falhou";
		} catch (NoSuchAlgorithmException e) {
			return "Algoritmo selecionado é inválido.";
		} catch (KeyStoreException e) {
			return "KeyStore inválida";
		} catch (UnrecoverableKeyException e) {
			return "Chave do certificado não pode ser recuperada.";
		} catch (CMSException e) {
			return "CMS não pode completar a operação.";
		} catch (Exception e) {
			return "Ocorreu um problema não identificado.";
		}
	}

	@PostMapping("/verify")
	public String verify(@RequestParam("file") MultipartFile file) {
		try{
			return new PostVerifyHandler().handleRequest(file);
		} catch (FileNotFoundException e) {
			return "INVÁLIDO, O(s) arquivo(s) não foram encontrados.";
		} catch (IOException e) {
			return "INVÁLIDO, Não foi possível ler/escrever o arquivo.";
		} catch (CertificateException e) {
			return "INVÁLIDO, Leitura de certificado falhou";
		} catch (CMSException e) {
			return "INVÁLIDO, CMS não pode completar a operação.";
		} catch (OperatorCreationException e) {
			return "INVÁLIDO, Não foi possível localizar os arquivos de provedor de seguranca.";
		}
	}
}
