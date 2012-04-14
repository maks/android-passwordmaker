package org.passwordmaker.android.hashalgos;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.passwordmaker.android.HashAlgo;
import org.passwordmaker.android.PwmHashAlgorithm.UnderliningHashAlgo;
import org.passwordmaker.android.PwmHashAlgorithm.UnderliningNormalHashAlgo;

public class HmacHashAlgo implements UnderliningHashAlgo {
	private UnderliningNormalHashAlgo underliningHash;
	private HashAlgo hashAlgo;

	public HmacHashAlgo(HashAlgo hashAlgo,
			UnderliningNormalHashAlgo underliningHash) {
		this.hashAlgo = hashAlgo;
		this.underliningHash = underliningHash;
	}

	@Override
	public int digestLength() {
		return this.underliningHash.digestLength();
	}

	@Override
	public int blockSize() {
		return this.underliningHash.blockSize();
	}

	@Override
	public HashAlgo getAlgo() {
		return hashAlgo;
	}

	@Override
	public byte[] getHashBlob(String key, String text) {
		final String algoName = "HMAC"
				+ underliningHash.getAlgo().getDigestName();
		try {
			final Mac mac = Mac.getInstance(algoName, "BC");
			mac.init(new SecretKeySpec(key.getBytes("UTF8"), algoName));
			mac.reset();
			mac.update(text.getBytes("UTF8"));
			return mac.doFinal();
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Invalid hash: " + algoName, e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Invalid hash " + algoName, e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid hash " + algoName, e);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Invalid hash " + algoName, e);
		}

	}

}
