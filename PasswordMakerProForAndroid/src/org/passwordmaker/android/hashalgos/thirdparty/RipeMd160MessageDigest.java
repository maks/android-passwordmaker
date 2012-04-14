package org.passwordmaker.android.hashalgos.thirdparty;

import java.security.MessageDigest;

public class RipeMd160MessageDigest extends MessageDigest {

	RipeMd160 hash = new RipeMd160();

	protected RipeMd160MessageDigest() {
		super("RIPEMD160");
	}

	@Override
	protected byte[] engineDigest() {
		return hash.digest();
	}

	@Override
	protected void engineReset() {
		hash.reset();
		
	}

	@Override
	protected void engineUpdate(byte arg0) {
		hash.update(arg0);
		
	}

	@Override
	protected void engineUpdate(byte[] arg0, int arg1, int arg2) {
		hash.update(arg0, arg1, arg2);
		
	}

}
