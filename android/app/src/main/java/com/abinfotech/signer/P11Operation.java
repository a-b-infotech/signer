package com.abinfotech.signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Log;
import ft.mobile.bank.utils.Convection;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Connector;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

public class P11Operation {
	public static PKCS11 myPKCS11Module_;
	public static long token_ = -1L;
	public static long session_ = -1L;

	public static int isLoadlib = 0;
	static{
		try { System.loadLibrary("c++_shared"); } catch (Throwable ignored) {}
		try { System.loadLibrary("OTGPass2003_India"); } catch (Throwable ignored) {}
	}

	public static String resolvePkcs11ModulePath(Context context) {
		String defaultName = "libOTGPass2003_India.so";
		try {
			// 1. Check system nativeLibraryDir
			if (context != null && context.getApplicationInfo() != null && context.getApplicationInfo().nativeLibraryDir != null) {
				File nativeLib = new File(context.getApplicationInfo().nativeLibraryDir, defaultName);
				if (nativeLib.exists() && nativeLib.canRead()) {
					return nativeLib.getAbsolutePath();
				}
			}

			// 2. Check internal files directory
			if (context != null) {
				File internalLib = new File(context.getFilesDir(), defaultName);
				if (internalLib.exists() && internalLib.length() > 0) {
					return internalLib.getAbsolutePath();
				}

				// 3. Extract directly from APK zip file
				String pkgCodePath = context.getPackageCodePath();
				if (pkgCodePath != null) {
					ZipFile zf = new ZipFile(pkgCodePath);
					String[] candidatePaths = new String[]{
						"lib/arm64-v8a/" + defaultName,
						"lib/armeabi-v7a/" + defaultName,
						"lib/armeabi/" + defaultName
					};
					for (String candidate : candidatePaths) {
						ZipEntry ze = zf.getEntry(candidate);
						if (ze != null) {
							try (InputStream is = zf.getInputStream(ze);
								 FileOutputStream fos = new FileOutputStream(internalLib)) {
								byte[] buf = new byte[8192];
								int r;
								while ((r = is.read(buf)) != -1) {
									fos.write(buf, 0, r);
								}
								fos.flush();
							}
							internalLib.setReadable(true, false);
							internalLib.setExecutable(true, false);
							zf.close();
							return internalLib.getAbsolutePath();
						}
					}
					zf.close();
				}
			}
		} catch (Throwable t) {
			Log.w("P11Operation", "Could not resolve PKCS11 native lib path: " + t.getMessage());
		}

		if (context != null && context.getApplicationInfo() != null && context.getApplicationInfo().nativeLibraryDir != null) {
			return context.getApplicationInfo().nativeLibraryDir + "/" + defaultName;
		}
		return defaultName;
	}

	@SuppressLint("SdCardPath")
	public static boolean p11initialize( Context _context) {
		if(null == _context)
		{
			return false;
		}
		try {
			if(0 == isLoadlib || myPKCS11Module_ == null)
			{
				String path = resolvePkcs11ModulePath(_context);
				myPKCS11Module_ = PKCS11Connector.connectToPKCS11Module(path);
				isLoadlib = 1;
			}
		} catch (Throwable e1) {
			e1.printStackTrace();
			isLoadlib = 0;
			return false;
		}

		try {
			myPKCS11Module_.C_Initialize(null);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				e.printStackTrace();
				return false;
			}
		}

		return true;
	}

	public static synchronized void resetSession() {
		try {
			if (myPKCS11Module_ != null && session_ != -1) {
				try {
					myPKCS11Module_.C_CloseSession(session_);
				} catch (Throwable ignored) {}
				session_ = -1;
			}
			token_ = -1;
		} catch (Throwable ignored) {}
	}

	public static synchronized void disconnect() {
		resetSession();
		try {
			if (myPKCS11Module_ != null) {
				try {
					myPKCS11Module_.C_Finalize(null);
				} catch (Throwable ignored) {}
				myPKCS11Module_ = null;
			}
		} catch (Throwable ignored) {}
		isLoadlib = 0;
	}

	public static void p11finalize() throws PKCS11Exception {
		disconnect();
	}

	public static void p11WrapperFinalize() throws Throwable {
		myPKCS11Module_.finalize();
		isLoadlib=0;
	}

	public static void getInfo() throws PKCS11Exception {
		//CK_INFO moduleInfo = myPKCS11Module_.C_GetInfo();
		myPKCS11Module_.C_GetInfo();
	}

	public static int getSlotInfo() throws PKCS11Exception {
		long[] slotIDs = myPKCS11Module_.C_GetSlotList(true);

		if(0 == slotIDs.length)
		{
			return -1;
		}

		token_ = slotIDs[0];
		return 0;
	}

	public static CK_TOKEN_INFO getTokenInfo() throws PKCS11Exception {

		CK_TOKEN_INFO tokenInfo = null;
		if(0 != token_)
		{
			tokenInfo = myPKCS11Module_.C_GetTokenInfo(token_);
		}

		return tokenInfo;
	}

	public static void openSession() throws PKCS11Exception {
		try{
		session_ = myPKCS11Module_.C_OpenSession(token_,
				PKCS11Constants.CKF_SERIAL_SESSION
						| PKCS11Constants.CKF_RW_SESSION, null, null);
		}catch(PKCS11Exception e){
			session_ = -1;
			throw e;
		}
	}

	public static void loginUser(String password) throws PKCS11Exception {
		try {
			if (null == password)
				return;

			myPKCS11Module_.C_Login(session_, PKCS11Constants.CKU_USER,
					password.toCharArray());
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() == PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
				logout();
				loginUser(password);
			} else if (e.getErrorCode() == PKCS11Constants.CKR_PIN_INCORRECT) {
				throw e;
			} else {
				throw e;
			}
		}
	}

	public static void changePassword(String oldPassword, String newPassword) throws PKCS11Exception {
		if (null != oldPassword && null != newPassword)
		{
			try {
				if (null == oldPassword || null == newPassword)
					return;

				myPKCS11Module_.C_SetPIN(session_, oldPassword.toCharArray(), newPassword.toCharArray());
			} catch (PKCS11Exception e) {
				e.printStackTrace();
				throw e;
			}
		}
	}

	public static long[] findKeypair(int bitSize) throws PKCS11Exception {

		CK_ATTRIBUTE[] findPubKeyAttrList = new CK_ATTRIBUTE[2];
		findPubKeyAttrList[0] = new CK_ATTRIBUTE();
		findPubKeyAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findPubKeyAttrList[0].pValue = new Long(PKCS11Constants.CKO_PUBLIC_KEY);
		findPubKeyAttrList[1] = new CK_ATTRIBUTE();
		findPubKeyAttrList[1].type = PKCS11Constants.CKA_MODULUS_BITS;
		findPubKeyAttrList[1].pValue = new Long(bitSize);

		myPKCS11Module_.C_FindObjectsInit(session_, findPubKeyAttrList);
		long[] pubKeyHandle = myPKCS11Module_.C_FindObjects(session_, 1);
		myPKCS11Module_.C_FindObjectsFinal(session_);

		if(pubKeyHandle == null)
		{
			return null;
		}

		int num = pubKeyHandle.length;
		if(num <= 0)
		{
			return null;
		}

		long publicKeyHandle_ = pubKeyHandle[0];

		CK_ATTRIBUTE[] getModulusAttrList = new CK_ATTRIBUTE[1];
		getModulusAttrList[0] = new CK_ATTRIBUTE();
		getModulusAttrList[0].type = PKCS11Constants.CKA_MODULUS;
		getModulusAttrList[0].pValue = new byte[256];

		myPKCS11Module_.C_GetAttributeValue(session_, publicKeyHandle_, getModulusAttrList);

		CK_ATTRIBUTE[] priAttrTmplList = new CK_ATTRIBUTE[3];

		priAttrTmplList[0] = new CK_ATTRIBUTE();
		priAttrTmplList[0].type = PKCS11Constants.CKA_CLASS;
		priAttrTmplList[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);

		priAttrTmplList[1] = new CK_ATTRIBUTE();
		priAttrTmplList[1].type = PKCS11Constants.CKA_TOKEN;
		priAttrTmplList[1].pValue = new Boolean(PKCS11Constants.TRUE);

		priAttrTmplList[2] = new CK_ATTRIBUTE();
		priAttrTmplList[2].type = PKCS11Constants.CKA_MODULUS;
		priAttrTmplList[2].pValue = getModulusAttrList[0].pValue;

		myPKCS11Module_.C_FindObjectsInit(session_, priAttrTmplList);
		long[] priKeyHandle = myPKCS11Module_.C_FindObjects(session_, 1);
		myPKCS11Module_.C_FindObjectsFinal(session_);

		if(priKeyHandle == null	|| priKeyHandle.length == 0)
		{
			return null;
		}

		long[] keyPair = new long[2];
		keyPair[0] = pubKeyHandle[0];
		keyPair[1] = priKeyHandle[0];

		return keyPair;
	}

	public static long[] generateKeypair(int bitSize) throws PKCS11Exception {
		//myTextView.append("\n\n\nGENERATING KEYPAIR...\n");
		CK_ATTRIBUTE[] pukAttrTmplList = new CK_ATTRIBUTE[7];
		pukAttrTmplList[0] = new CK_ATTRIBUTE();
		pukAttrTmplList[0].type = PKCS11Constants.CKA_CLASS;
		pukAttrTmplList[0].pValue = new Long(PKCS11Constants.CKO_PUBLIC_KEY);
		pukAttrTmplList[1] = new CK_ATTRIBUTE();
		pukAttrTmplList[1].type = PKCS11Constants.CKA_KEY_TYPE;
		pukAttrTmplList[1].pValue = new Long(PKCS11Constants.CKK_RSA);
		pukAttrTmplList[2] = new CK_ATTRIBUTE();
		pukAttrTmplList[2].type = PKCS11Constants.CKA_SUBJECT;
		byte[] subject = "Sample RSA Key Pair".getBytes();
		pukAttrTmplList[2].pValue = subject;
		pukAttrTmplList[3] = new CK_ATTRIBUTE();
		pukAttrTmplList[3].type = PKCS11Constants.CKA_MODULUS_BITS;
		pukAttrTmplList[3].pValue = new Long(bitSize);
		pukAttrTmplList[4] = new CK_ATTRIBUTE();
		pukAttrTmplList[4].type = PKCS11Constants.CKA_ENCRYPT;
		pukAttrTmplList[4].pValue = new Boolean(PKCS11Constants.TRUE);
		pukAttrTmplList[5] = new CK_ATTRIBUTE();
		pukAttrTmplList[5].type = PKCS11Constants.CKA_TOKEN;
		pukAttrTmplList[5].pValue = new Boolean(PKCS11Constants.TRUE);
		pukAttrTmplList[6] = new CK_ATTRIBUTE();
		pukAttrTmplList[6].type = PKCS11Constants.CKA_WRAP;
		pukAttrTmplList[6].pValue = new Boolean(PKCS11Constants.TRUE);

		CK_ATTRIBUTE[] prkAttrTmplList = new CK_ATTRIBUTE[9];
		prkAttrTmplList[0] = new CK_ATTRIBUTE();
		prkAttrTmplList[0].type = PKCS11Constants.CKA_CLASS;
		prkAttrTmplList[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);
		prkAttrTmplList[1] = new CK_ATTRIBUTE();
		prkAttrTmplList[1].type = PKCS11Constants.CKA_KEY_TYPE;
		prkAttrTmplList[1].pValue = new Long(PKCS11Constants.CKK_RSA);
		prkAttrTmplList[2] = new CK_ATTRIBUTE();
		prkAttrTmplList[2].type = PKCS11Constants.CKA_SUBJECT;
		prkAttrTmplList[2].pValue = subject;
		prkAttrTmplList[3] = new CK_ATTRIBUTE();
		prkAttrTmplList[3].type = PKCS11Constants.CKA_DECRYPT;
		prkAttrTmplList[3].pValue = new Boolean(PKCS11Constants.TRUE);
		prkAttrTmplList[4] = new CK_ATTRIBUTE();
		prkAttrTmplList[4].type = PKCS11Constants.CKA_PRIVATE;
		prkAttrTmplList[4].pValue = new Boolean(PKCS11Constants.TRUE);
		prkAttrTmplList[5] = new CK_ATTRIBUTE();
		prkAttrTmplList[5].type = PKCS11Constants.CKA_SENSITIVE;
		prkAttrTmplList[5].pValue = new Boolean(PKCS11Constants.TRUE);
		prkAttrTmplList[6] = new CK_ATTRIBUTE();
		prkAttrTmplList[6].type = PKCS11Constants.CKA_TOKEN;
		prkAttrTmplList[6].pValue = new Boolean(PKCS11Constants.TRUE);
		prkAttrTmplList[7] = new CK_ATTRIBUTE();
		prkAttrTmplList[7].type = PKCS11Constants.CKA_EXTRACTABLE;
		prkAttrTmplList[7].pValue = new Boolean(PKCS11Constants.TRUE);
		prkAttrTmplList[8] = new CK_ATTRIBUTE();
		prkAttrTmplList[8].type = PKCS11Constants.CKA_UNWRAP;
		prkAttrTmplList[8].pValue = new Boolean(PKCS11Constants.TRUE);

		CK_MECHANISM genkeyMechanism_ = new CK_MECHANISM();
		genkeyMechanism_.mechanism = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
		genkeyMechanism_.pParameter = null;
		long[] objectHandles = myPKCS11Module_.C_GenerateKeyPair(session_,
				genkeyMechanism_, pukAttrTmplList, prkAttrTmplList);
		//publicKeyHandle_ = objectHandles[0];
		//privateKeyHandle_ = objectHandles[1];
		return objectHandles;
		//myTextView.append("public key handle:\n"
		//		+ Long.toString(publicKeyHandle_) + "\n");
		//myTextView.append("private key handle:\n"
		//		+ Long.toString(privateKeyHandle_) + "\n");
		//myTextView.append("FINISHED\n");
	}

	public static byte[] signData(byte[] signData, long privateKeyHandle_, long mechanism) throws PKCS11Exception {
		//myTextView.append("\n\n\nSIGNING DATA...\n");
		if (null == signData)
			return null;
		if(signData.length==0)
			return null;

		//########################
		//signData = "110000000284210000000200<?xml version=\"1.0\" encoding=\"GBK\" ?><TradeData><field name=\"支锟斤拷锟斤拷锟斤拷锟剿ｏ拷锟斤拷\" value=\"9558880200005531792\" DisplayOnScreen=\"TRUE\"/><field name=\"转锟剿斤拷锟絓" value=\"100\" DisplayOnScreen=\"TRUE\"/></TradeData>220000000048支锟斤拷锟斤拷锟斤拷锟剿ｏ拷锟斤拷:9558880200005531792转锟剿斤拷锟�:100230000000000";
		//String strSignData = "110000001045210000000965<?xml version=\"1.0\" encoding=\"UTF-8\"?><TradeData><field name=\"锟斤拷锟剿碉拷锟斤拷锟斤拷\" value=\"指锟斤拷锟剿伙拷锟斤拷锟剿碉拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷频锟斤拷\" value=\"锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟阶次讹拷锟斤拷锟斤拷\" value=\"2016-07-31\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1\" DisplayOnScreen=\"TRUE\"/><field name=\"指锟斤拷锟斤拷锟斤拷锟斤拷锟絓" value=\"锟斤拷元\" DisplayOnScreen=\"TRUE\"/><field name=\"锟角凤拷锟皆讹拷展锟斤拷\" value=\"锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"展锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷嘶锟絓" value=\"1.  锟剿猴拷:0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟秸凤拷式\" value=\"(1). 锟斤拷取 锟斤拷取锟斤拷锟斤拷:锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷录ID\" value=\"0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟结交时锟斤拷\" value=\"2016-07-30 11:44:06\" DisplayOnScreen=\"TRUE\"/></TradeData>220000000044锟斤拷确锟斤拷签锟斤拷锟斤拷锟剿碉拷协锟斤拷(锟斤拷锟斤拷锟斤拷锟斤拷)230000000000";
		//String strSignData = "110000001045210000000965<?xml version=\"1.0\" encoding=\"UTF-8\"?><TradeData><field name=\"锟斤拷锟剿碉拷锟斤拷锟斤拷\" value=\"指锟斤拷锟剿伙拷锟斤拷锟剿碉拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷频锟斤拷\" value=\"锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟阶次讹拷锟斤拷锟斤拷\" value=\"2016-07-31\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1\" DisplayOnScreen=\"TRUE\"/><field name=\"指锟斤拷锟斤拷锟斤拷锟斤拷锟絓" value=\"锟斤拷元\" DisplayOnScreen=\"TRUE\"/><field name=\"锟角凤拷锟皆讹拷展锟斤拷\" value=\"锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"展锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷嘶锟絓" value=\"\r\n1.  锟剿猴拷:0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟秸凤拷式\" value=\"\r\n(1). 锟斤拷取 锟斤拷取锟斤拷锟斤拷:锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷录ID\" value=\"0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟结交时锟斤拷\" value=\"2016-07-30 11:44:06\" DisplayOnScreen=\"TRUE\"/></TradeData>220000000044锟斤拷确锟斤拷签锟斤拷锟斤拷锟剿碉拷协锟斤拷(锟斤拷锟斤拷锟斤拷锟斤拷)230000000000";
		//String strSignData = "110000000897210000000810<?xml version=\"1.0\" encoding=\"UTF-8\"?><TradeData><field name=\"锟斤拷锟絓" value=\"123.00元\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷写锟斤拷锟絓" value=\"壹锟桔凤拷拾锟斤拷元锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷畹ノ伙拷锟斤拷锟絓" value=\"锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷薰锟剿綷" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷畹ノ伙拷撕锟絓" value=\"0200205309200001231\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷畹ノ伙拷锟斤拷锟斤拷锟斤拷锟斤拷锟絓" value=\"锟斤拷平锟斤拷支锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟秸款单位锟斤拷锟斤拷\" value=\"锟斤拷锟斤拷锟结·锟铰猴拷锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟秸款单位锟剿猴拷\" value=\"6222081208000335070\" DisplayOnScreen=\"TRUE\"/><field name=\"锟秸款单位锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"icbc\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷陆ID\" value=\"80hou0.c.0200\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟结交时锟斤拷\" value=\"2010050115061937529489315\" DisplayOnScreen=\"TRUE\"/></TradeData>220000000051锟斤拷锟�:123.00元RMB 锟剿猴拷:6222081208000335070(锟斤拷锟斤拷锟斤拷锟斤拷)230000000000";

		//#########################

		//byte[] data = signData.getBytes();
		/*
		byte[] data = null;
		try {
			data = signData.getBytes("GBK");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		//byte[] data = Convection.getUtf8Bytes(strSignData);
		//int dataLen = data.length;
		//byte[] data = signData.getBytes();


		CK_MECHANISM signatureMechanism_ = new CK_MECHANISM();
		signatureMechanism_.mechanism = mechanism;
		signatureMechanism_.pParameter = null;

		myPKCS11Module_.C_SignInit(session_, signatureMechanism_,
				privateKeyHandle_);

		byte[] signature_ = myPKCS11Module_.C_Sign(session_, signData);

		//myTextView.append("signature: \n" + byteArrayToString(signature_)
		//		+ "\nlen:" + Integer.toString(signature_.length) + "\n");
		//myTextView.append("FINISHED\n");
		return signature_;
	}

	public static void verifySignature(byte[] signData, byte[] signature_, long publicKeyHandle_, long mechanism) throws PKCS11Exception {
		//myTextView.append("\n\n\nVERIFYING SIGNATURE...\n");
		if (null == signData || null == signature_)
			return;

		//String strSignData = "110000001045210000000965<?xml version=\"1.0\" encoding=\"UTF-8\"?><TradeData><field name=\"锟斤拷锟剿碉拷锟斤拷锟斤拷\" value=\"指锟斤拷锟剿伙拷锟斤拷锟剿碉拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷频锟斤拷\" value=\"锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟阶次讹拷锟斤拷锟斤拷\" value=\"2016-07-31\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷\" value=\"1\" DisplayOnScreen=\"TRUE\"/><field name=\"指锟斤拷锟斤拷锟斤拷锟斤拷锟絓" value=\"锟斤拷元\" DisplayOnScreen=\"TRUE\"/><field name=\"锟角凤拷锟皆讹拷展锟斤拷\" value=\"锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"展锟斤拷锟斤拷锟斤拷\" value=\"1锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟斤拷锟斤拷嘶锟絓" value=\"\r\n1.  锟剿猴拷:0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟秸凤拷式\" value=\"\r\n(1). 锟斤拷取 锟斤拷取锟斤拷锟斤拷:锟斤拷锟斤拷\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷录ID\" value=\"0119000100001025238\" DisplayOnScreen=\"TRUE\"/><field name=\"锟斤拷锟斤拷锟结交时锟斤拷\" value=\"2016-07-30 11:44:06\" DisplayOnScreen=\"TRUE\"/></TradeData>220000000044锟斤拷确锟斤拷签锟斤拷锟斤拷锟剿碉拷协锟斤拷(锟斤拷锟斤拷锟斤拷锟斤拷)230000000000";
		//byte[] data = Convection.getUtf8Bytes(strSignData);
		//int dataLen = data.length;

		CK_MECHANISM signatureMechanism_ = new CK_MECHANISM();
		signatureMechanism_.mechanism = mechanism;
		signatureMechanism_.pParameter = null;
		try {
			myPKCS11Module_.C_VerifyInit(session_, signatureMechanism_,
					publicKeyHandle_);
			myPKCS11Module_.C_Verify(session_, signData, signature_);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				//myTextView.append("verification failed.\n");
				//myTextView.append("error code: " + e.getMessage() + "\n");
			}
			e.printStackTrace();
			throw e;
		}
		//myTextView.append("verification succeed.\n");
		//myTextView.append("FINISHED\n");
	}

	public static byte[] symEncryptData(String strKey, String strData, long algorithm) throws PKCS11Exception
	{
		long hSymKey=0;
		long keyType = 0;
		long keyLen = 0;

		if (null == strKey || null == strData)
			return null;

		if(algorithm == PKCS11Constants.CKM_DES_ECB
			|| algorithm == PKCS11Constants.CKM_DES_CBC)
		{
			keyType = PKCS11Constants.CKK_DES;
			keyLen = 8;
		}
		else if(algorithm == PKCS11Constants.CKM_DES3_ECB
			|| algorithm == PKCS11Constants.CKM_DES3_CBC)
		{
			//keyType = PKCS11Constants.CKK_DES3;
			keyType = PKCS11Constants.CKK_DES3;
			keyLen = 24;
		}

		byte[] symkey = Convection.hexString2Bytes(strKey);
		byte[] data = Convection.hexString2Bytes(strData);

		CK_ATTRIBUTE[] symKeyTemplateList = new CK_ATTRIBUTE[8];
		symKeyTemplateList[0] = new CK_ATTRIBUTE();
		symKeyTemplateList[0].type = PKCS11Constants.CKA_CLASS;
		symKeyTemplateList[0].pValue = new Long(PKCS11Constants.CKO_SECRET_KEY);
		symKeyTemplateList[1] = new CK_ATTRIBUTE();
		symKeyTemplateList[1].type = PKCS11Constants.CKA_KEY_TYPE;
		symKeyTemplateList[1].pValue = new Long(keyType);
		symKeyTemplateList[2] = new CK_ATTRIBUTE();
		symKeyTemplateList[2].type = PKCS11Constants.CKA_TOKEN;
		symKeyTemplateList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		symKeyTemplateList[3] = new CK_ATTRIBUTE();
		symKeyTemplateList[3].type = PKCS11Constants.CKA_PRIVATE;
		symKeyTemplateList[3].pValue = new Boolean(PKCS11Constants.FALSE);
		symKeyTemplateList[4] = new CK_ATTRIBUTE();
		symKeyTemplateList[4].type = PKCS11Constants.CKA_ENCRYPT;
		symKeyTemplateList[4].pValue = new Boolean(PKCS11Constants.TRUE);
		symKeyTemplateList[5] = new CK_ATTRIBUTE();
		symKeyTemplateList[5].type = PKCS11Constants.CKA_DECRYPT;
		symKeyTemplateList[5].pValue = new Boolean(PKCS11Constants.TRUE);
		symKeyTemplateList[6] = new CK_ATTRIBUTE();
		symKeyTemplateList[6].type = PKCS11Constants.CKA_VALUE;
		symKeyTemplateList[6].pValue = symkey;//??????????????????????
		symKeyTemplateList[7] = new CK_ATTRIBUTE();
		symKeyTemplateList[7].type = PKCS11Constants.CKA_VALUE_LEN;
		symKeyTemplateList[7].pValue = new Long(keyLen);

	    byte iv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		CK_MECHANISM ckMechanism = new CK_MECHANISM();
		ckMechanism.mechanism = algorithm;
		ckMechanism.pParameter = iv;
		long hSession =0;
		try{
			hSession = myPKCS11Module_.C_OpenSession(token_, 6,null, null);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {

			}
			e.printStackTrace();
			throw e;
		}

		try {
			hSymKey = myPKCS11Module_.C_CreateObject(hSession, symKeyTemplateList);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				//myTextView.append("encryption failed.\n");
				//myTextView.append("error code: " + e.getMessage() + "\n");
				if(hSymKey != 0)
				{
					myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
					hSymKey=0;
				}
				myPKCS11Module_.C_CloseSession(hSession);
			}
			e.printStackTrace();
			throw e;
		}

		byte[] cipher_ = null;
		try {
			myPKCS11Module_.C_EncryptInit(hSession, ckMechanism,
					hSymKey);
			cipher_ = myPKCS11Module_.C_Encrypt(hSession, data);
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				if(hSymKey != 0)
				{
					myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
					hSymKey=0;
				}
				myPKCS11Module_.C_CloseSession(hSession);
			}
			e.printStackTrace();
		}

		try {
			if(hSymKey !=0){
				myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
				hSymKey=0;
			}
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		myPKCS11Module_.C_CloseSession(hSession);
		return cipher_;
	}

	public static byte[] symDecryptData(String strKey, String strData, long algorithm) throws PKCS11Exception
	{
		long hSymKey=0;
		long keyType = 0;
		long keyLen = 0;
		if (null == strKey || null == strData)
			return null;

		if(algorithm == PKCS11Constants.CKM_DES_ECB
			|| algorithm == PKCS11Constants.CKM_DES_CBC)
		{
			keyType = PKCS11Constants.CKK_DES;
			keyLen = 8;
		}
		else if(algorithm == PKCS11Constants.CKM_DES3_ECB
			|| algorithm == PKCS11Constants.CKM_DES3_CBC)
		{
			//keyType = PKCS11Constants.CKK_DES3;
			keyType = PKCS11Constants.CKK_DES3;
			keyLen = 24;
		}

		byte[] symkey = Convection.hexString2Bytes(strKey);
		byte[] data = Convection.hexString2Bytes(strData);

		CK_ATTRIBUTE[] symKeyTemplateList = new CK_ATTRIBUTE[8];
		symKeyTemplateList[0] = new CK_ATTRIBUTE();
		symKeyTemplateList[0].type = PKCS11Constants.CKA_CLASS;
		symKeyTemplateList[0].pValue = new Long(PKCS11Constants.CKO_SECRET_KEY);
		symKeyTemplateList[1] = new CK_ATTRIBUTE();
		symKeyTemplateList[1].type = PKCS11Constants.CKA_KEY_TYPE;
		symKeyTemplateList[1].pValue = new Long(keyType);
		symKeyTemplateList[2] = new CK_ATTRIBUTE();
		symKeyTemplateList[2].type = PKCS11Constants.CKA_TOKEN;
		symKeyTemplateList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		symKeyTemplateList[3] = new CK_ATTRIBUTE();
		symKeyTemplateList[3].type = PKCS11Constants.CKA_PRIVATE;
		symKeyTemplateList[3].pValue = new Boolean(PKCS11Constants.FALSE);
		symKeyTemplateList[4] = new CK_ATTRIBUTE();
		symKeyTemplateList[4].type = PKCS11Constants.CKA_ENCRYPT;
		symKeyTemplateList[4].pValue = new Boolean(PKCS11Constants.TRUE);
		symKeyTemplateList[5] = new CK_ATTRIBUTE();
		symKeyTemplateList[5].type = PKCS11Constants.CKA_DECRYPT;
		symKeyTemplateList[5].pValue = new Boolean(PKCS11Constants.TRUE);
		symKeyTemplateList[6] = new CK_ATTRIBUTE();
		symKeyTemplateList[6].type = PKCS11Constants.CKA_VALUE;
		symKeyTemplateList[6].pValue = symkey;//??????????????????????
		symKeyTemplateList[7] = new CK_ATTRIBUTE();
		symKeyTemplateList[7].type = PKCS11Constants.CKA_VALUE_LEN;
		symKeyTemplateList[7].pValue = new Long(keyLen);

	    byte iv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		CK_MECHANISM ckMechanism = new CK_MECHANISM();
		ckMechanism.mechanism = algorithm;
		ckMechanism.pParameter = iv;
		long hSession =0;
		try{
			hSession = myPKCS11Module_.C_OpenSession(token_, 6,null, null);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
			}
			e.printStackTrace();
			throw e;
		}

		try {
			hSymKey = myPKCS11Module_.C_CreateObject(hSession, symKeyTemplateList);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				//myTextView.append("encryption failed.\n");
				//myTextView.append("error code: " + e.getMessage() + "\n");
				if(hSymKey !=0){
					myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
					hSymKey=0;
				}
				myPKCS11Module_.C_CloseSession(hSession);
			}
			e.printStackTrace();
			throw e;
		}

		byte[] cipher_ = null;
		try {
			myPKCS11Module_.C_DecryptInit(hSession, ckMechanism,
					hSymKey);
			cipher_ = myPKCS11Module_.C_Decrypt(hSession, data);
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				if(hSymKey !=0){
					myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
					hSymKey=0;
				}
				myPKCS11Module_.C_CloseSession(hSession);
			}
			e.printStackTrace();
		}

		try {
			if(hSymKey !=0){
				myPKCS11Module_.C_DestroyObject(hSession, hSymKey);
				hSymKey=0;
			}
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block

			e.printStackTrace();
		}
		myPKCS11Module_.C_CloseSession(hSession);
		return cipher_;
	}

	public static byte[] encryptData(byte[] encryptdata, long publicKeyHandle_) throws PKCS11Exception {
		//myTextView.append("\n\n\nENCRYPTING DATA...\n");
		//myTextView.append("orignal: \n" + byteArrayToString(data) + "\nlen:"
		//		+ Integer.toString(data.length) + "\n");
		CK_MECHANISM encryptMechanism_ = new CK_MECHANISM();
		encryptMechanism_.mechanism = PKCS11Constants.CKM_RSA_PKCS;
		encryptMechanism_.pParameter = null;
		byte[] cipher_=null;
		try {
			myPKCS11Module_.C_EncryptInit(session_, encryptMechanism_,
					publicKeyHandle_);
			cipher_ = myPKCS11Module_.C_Encrypt(session_, encryptdata);
		} catch (PKCS11Exception e) {
			if (e.getErrorCode() != PKCS11Constants.CKR_OK) {
				//myTextView.append("encryption failed.\n");
				//myTextView.append("error code: " + e.getMessage() + "\n");
			}
			e.printStackTrace();
			throw e;
		}
		//myTextView.append("cipher: \n" + byteArrayToString(cipher_) + "\nlen:"
		//		+ Integer.toString(cipher_.length) + "\n");
		//myTextView.append("FINISHED\n");
		return cipher_;
	}

	public static byte[] decryptData(byte[] cipher_, long privateKeyHandle_) throws PKCS11Exception {
		//myTextView.append("\n\n\nDERYPTING DATA...\n");
		byte[] plain = null;
		if (null == cipher_)
			return null;

		CK_MECHANISM encryptMechanism_ = new CK_MECHANISM();
		encryptMechanism_.mechanism = PKCS11Constants.CKM_RSA_PKCS;
		encryptMechanism_.pParameter = null;
		try {
			myPKCS11Module_.C_DecryptInit(session_, encryptMechanism_,
					privateKeyHandle_);
			plain = myPKCS11Module_.C_Decrypt(session_, cipher_);
		} catch (PKCS11Exception e) {
			//myTextView.append("decryption failed.\n");
			//myTextView.append("error code: " + e.getMessage() + "\n");
			e.printStackTrace();
			throw e;
		}
		//myTextView.append("plain: \n" + byteArrayToString(plain) + "\nlen:"
		//		+ Integer.toString(plain.length) + "\n");
		//myTextView.append("FINISHED\n");
		return plain;
	}

	public static byte[] digest(String data, long mechanism) throws PKCS11Exception {
		byte[] digest = null;

		if (null == data)
			return null;

		CK_MECHANISM Mechanism_ = new CK_MECHANISM();
		Mechanism_.mechanism = mechanism;
		Mechanism_.pParameter = null;
		try {
			myPKCS11Module_.C_DigestInit(session_, Mechanism_);
			digest = myPKCS11Module_.C_Digest(session_, data.getBytes());
		} catch (PKCS11Exception e) {
			e.printStackTrace();
			throw e;
		}
		return digest;
	}

	public static void cleanup(long[] objectHandles) throws PKCS11Exception {
		//myTextView.append("\n\n\nCLEAN UP...\n");

		if (null == objectHandles || objectHandles.length < 2)
			return;

		try {
			myPKCS11Module_.C_DestroyObject(session_, objectHandles[0]);
			myPKCS11Module_.C_DestroyObject(session_, objectHandles[1]);
		} catch (PKCS11Exception e) {
			//myTextView.append("cleaning up failed.\n");
			//myTextView.append("error code: " + e.getMessage() + "\n");
			e.printStackTrace();
			throw e;
		}

		//myTextView.append("FINISHED\n");
	}

	public static void logout() throws PKCS11Exception {
		//myTextView.append("\n\n\nLOGGING OUT SESSION...\n");
		myPKCS11Module_.C_Logout(session_);
		//myTextView.append("FINISHED\n");
	}



	public static long[] getCertificateKeyHandle(X509Certificate x509Cert) throws PKCS11Exception
	{
		CK_ATTRIBUTE[] findCertAttrList = new CK_ATTRIBUTE[3];
		findCertAttrList[0] = new CK_ATTRIBUTE();
		findCertAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findCertAttrList[0].pValue = new Long(PKCS11Constants.CKO_CERTIFICATE);
		findCertAttrList[1] = new CK_ATTRIBUTE();
		findCertAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findCertAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findCertAttrList[2] = new CK_ATTRIBUTE();
		findCertAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findCertAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		long certHandleBuff[] = null;
		long certHandle[] = new long[1];

		try{
			myPKCS11Module_.C_FindObjectsInit(session_, findCertAttrList);
			certHandleBuff = myPKCS11Module_.C_FindObjects(session_, 10);
			myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			throw e;
		}

		if(certHandleBuff == null)
		{
			return null;
		}
		//get the same cert in key
		for(int i=0;i<certHandleBuff.length;i++)
		{
			CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
			getValue[0] = new CK_ATTRIBUTE();
			getValue[0].type = PKCS11Constants.CKA_VALUE;
			getValue[0].pValue = null;/*new byte[8192];*/
			try{
				myPKCS11Module_.C_GetAttributeValue(session_, certHandleBuff[i], getValue);
			}
			catch(PKCS11Exception e)
			{
				throw e;
			}

			if( getValue[0].pValue!=null)
			{
				int l = ((byte[])getValue[0].pValue).length;
				byte[] bCert = new byte[l];
				for(int j=0;j<l;j++)
					bCert[j] = ((byte[])getValue[0].pValue)[j];

				try{
					X509Certificate oneCert=X509Certificate.getInstance(bCert);
					if(x509Cert.equals(oneCert))
					{
						certHandle[0] = certHandleBuff[i];
						break;
					}
				}
				catch(CertificateException e){
					return null;
				}
			}
		}

		//get CKA_ID by certhanle
		CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
		getValue[0] = new CK_ATTRIBUTE();
		getValue[0].type = PKCS11Constants.CKA_ID;
		getValue[0].pValue = null;/*new byte[8192];*/
		try{
			myPKCS11Module_.C_GetAttributeValue(session_, certHandle[0], getValue);
		}
		catch(PKCS11Exception e)
		{
			throw e;
		}

		int l = ((byte[])getValue[0].pValue).length;
		byte[] id = new  byte[l];
		int i=0;
		for(i=0;i<l;i++){
			id[i] = ((byte[])getValue[0].pValue)[i];
		}

		//find pubkey by CKA_ID
		CK_ATTRIBUTE[] findPublicKeyAttrList = new CK_ATTRIBUTE[4];
		findPublicKeyAttrList[0] = new CK_ATTRIBUTE();
		findPublicKeyAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findPublicKeyAttrList[0].pValue = new Long(PKCS11Constants.CKO_PUBLIC_KEY);
		findPublicKeyAttrList[1] = new CK_ATTRIBUTE();
		findPublicKeyAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findPublicKeyAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findPublicKeyAttrList[2] = new CK_ATTRIBUTE();
		findPublicKeyAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findPublicKeyAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		findPublicKeyAttrList[3] = new CK_ATTRIBUTE();
		findPublicKeyAttrList[3].type = PKCS11Constants.CKA_ID;
		findPublicKeyAttrList[3].pValue =id;

		long[] pubKeyHandle = null;

		try{
			myPKCS11Module_.C_FindObjectsInit(session_, findPublicKeyAttrList);
			pubKeyHandle = myPKCS11Module_.C_FindObjects(session_, 1);
			myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			throw e;
		}

		////find prikey by CKA_ID
		CK_ATTRIBUTE[] findPrivateKeyAttrList = new CK_ATTRIBUTE[4];
		findPrivateKeyAttrList[0] = new CK_ATTRIBUTE();
		findPrivateKeyAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findPrivateKeyAttrList[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);
		findPrivateKeyAttrList[1] = new CK_ATTRIBUTE();
		findPrivateKeyAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findPrivateKeyAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findPrivateKeyAttrList[2] = new CK_ATTRIBUTE();
		findPrivateKeyAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findPrivateKeyAttrList[2].pValue = new Boolean(PKCS11Constants.TRUE);
		findPrivateKeyAttrList[3] = new CK_ATTRIBUTE();
		findPrivateKeyAttrList[3].type = PKCS11Constants.CKA_ID;
		findPrivateKeyAttrList[3].pValue =id;
		long[] priKeyHandle=null;

		try{
			myPKCS11Module_.C_FindObjectsInit(session_, findPrivateKeyAttrList);
			priKeyHandle = myPKCS11Module_.C_FindObjects(session_, 1);
			myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			throw e;
		}

		if(0 == pubKeyHandle.length || 0 == priKeyHandle.length)
		{
			return null;
		}

		long keyHandle[] = new long[2];
		keyHandle[0] =  pubKeyHandle[0];
		keyHandle[1] = priKeyHandle[0];

		return keyHandle;
	}

	public static long[] getCertificateKeyHandle() throws PKCS11Exception
	{
		CK_ATTRIBUTE[] findCertAttrList = new CK_ATTRIBUTE[3];
		findCertAttrList[0] = new CK_ATTRIBUTE();
		findCertAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findCertAttrList[0].pValue = new Long(PKCS11Constants.CKO_CERTIFICATE);
		findCertAttrList[1] = new CK_ATTRIBUTE();
		findCertAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findCertAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findCertAttrList[2] = new CK_ATTRIBUTE();
		findCertAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findCertAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		long[] certHandle=null;
		try{
		myPKCS11Module_.C_FindObjectsInit(session_, findCertAttrList);
		certHandle = myPKCS11Module_.C_FindObjects(session_, 1);
		myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			throw e;
		}
		if(certHandle == null || 0 == certHandle.length)
		{
			return null;
		}
		else
		{
			CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
			getValue[0] = new CK_ATTRIBUTE();
			getValue[0].type = PKCS11Constants.CKA_ID;
			getValue[0].pValue = null;/*new byte[8192];*/
			try{
			myPKCS11Module_.C_GetAttributeValue(session_, certHandle[0], getValue);
			}
			catch(PKCS11Exception e)
			{
				throw e;
			}
			int l = ((byte[])getValue[0].pValue).length;
			byte[] id = new  byte[l];
			int i=0;
			for(i=0;i<l;i++){
				id[i] = ((byte[])getValue[0].pValue)[i];
			}

			CK_ATTRIBUTE[] findPrivateKeyAttrList = new CK_ATTRIBUTE[4];
			findPrivateKeyAttrList[0] = new CK_ATTRIBUTE();
			findPrivateKeyAttrList[0].type = PKCS11Constants.CKA_CLASS;
			findPrivateKeyAttrList[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);
			findPrivateKeyAttrList[1] = new CK_ATTRIBUTE();
			findPrivateKeyAttrList[1].type = PKCS11Constants.CKA_TOKEN;
			findPrivateKeyAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
			findPrivateKeyAttrList[2] = new CK_ATTRIBUTE();
			findPrivateKeyAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
			findPrivateKeyAttrList[2].pValue = new Boolean(PKCS11Constants.TRUE);
			findPrivateKeyAttrList[3] = new CK_ATTRIBUTE();
			findPrivateKeyAttrList[3].type = PKCS11Constants.CKA_ID;
			findPrivateKeyAttrList[3].pValue =id;
			long[] keyHandle2=null;
			try{
			myPKCS11Module_.C_FindObjectsInit(session_, findPrivateKeyAttrList);
			keyHandle2 = myPKCS11Module_.C_FindObjects(session_, 1);
			myPKCS11Module_.C_FindObjectsFinal(session_);
			}
			catch(PKCS11Exception e){
				throw e;
			}

			CK_ATTRIBUTE[] findPublicKeyAttrList = new CK_ATTRIBUTE[4];
			findPublicKeyAttrList[0] = new CK_ATTRIBUTE();
			findPublicKeyAttrList[0].type = PKCS11Constants.CKA_CLASS;
			findPublicKeyAttrList[0].pValue = new Long(PKCS11Constants.CKO_PUBLIC_KEY);
			findPublicKeyAttrList[1] = new CK_ATTRIBUTE();
			findPublicKeyAttrList[1].type = PKCS11Constants.CKA_TOKEN;
			findPublicKeyAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
			findPublicKeyAttrList[2] = new CK_ATTRIBUTE();
			findPublicKeyAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
			findPublicKeyAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
			findPublicKeyAttrList[3] = new CK_ATTRIBUTE();
			findPublicKeyAttrList[3].type = PKCS11Constants.CKA_ID;
			findPublicKeyAttrList[3].pValue =id;
			long[] keyHandle1=null;
			try{
			myPKCS11Module_.C_FindObjectsInit(session_, findPublicKeyAttrList);
			keyHandle1 = myPKCS11Module_.C_FindObjects(session_, 1);
			myPKCS11Module_.C_FindObjectsFinal(session_);
			}
			catch(PKCS11Exception e){
				throw e;
			}

			long[] handle2 = new long[2];
			if(keyHandle1!=null) handle2[0] =  keyHandle1[0];
			if(keyHandle2!=null) handle2[1] = keyHandle2[0];

			return handle2;

		}

	}

	//锟矫碉拷证锟斤拷
	public static X509Certificate getX509Certificate()
	{
		CK_ATTRIBUTE[] findCertAttrList = new CK_ATTRIBUTE[3];
		findCertAttrList[0] = new CK_ATTRIBUTE();
		findCertAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findCertAttrList[0].pValue = new Long(PKCS11Constants.CKO_CERTIFICATE);
		findCertAttrList[1] = new CK_ATTRIBUTE();
		findCertAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findCertAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findCertAttrList[2] = new CK_ATTRIBUTE();
		findCertAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findCertAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		long[] certHandle=null;
		try{
		myPKCS11Module_.C_FindObjectsInit(session_, findCertAttrList);
		certHandle = myPKCS11Module_.C_FindObjects(session_, 1);
		myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			return null;
		}
		if(certHandle == null || 0 == certHandle.length)
		{
			return null;
		}
		else
		{//取证锟斤拷锟斤拷锟斤拷锟�
				//if(certHandle.length == 0)
					//return null;

				CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
				getValue[0] = new CK_ATTRIBUTE();
				getValue[0].type = PKCS11Constants.CKA_VALUE;
				getValue[0].pValue = null;/*new byte[8192];*/
				try{
				myPKCS11Module_.C_GetAttributeValue(session_, certHandle[0], getValue);
				}
				catch(PKCS11Exception e)
				{
					e.printStackTrace();
					return null;
				}
				if( getValue[0].pValue!=null)
				{
					int l = ((byte[])getValue[0].pValue).length;
					byte[] bCert = new byte[l];
					int i;
					for(i=0;i<l;i++)
						bCert[i] = ((byte[])getValue[0].pValue)[i];

					try{
						X509Certificate c=X509Certificate.getInstance(bCert);
						return c;
					}
					catch(CertificateException e){
						return null;
					}

				}
				else{
					return null;
				}

		}
	}

	public static X509Certificate[] getAllX509Certificate() throws PKCS11Exception, CertificateException
	{
		CK_ATTRIBUTE[] findCertAttrList = new CK_ATTRIBUTE[3];
		findCertAttrList[0] = new CK_ATTRIBUTE();
		findCertAttrList[0].type = PKCS11Constants.CKA_CLASS;
		findCertAttrList[0].pValue = new Long(PKCS11Constants.CKO_CERTIFICATE);
		findCertAttrList[1] = new CK_ATTRIBUTE();
		findCertAttrList[1].type = PKCS11Constants.CKA_TOKEN;
		findCertAttrList[1].pValue = new Boolean(PKCS11Constants.TRUE);
		findCertAttrList[2] = new CK_ATTRIBUTE();
		findCertAttrList[2].type = PKCS11Constants.CKA_PRIVATE;
		findCertAttrList[2].pValue = new Boolean(PKCS11Constants.FALSE);
		long certHandle[] = null;
		long MaxObjectCount = 64;

		try
		{
			myPKCS11Module_.C_FindObjectsInit(session_, findCertAttrList);
			certHandle = myPKCS11Module_.C_FindObjects(session_, MaxObjectCount);
			myPKCS11Module_.C_FindObjectsFinal(session_);
		}
		catch(PKCS11Exception e){
			throw e;
		}

		if(null == certHandle || certHandle.length == 0)
		{
			return null;
		}

		List<X509Certificate> clientCertList = new ArrayList<>();
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (Throwable ignored) {}

		for(int i = 0; i < certHandle.length; i++)
		{
			CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
			getValue[0] = new CK_ATTRIBUTE();
			getValue[0].type = PKCS11Constants.CKA_VALUE;
			getValue[0].pValue = null;
			try {
				myPKCS11Module_.C_GetAttributeValue(session_, certHandle[i], getValue);
			} catch(PKCS11Exception e) {
				continue;
			}

			if(getValue[0].pValue != null)
			{
				byte[] bCert = (byte[]) getValue[0].pValue;
				try {
					if (cf != null) {
						java.security.cert.X509Certificate javaCert = 
							(java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bCert));
						if (!CertificateManager.isClientCertificate(javaCert)) {
							// Filter out Root CA and Sub CA! Only client certificates returned
							continue;
						}
					}
					X509Certificate oneCert = X509Certificate.getInstance(bCert);
					clientCertList.add(oneCert);
				} catch (Throwable ignored) {}
			}
		}

		// Fallback: If strict client filter left list empty, return all valid certs
		if (clientCertList.isEmpty() && certHandle.length > 0) {
			for(int i = 0; i < certHandle.length; i++) {
				CK_ATTRIBUTE[] getValue = new CK_ATTRIBUTE[1];
				getValue[0] = new CK_ATTRIBUTE();
				getValue[0].type = PKCS11Constants.CKA_VALUE;
				getValue[0].pValue = null;
				try {
					myPKCS11Module_.C_GetAttributeValue(session_, certHandle[i], getValue);
					if (getValue[0].pValue != null) {
						byte[] bCert = (byte[]) getValue[0].pValue;
						clientCertList.add(X509Certificate.getInstance(bCert));
					}
				} catch (Throwable ignored) {}
			}
		}

		return clientCertList.toArray(new X509Certificate[0]);
	}
}
