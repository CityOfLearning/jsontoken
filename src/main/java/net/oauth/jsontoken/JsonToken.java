/**
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package net.oauth.jsontoken;

import java.security.SignatureException;
import java.time.Instant;

import org.apache.commons.codec.binary.Base64;

import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import net.oauth.jsontoken.crypto.AsciiStringSigner;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Signer;

/**
 * A JSON Token.
 */
public class JsonToken {
	// header names
	public final static String ALGORITHM_HEADER = "alg";
	public final static String KEY_ID_HEADER = "kid";
	public final static String TYPE_HEADER = "typ";

	// standard claim names (payload parameters)
	public final static String ISSUER = "iss";
	public final static String ISSUED_AT = "iat";
	public final static String EXPIRATION = "exp";
	public final static String AUDIENCE = "aud";
	public final static String SUBJECT = "sub";
	public final static String NOT_BEFORE = "nbf";
	public final static String UNIQUE_ID = "jti";

	// default encoding for all Json token
	public final static String BASE64URL_ENCODING = "base64url";

	public final static int DEFAULT_LIFETIME_IN_MINS = 2;

	private JsonObject header;
	private SignatureAlgorithm sigAlg;

	protected final Clock clock;
	private final JsonObject payload;
	private final String tokenString;

	// The following fields are only valid when signing the token.
	private final Signer signer;
	private String signature;
	private String baseString;

	/**
	 * Public constructor used when parsing a JsonToken {@link JsonToken} (as
	 * opposed to create a token). This constructor takes Json payload as
	 * parameter, set all other signing related parameters to null.
	 *
	 * @param payload
	 *            A payload JSON object.
	 */
	public JsonToken(JsonObject payload) {
		this.payload = payload;
		baseString = null;
		tokenString = null;
		signature = null;
		sigAlg = null;
		signer = null;
		clock = null;
	}

	/**
	 * Public constructor used when parsing a JsonToken {@link JsonToken} (as
	 * opposed to create a token). This constructor takes Json payload and clock
	 * as parameters, set all other signing related parameters to null.
	 *
	 * @param payload
	 *            A payload JSON object.
	 * @param clock
	 *            a clock whose notion of current time will determine the
	 *            not-before timestamp of the token, if not explicitly set.
	 */
	public JsonToken(JsonObject payload, Clock clock) {
		this.payload = payload;
		this.clock = clock;
		baseString = null;
		tokenString = null;
		signature = null;
		sigAlg = null;
		signer = null;
	}

	/**
	 * Public constructor used when parsing a JsonToken {@link JsonToken} (as
	 * opposed to create a token). This constructor takes Json payload and clock
	 * as parameters, set all other signing related parameters to null.
	 *
	 * @param payload
	 *            A payload JSON object.
	 * @param clock
	 *            a clock whose notion of current time will determine the
	 *            not-before timestamp of the token, if not explicitly set.
	 * @param tokenString
	 *            The original token string we parsed to get this payload.
	 */
	public JsonToken(JsonObject header, JsonObject payload, Clock clock, String tokenString) {
		this.payload = payload;
		this.clock = clock;
		baseString = null;
		signature = null;
		sigAlg = null;
		signer = null;
		this.header = header;
		this.tokenString = tokenString;
	}

	/**
	 * Public constructor, use empty data type.
	 *
	 * @param signer
	 *            the signer that will sign the token.
	 */
	public JsonToken(Signer signer) {
		this(signer, new SystemClock());
	}

	/**
	 * Public constructor.
	 *
	 * @param signer
	 *            the signer that will sign the token
	 * @param clock
	 *            a clock whose notion of current time will determine the
	 *            not-before timestamp of the token, if not explicitly set.
	 */
	public JsonToken(Signer signer, Clock clock) {
		Preconditions.checkNotNull(signer);
		Preconditions.checkNotNull(clock);

		payload = new JsonObject();
		this.signer = signer;
		this.clock = clock;
		sigAlg = signer.getSignatureAlgorithm();
		signature = null;
		baseString = null;
		tokenString = null;
		createHeader();
		String issuer = signer.getIssuer();
		if (issuer != null) {
			setParam(JsonToken.ISSUER, issuer);
		}
	}

	public void addJsonObject(String name, JsonObject obj) {
		payload.add(name, obj);
	}

	protected String computeSignatureBaseString() {
		if ((baseString != null) && !baseString.isEmpty()) {
			return baseString;
		}
		// System.out.println(JsonTokenUtil.toBase64(getHeader()));
		// System.out.println(JsonTokenUtil.toBase64(payload));
		baseString = JsonTokenUtil.toDotFormat(JsonTokenUtil.toBase64(getHeader()), JsonTokenUtil.toBase64(payload));
		return baseString;
	}

	private JsonObject createHeader() {
		header = new JsonObject();
		header.addProperty(TYPE_HEADER, "JWT");
		header.addProperty(ALGORITHM_HEADER, getSignatureAlgorithm().getNameForJson());
		String keyId = getKeyId();
		if (keyId != null) {
			header.addProperty(KEY_ID_HEADER, keyId);
		}
		return header;
	}

	public String getAudience() {
		return getParamAsString(AUDIENCE);
	}

	public Instant getExpiration() {
		Long expiration = getParamAsLong(EXPIRATION);
		if (expiration == null) {
			return null;
		}
		// JWT represents time in seconds
		return Instant.ofEpochSecond(expiration);
	}

	public JsonObject getHeader() {
		if (header == null) {
			createHeader();
		}
		return header;
	}

	public Instant getIssuedAt() {
		Long issuedAt = getParamAsLong(ISSUED_AT);
		if (issuedAt == null) {
			return null;
		}
		// JWT represents time in seconds
		return Instant.ofEpochSecond(issuedAt);
	}

	public String getIssuer() {
		return getParamAsString(ISSUER);
	}

	public String getKeyId() {
		return signer.getKeyId();
	}

	private Long getParamAsLong(String param) {
		JsonPrimitive primitive = getParamAsPrimitive(param);
		if ((primitive != null) && (primitive.isNumber() || primitive.isString())) {
			try {
				return primitive.getAsLong();
			} catch (NumberFormatException e) {
				return null;
			}
		}
		return null;
	}

	public JsonPrimitive getParamAsPrimitive(String param) {
		JsonElement element = payload.get(param);
		if ((element != null) && element.isJsonPrimitive()) {
			return (JsonPrimitive) element;
		}
		return null;
	}

	private String getParamAsString(String param) {
		JsonPrimitive primitive = getParamAsPrimitive(param);
		return primitive == null ? null : primitive.getAsString();
	}

	public JsonObject getPayloadAsJsonObject() {
		return payload;
	}

	private String getSignature() throws SignatureException {
		if ((signature != null) && !signature.isEmpty()) {
			return signature;
		}

		if (signer == null) {
			throw new SignatureException("can't sign JsonToken with signer.");
		}
		String signature;
		// now, generate the signature
		AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
		signature = Base64.encodeBase64URLSafeString(asciiSigner.sign(baseString));

		return signature;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		if (sigAlg == null) {
			if (header == null) {
				throw new IllegalStateException("JWT has no algorithm or header");
			}
			JsonElement algorithmName = header.get(JsonToken.ALGORITHM_HEADER);
			if (algorithmName == null) {
				throw new IllegalStateException(
						"JWT header is missing the required '" + JsonToken.ALGORITHM_HEADER + "' parameter");
			}
			sigAlg = SignatureAlgorithm.getFromJsonName(algorithmName.getAsString());
		}
		return sigAlg;
	}

	public String getSubject() {
		String subject = getParamAsString(SUBJECT);
		if (subject == null) {
			return null;
		}
		// JWT represents time in seconds
		return subject;
	}

	public String getTokenAsString() {
		String temp = "\n{\n\t";
		;
		int index = 1;

		temp = temp + header.toString().substring(index, header.toString().indexOf(",") + 1) + "\n\t";
		index = header.toString().indexOf(",", index + 1);
		while ((index > -1) && (index < header.toString().length())) {
			if (header.toString().indexOf(",", index + 1) > 0) {
				temp = temp + header.toString().substring(index + 1, header.toString().indexOf(",", index + 1) + 1)
						+ "\n\t";
			} else {
				temp = temp + header.toString().substring(index + 1, header.toString().length() - 1) + ",";
			}
			index = header.toString().indexOf(",", index + 1);
		}
		temp = temp + "\n\tpayload: {\n\t\t";
		index = 1;
		temp = temp + payload.toString().substring(index, payload.toString().indexOf(",") + 1) + "\n\t\t";
		index = payload.toString().indexOf(",", index + 1);
		while ((index > -1) && (index < payload.toString().length())) {
			if (payload.toString().indexOf(",", index + 1) > 0) {
				temp = temp + payload.toString().substring(index + 1, payload.toString().indexOf(",", index + 1) + 1)
						+ "\n\t\t";
			} else {
				temp = temp + payload.toString().substring(index + 1, payload.toString().length() - 1);
			}
			index = payload.toString().indexOf(",", index + 1);
		}
		temp = temp + "\n\t}\n}";
		return temp;
	}

	public String getTokenString() {
		return tokenString;
	}

	/**
	 * Returns the serialized representation of this token, i.e.,
	 * keyId.sig.base64(payload).base64(data_type).base64(encoding).base64(alg)
	 *
	 * This is what a client (token issuer) would send to a token verifier over
	 * the wire.
	 *
	 * @throws SignatureException
	 *             if the token can't be signed.
	 */
	public String serializeAndSign() throws SignatureException {
		String baseString = computeSignatureBaseString();
		String sig = getSignature();
		return JsonTokenUtil.toDotFormat(baseString, sig);
	}

	public void setAudience(String audience) {
		setParam(AUDIENCE, audience);
	}

	public void setExpiration(Instant instant) {
		setParam(JsonToken.EXPIRATION, instant.getEpochSecond());
	}

	public void setIssuedAt(Instant instant) {
		setParam(JsonToken.ISSUED_AT, instant.getEpochSecond());
	}

	public void setParam(String name, Number value) {
		payload.addProperty(name, value);
	}

	public void setParam(String name, String value) {
		payload.addProperty(name, value);
	}

	public void setSubject(String subject) {
		setParam(JsonToken.SUBJECT, subject);
	}

	/**
	 * Returns a human-readable version of the token.
	 */
	@Override
	public String toString() {
		return JsonTokenUtil.toJson(payload);
	}

}
