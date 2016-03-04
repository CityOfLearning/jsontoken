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

import com.google.gson.JsonObject;
/**
 * Token verifiers must implement this interface.
 */
public interface Checker {

  /**
   * Checks that the given payload satisfies this token verifier.
   *
   * @param payload the payload component of a JsonToken (JWT)
   * @throws SignatureException if the audience doesn't match.
   */
  public void check(JsonObject payload) throws SignatureException;

}