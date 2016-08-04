package jetbrains.teamcilty.github.api.impl;

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.params.AuthParams;
import org.apache.http.message.BufferedHeader;
import org.apache.http.util.CharArrayBuffer;

public class OAuthTokenScheme {

  /**
   * Produces basic authorization header for the given token.
   *
   * @param token The API token to be used for authentication
   * @param request The request being authenticated
   *
   * @return a basic authorization string
   */
  public Header authenticate(
          final String token,
          final HttpRequest request) {

    if (token == null) {
      throw new IllegalArgumentException("Token may not be null");
    }
    if (token.trim().length() == 0) {
      throw new IllegalArgumentException("Token may not be empty");
    }
    if (request == null) {
      throw new IllegalArgumentException("HTTP request may not be null");
    }

    String charset = AuthParams.getCredentialCharset(request.getParams());
    return authenticate(token, charset, false); // assume no proxy
  }

  /**
   * Returns a basic <tt>Authorization</tt> header value for the given
   * token and charset.
   *
   * @param token The token to encode.
   * @param charset The charset to use for encoding the credentials
   *
   * @return a basic authorization header
   */
  public static Header authenticate(
          final String token,
          final String charset,
          boolean proxy) {
    if (token == null) {
      throw new IllegalArgumentException("Token may not be null");
    }
    if (token.trim().length() == 0) {
      throw new IllegalArgumentException("Token may not be empty");
    }
    if (charset == null) {
      throw new IllegalArgumentException("charset may not be null");
    }

    CharArrayBuffer buffer = new CharArrayBuffer(32);
    if (proxy) {
      buffer.append(AUTH.PROXY_AUTH_RESP);
    } else {
      buffer.append(AUTH.WWW_AUTH_RESP);
    }
    buffer.append(": token ");
    buffer.append(token);

    return new BufferedHeader(buffer);
  }
}
