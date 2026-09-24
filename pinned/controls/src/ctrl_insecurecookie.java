package controls;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Session cookie created without the Secure and HttpOnly flags. OWASP Benchmark
 * category "securecookie".
 *
 * Without `Secure` the cookie is sent over plaintext HTTP; without `HttpOnly`
 * it is readable by any script that achieves XSS on the origin.
 */
public class ctrl_insecurecookie {

    public void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Cookie c = new Cookie("sessionId", request.getParameter("sid"));
        response.addCookie(c);
    }
}
