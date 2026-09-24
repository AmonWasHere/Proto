package controls;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Open redirect (CWE-601).
 *
 * The redirect target is attacker-controlled, which is the standard ingredient
 * of a credible phishing link: the URL carries a trusted domain.
 */
public class ctrl_open_redirect {

    public void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect(next);
    }
}
