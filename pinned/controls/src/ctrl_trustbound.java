package controls;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Trust boundary violation: an unvalidated request value is stored directly in
 * the session, where it acquires the session's authority. OWASP Benchmark
 * category "trustbound".
 *
 * The vulnerability is one of provenance rather than of syntax -- the setter is
 * ordinary, and what makes it a finding is that a client-controlled string
 * crosses into trusted server-side state.
 */
public class ctrl_trustbound {

    public void run(HttpServletRequest request) throws Exception {
        HttpSession session = request.getSession(true);
        String role = request.getParameter("role");
        session.setAttribute("role", role);
    }
}
