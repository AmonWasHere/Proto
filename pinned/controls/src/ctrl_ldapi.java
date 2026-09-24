package controls;

import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

/**
 * LDAP injection. OWASP Benchmark category "ldapi".
 */
public class ctrl_ldapi {

    public void run(HttpServletRequest request, DirContext ctx) throws Exception {
        String filter = "(uid=" + request.getParameter("uid") + ")";
        ctx.search("ou=people", filter, null);
    }
}
