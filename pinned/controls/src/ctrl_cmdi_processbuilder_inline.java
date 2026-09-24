package controls;

import javax.servlet.http.HttpServletRequest;

/**
 * Command injection via ProcessBuilder, written inline.
 *
 * Paired deliberately with ctrl_cmdi_processbuilder_assigned. The two differ
 * only in whether the builder is bound to a variable before `start()` is
 * called, which is not a difference in vulnerability -- both execute a
 * user-supplied command. Phase one found the ruleset detects one and misses the
 * other, so the pair is kept to hold that finding in place.
 */
public class ctrl_cmdi_processbuilder_inline {

    public void run(HttpServletRequest request) throws Exception {
        new ProcessBuilder(request.getParameter("cmd")).start();
    }
}
