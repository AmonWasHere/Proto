package controls;

import javax.servlet.http.HttpServletRequest;

/**
 * Command injection via ProcessBuilder, bound to a variable first.
 *
 * Identical in behaviour to the inline form; different only in syntax. See
 * ctrl_cmdi_processbuilder_inline.
 */
public class ctrl_cmdi_processbuilder_assigned {

    public void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        ProcessBuilder builder = new ProcessBuilder(cmd);
        builder.start();
    }
}
