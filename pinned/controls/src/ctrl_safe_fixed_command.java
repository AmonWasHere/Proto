package controls;

import javax.servlet.http.HttpServletRequest;

/**
 * NEGATIVE CONTROL -- this file is not vulnerable.
 *
 * The executed command is a compile-time constant. Nothing the client sends can
 * reach the argument list; the request is used only to choose which *fixed*
 * command runs, and even that is constrained by an equality test rather than
 * interpolated.
 *
 * Paired against ctrl_cmdi_runtime_exec: same sink, same file shape, and the
 * only difference is whether untrusted data reaches it. A tool that flags both
 * is not tracking data, and this file is how that shows up.
 *
 * Expected: no finding.
 */
public class ctrl_safe_fixed_command {

    public void run(HttpServletRequest request) throws Exception {
        if ("list".equals(request.getParameter("action"))) {
            Runtime.getRuntime().exec("/bin/ls");
        } else {
            Runtime.getRuntime().exec("/bin/date");
        }
    }
}
