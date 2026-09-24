package controls;

import javax.servlet.http.HttpServletRequest;

/**
 * The canonical Java command injection, and the single most important control
 * in this set.
 *
 * `Runtime.getRuntime().exec(userControlled)` is the form every Java SAST
 * benchmark, tutorial and CWE-78 writeup uses. Phase one of this study found
 * that the 690-rule union ruleset does not fire on it in any syntactic variant
 * it was tried in. If that reproduces here, the control matrix says so in a way
 * that is hard to argue with: the miss is not in an obscure construct.
 */
public class ctrl_cmdi_runtime_exec {

    public void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
