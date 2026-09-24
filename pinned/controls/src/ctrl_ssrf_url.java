package controls;

import java.net.URL;
import javax.servlet.http.HttpServletRequest;

/**
 * Server-side request forgery (CWE-918).
 *
 * The server fetches a URL the client chooses, so the client can reach hosts
 * behind the firewall -- including cloud metadata endpoints.
 */
public class ctrl_ssrf_url {

    public java.io.InputStream run(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        URL url = new URL(target);
        return url.openConnection().getInputStream();
    }
}
