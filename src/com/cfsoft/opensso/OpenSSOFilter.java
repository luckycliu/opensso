package com.cfsoft.opensso;

import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.assertion.Subject;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.profile.SPACSUtils;
import com.sun.identity.saml2.protocol.Response;
import com.sun.identity.shared.encode.URLEncDec;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static com.sun.identity.shared.encode.URLEncDec.encode;


public class OpenSSOFilter implements javax.servlet.Filter {
    private String loginUrl = null;
    private String logoutUrl = null;
    private String deployUri = null;

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws java.io.IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;
        String requestURI = request.getRequestURI();
        if (requestURI.startsWith(deployUri + "/ssoLogin")) {
            chain.doFilter(request, response);
            return;
        } else if (requestURI.startsWith(deployUri + "/ssoLogout")) {
            chain.doFilter(request, response);
            return;
        } else if (requestURI.startsWith(deployUri + "/logout.jsp")) {
            chain.doFilter(request, response);
            return;
        } else {
            HttpSession session = request.getSession(false);
            if (session != null && session.getAttribute("LOGIN") != null) {
                chain.doFilter(request, response);
                return;
            } else {
                try {
                    if (request.getParameter(SAML2Constants.SAML_RESPONSE) != null) {
                        Map map = SPACSUtils.processResponseForFedlet(request, response);
                        request.getSession().setAttribute("LOGIN", true);
                        request.getSession().setAttribute("logoutUrl", getLogoutUrl(map));
                        //build logout url
                    }

                    Object ssoToken = null;
                    try {
                        ssoToken = SessionManager.getProvider().getSession(request);
                    } catch (SessionException se) {
                        if (SAML2Utils.debug.messageEnabled()) {
                            SAML2Utils.debug.message("No session.");
                        }
                        ssoToken = null;
                    }
                    if (ssoToken == null) {
                        response.sendRedirect(loginUrl);
                    } else {
                        chain.doFilter(request, response);
                    }
                } catch (SAML2Exception e) {
                    e.printStackTrace();
                } catch (SessionException e) {
                    e.printStackTrace();
                }

            }
        }

    }

    private String getLoginUrl(ServletContext ctx) {
        deployUri = ctx.getContextPath();
        System.out.println(deployUri);
        int slashLoc = deployUri.indexOf("/", 1);
        if (slashLoc != -1) {
            deployUri = deployUri.substring(0, slashLoc);
        }
        String fedletBaseUrl = OpenSSOUtils.getFedletBaseUrl(OpenSSOUtils.getSpEntityID(), deployUri);
        String template = "%s/ssoLogin?metaAlias=%s&idpEntityID=%s&binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        return String.format(template, fedletBaseUrl, OpenSSOUtils.getSpMetaAlias(), OpenSSOUtils.getIdpEntityID());
    }


    /**
     * init opensso
     *
     * @param config of type FilterConfig
     * @throws ServletException when
     */
    public void init(javax.servlet.FilterConfig config) throws ServletException {
        ServletContext servletCtx = config.getServletContext();
        //get fedletHomeDir
        String fedletHomeDir = System.getProperty("com.sun.identity.fedlet.home");
        if ((fedletHomeDir == null) || (fedletHomeDir.trim().length() == 0)) {
            fedletHomeDir = config.getServletContext().getInitParameter("fedlet.home");
            if (fedletHomeDir == null || fedletHomeDir.trim().length() == 0) {
                if (System.getProperty("user.home").equals(File.separator)) {
                    fedletHomeDir = File.separator + "fedlet";
                } else {
                    fedletHomeDir = System.getProperty("user.home") +
                            File.separator + "fedlet";
                }
            }
            System.setProperty("com.sun.identity.fedlet.home", fedletHomeDir);
        }
        //check home dir
        File dir = new File(fedletHomeDir);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                throw new ServletException(new SAML2Exception("Failed to create Fedlet " +
                        "configuration home directory " + fedletHomeDir));
            }
        } else if (dir.isFile()) {
            throw new ServletException(new SAML2Exception("Fedlet configuration home " +
                    fedletHomeDir + " is a pre-existing file. <br>Please " +
                    "remove the file and try again."));
        }
        //check need create config
        File file = new File(fedletHomeDir + File.separator + "FederationConfig.properties");
        if (!file.exists()) {
            //copy config from conf
            String[] files = new String[]{
                    "FederationConfig.properties",
                    "idp.xml",
                    "idp-extended.xml",
                    "sp.xml",
                    "sp-extended.xml",
                    "fedlet.cot" };

            for (int i = 0; i < files.length; i++) {
                String source = "/conf/" + files[i];
                String dest = dir.getPath() + File.separator + files[i];
                FileOutputStream fos = null;
                InputStream src = null;
                try {
                    src = servletCtx.getResourceAsStream(source);
                    if (src != null) {
                        fos = new FileOutputStream(dest);
                        int length = 0;
                        byte[] bytes = new byte[1024];
                        while ((length = src.read(bytes)) != -1) {
                            fos.write(bytes, 0, length);
                        }
                    } else {
                        throw new ServletException(new SAML2Exception("File " + source +
                                " could not be found in fedlet.war"));
                    }
                } catch (IOException e) {
                    throw new ServletException(new SAML2Exception(e.getMessage()));
                } finally {
                    try {
                        if (fos != null) {
                            fos.close();
                        }
                        if (src != null) {
                            src.close();
                        }
                    } catch (IOException ex) {
                        //ignore
                    }
                }
            }
        } else if (file.isDirectory()) {
            throw new ServletException(new SAML2Exception("Fedlet configuration home " +
                    fedletHomeDir + "/FederationConfig.properties is a directory. <br>Please " +
                    "remove the directory and try again."));
        }


        try {
            OpenSSOUtils.init();
            loginUrl = getLoginUrl(servletCtx);
        } catch (SAML2MetaException e) {
            throw new ServletException(e);
        }

    }

    private String getLogoutUrl(Map map) {
//        Response samlResp = (Response) map.get(SAML2Constants.RESPONSE);
//        Assertion assertion = (Assertion) map.get(SAML2Constants.ASSERTION);
//        Subject subject = (Subject) map.get(SAML2Constants.SUBJECT);
        String entityID = (String) map.get(SAML2Constants.IDPENTITYID);
        String spEntityID = (String) map.get(SAML2Constants.SPENTITYID);
        NameID nameId = (NameID) map.get(SAML2Constants.NAMEID);
        String value = nameId.getValue();
        String sessionIndex = (String) map.get(SAML2Constants.SESSION_INDEX);
//        String format = nameId.getFormat();
        //fedletBaseUrl + "/fedletSloInit?spEntityID=" + URLEncDec.encode(spEntityID) + "&idpEntityID=" + URLEncDec.encode(entityID) +
        // "&NameIDValue=" + URLEncDec.encode(value) + "&SessionIndex=" + URLEncDec.encode(sessionIndex) + "&binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
        // &RelayState=" + URLEncDec.encode(fedletBaseUrl + "/index.jsp") + "\">Run Fedlet initiated Single Logout using HTTP POST binding</a></b></br>");
        String template = "%s?spEntityId=%s&idpEntityID=%s&NameIDValue=%s&SessionIndex=%s&binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        String logoutUrl = String.format(template, deployUri + "/ssoLogout", encode(spEntityID), encode(entityID),
                encode(value), encode(sessionIndex));
        return logoutUrl;
    }


}
