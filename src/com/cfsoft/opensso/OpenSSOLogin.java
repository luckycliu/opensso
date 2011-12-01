package com.cfsoft.opensso;

import com.sun.identity.saml.common.SAMLUtils;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.profile.SPCache;
import com.sun.identity.saml2.profile.SPSSOFederate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class OpenSSOLogin extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        login(request, response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        login(request, response);
    }

    /**
     * http://sp.wfoo.org:8080/fedlet/saml2/jsp/fedletSSOInit.jsp?metaAlias=/sp&idpEntityID=enterprise-idp&binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
     * Following are the list of supported query parameters :
     * <p/>
     * Query Parameter Name    Description
     * <p/>
     * 1. metaAlias         MetaAlias for Service Provider. The format of
     * this parameter is /realm_name/SP name. If unspecified,
     * first available hosted SP is used.
     * <p/>
     * 2. idpEntityID       Identifier for Identity Provider. If unspecified,
     * first available remote IDP is used.
     * <p/>
     * 3. RelayState        Target URL on successful complete of SSO/Federation
     * <p/>
     * 4. RelayStateAlias   Specify the parameter(s) to use as the RelayState.
     * e.g. if the request URL has :
     * ?TARGET=http://server:port/uri&RelayStateAlias=TARGET
     * then the TARGET query parameter will be interpreted as
     * RelayState and on successful completion of
     * SSO/Federation user will be redirected to the TARGET
     * URL.
     * <p/>
     * 5. NameIDFormat      NameIDPolicy format Identifier Value.
     * For example,
     * urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
     * urn:oasis:names:tc:SAML:2.0:nameid-format:transient
     * Note : transient will always be used for Fedlet
     * <p/>
     * 6. binding           URI value that identifies a SAML protocol binding to
     * used when returning the Response message.
     * The supported values are :
     * HTTP-Artifact
     * HTTP-POST (default for Fedlet)
     * <p/>
     * 7. AssertionConsumerServiceIndex
     * An integer number indicating the location
     * to which the Response message should be returned to
     * the requester.
     * <p/>
     * 8. AttributeConsumingServiceIndex
     * Indirectly specifies information associated
     * with the requester describing the SAML attributes
     * the requester desires or requires to be supplied
     * by the IDP in the generated Response message.
     * Note: This parameter may not be supported for
     * this release.
     * <p/>
     * 9. isPassive         true or false value indicating whether the IDP
     * should authenticate passively.
     * <p/>
     * 10. ForceAuthN       true or false value indicating if IDP must
     * force authentication OR false if IDP can rely on
     * reusing existing security contexts.
     * true - force authentication
     * <p/>
     * 11.AllowCreate       Value indicates if IDP is allowed to created a new
     * identifier for the principal if it does not exist.
     * Value of this parameter can be true OR false.
     * true - IDP can dynamically create user.
     * <p/>
     * 12.Destination       A URI Reference indicating the address to which the
     * request has been sent.
     * <p/>
     * 13.AuthnContextDeclRef
     * Specifies the AuthnContext Declaration Reference.
     * The value is a pipe separated value with multiple
     * references.
     * <p/>
     * 14.AuthnContextClassRef
     * Specifies the AuthnContext Class References.
     * The value is a pipe separated value with multiple
     * references.
     * <p/>
     * 15 AuthLevel         The Authentication Level of the Authentication
     * Context to use for Authentication.
     * <p/>
     * 16.AuthComparison    The comparison method used to evaluate the
     * requested context classes or statements.
     * Allowed values are :
     * exact
     * minimum
     * maximum
     * better
     * <p/>
     * 17.Consent           Specifies a URI a SAML defined identifier
     * known as Consent Identifiers.These are defined in
     * the SAML 2 Assertions and Protocols Document.
     * Note: This parameter may not be supported for
     * this release.
     * <p/>
     * 18.reqBinding        URI value that identifies a SAML protocol binding to
     * used when sending the AuthnRequest.
     * The supported values are :
     * urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
     * urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
     * <p/>
     * 19.affiliationID     Affiliation entity ID
     */
    public void login(HttpServletRequest request, HttpServletResponse response) {
        // Retreive the Request Query Parameters
        // metaAlias and idpEntiyID are the required query parameters
        // metaAlias - Service Provider Entity Id
        // idpEntityID - Identity Provider Identifier
        // Query parameters supported will be documented.
        String idpEntityID = null;
        String metaAlias = null;
        Map paramsMap = null;
        try {
            String reqID = request.getParameter("requestID");
            if (reqID != null) {
                //get the preferred idp
                idpEntityID = SAML2Utils.getPreferredIDP(request);
                paramsMap = (Map) SPCache.reqParamHash.get(reqID);
                metaAlias = (String) paramsMap.get("metaAlias");
                SPCache.reqParamHash.remove(reqID);
            } else {
                // this is an original request check
                // get the metaAlias ,idpEntityID
                // if idpEntityID is null redirect to IDP Discovery
                // Service to retrieve.
                metaAlias = request.getParameter("metaAlias");
                if ((metaAlias == null) || (metaAlias.length() == 0)) {
                    SAML2MetaManager manager = new SAML2MetaManager();
                    List spMetaAliases =
                            manager.getAllHostedServiceProviderMetaAliases("/");
                    if ((spMetaAliases != null) && !spMetaAliases.isEmpty()) {
                        // get first one
                        metaAlias = (String) spMetaAliases.get(0);
                    }
                    if ((metaAlias == null) || (metaAlias.length() == 0)) {
                        SAMLUtils.sendError(request, response,
                                response.SC_BAD_REQUEST, "nullSPEntityID",
                                SAML2Utils.bundle.getString("nullSPEntityID"));
                        return;
                    }
                }

                idpEntityID = request.getParameter("idpEntityID");
                paramsMap = SAML2Utils.getParamsMap(request);
                // always use transient
                List list = new ArrayList();
                list.add(SAML2Constants.NAMEID_TRANSIENT_FORMAT);
                paramsMap.put(SAML2Constants.NAMEID_POLICY_FORMAT, list);
                if (paramsMap.get(SAML2Constants.BINDING) == null) {
                    // use POST binding
                    list = new ArrayList();
                    list.add(SAML2Constants.HTTP_POST);
                    paramsMap.put(SAML2Constants.BINDING, list);
                }

                if ((idpEntityID == null) || (idpEntityID.length() == 0)) {
                    // get reader url
                    String readerURL = SAML2Utils.getReaderURL(metaAlias);
                    if (readerURL != null) {
                        String rID = SAML2Utils.generateID();
                        String redirectURL =
                                SAML2Utils.getRedirectURL(readerURL, rID, request);
                        if (redirectURL != null) {
                            paramsMap.put("metaAlias", metaAlias);
                            SPCache.reqParamHash.put(rID, paramsMap);
                            response.sendRedirect(redirectURL);
                            return;
                        }
                    }
                }
            }

            if ((idpEntityID == null) || (idpEntityID.length() == 0)) {
                SAML2MetaManager manager = new SAML2MetaManager();
                List idpEntities = manager.getAllRemoteIdentityProviderEntities("/");
                if ((idpEntities == null) || idpEntities.isEmpty()) {
                    SAMLUtils.sendError(request, response,
                            response.SC_BAD_REQUEST, "idpNotFound",
                            SAML2Utils.bundle.getString("idpNotFound"));
                    return;
                } else if (idpEntities.size() == 1) {
                    // only one IDP, just use it
                    idpEntityID = (String) idpEntities.get(0);
                } else {
                    // multiple IDP configured in fedlet
                    SAMLUtils.sendError(request, response,
                            response.SC_BAD_REQUEST, "nullIDPEntityID",
                            SAML2Utils.bundle.getString("nullIDPEntityID"));
                    return;
                }
            }
            // get the parameters and put it in a map.
            SPSSOFederate.initiateAuthnRequest(request, response, metaAlias,
                    idpEntityID, paramsMap);
        } catch (SAML2Exception sse) {
            SAML2Utils.debug.error("Error sending AuthnRequest ", sse);
            SAMLUtils.sendError(request, response,
                    response.SC_BAD_REQUEST, "requestProcessingError",
                    SAML2Utils.bundle.getString("requestProcessingError") + " " +
                            sse.getMessage());
        } catch (Exception e) {
            SAML2Utils.debug.error("Error processing Request ", e);
            SAMLUtils.sendError(request, response,
                    response.SC_BAD_REQUEST, "requestProcessingError",
                    SAML2Utils.bundle.getString("requestProcessingError") + " " +
                            e.getMessage());
        }
    }
}
