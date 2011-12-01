package com.cfsoft.opensso;

import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.jaxb.metadata.AssertionConsumerServiceElement;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SingleSignOnServiceElement;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;

import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


public class OpenSSOUtils {
    private static String spEntityID = null;
    private static String spMetaAlias = null;
    private static String idpEntityID = null;

    public static void init() throws SAML2MetaException {
        SAML2MetaManager manager = new SAML2MetaManager();
        if (spEntityID == null) {

            List spEntities =
                    manager.getAllHostedServiceProviderEntities("/");
            if ((spEntities != null) && !spEntities.isEmpty()) {
                // get first one
                spEntityID = (String) spEntities.get(0);
            }
        }

        if (spMetaAlias == null) {
            List spMetaAliases =
                    manager.getAllHostedServiceProviderMetaAliases("/");
            if ((spMetaAliases != null) && !spMetaAliases.isEmpty()) {
                // get first one
                spMetaAlias = (String) spMetaAliases.get(0);
            }
        }

        if ((idpEntityID == null) || (idpEntityID.length() == 0)) {
            // find out all trusted IDPs
            List idpEntities =
                    manager.getAllRemoteIdentityProviderEntities("/");
            if ((idpEntities != null) && !idpEntities.isEmpty()) {
                int numOfIDP = idpEntities.size();
                for (int j = 0; j < numOfIDP; j++) {
                    String idpID = (String) idpEntities.get(j);
                    if (manager.isTrustedProvider("/",
                            spEntityID, idpID)) {
                        idpEntityID = idpID;
                    }
                }
            }
        }
    }

    public static String getFedletBaseUrl(String spEntityID, String deployuri) {
        if (spEntityID == null) {
            return null;
        }
        String fedletBaseUrl = null;
        try {
            SAML2MetaManager manager = new SAML2MetaManager();
            SPSSODescriptorElement sp =
                    manager.getSPSSODescriptor("/", spEntityID);
            List acsList = sp.getAssertionConsumerService();
            if ((acsList != null) && (!acsList.isEmpty())) {
                Iterator j = acsList.iterator();
                while (j.hasNext()) {
                    AssertionConsumerServiceElement acs =
                            (AssertionConsumerServiceElement) j.next();
                    if ((acs != null) && (acs.getBinding() != null)) {
                        String acsURL = acs.getLocation();
                        int loc = acsURL.indexOf(deployuri + "/");
                        if (loc == -1) {
                            continue;
                        } else {
                            fedletBaseUrl = acsURL.substring(
                                    0, loc + deployuri.length());
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            SAML2Utils.debug.error("couldn't get fedlet base url:", e);
        }
        return fedletBaseUrl;
    }

    public static Map getIDPBaseUrlAndMetaAlias(String idpEntityID, String deployuri) {
        Map returnMap = new HashMap();
        if (idpEntityID == null) {
            return returnMap;
        }
        String idpBaseUrl = null;
        try {
            // find out IDP meta alias
            SAML2MetaManager manager = new SAML2MetaManager();
            IDPSSODescriptorElement idp =
                    manager.getIDPSSODescriptor("/", idpEntityID);
            List ssoServiceList = idp.getSingleSignOnService();
            if ((ssoServiceList != null)
                    && (!ssoServiceList.isEmpty())) {
                Iterator i = ssoServiceList.iterator();
                while (i.hasNext()) {
                    SingleSignOnServiceElement sso =
                            (SingleSignOnServiceElement) i.next();
                    if ((sso != null) && (sso.getBinding() != null)) {
                        String ssoURL = sso.getLocation();
                        int loc = ssoURL.indexOf("/metaAlias/");
                        if (loc == -1) {
                            continue;
                        } else {
                            returnMap.put("idpMetaAlias", ssoURL.substring(loc + 10));
                            String tmp = ssoURL.substring(0, loc);
                            loc = tmp.lastIndexOf("/");
                            returnMap.put("idpBaseUrl", tmp.substring(0, loc));
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            SAML2Utils.debug.error("couldn't get IDP base url:", e);
        }
        return returnMap;
    }

    public static String getSpEntityID() {
        return spEntityID;
    }

    public static String getSpMetaAlias() {
        return spMetaAlias;
    }

    public static String getIdpEntityID() {
        return idpEntityID;
    }


}
