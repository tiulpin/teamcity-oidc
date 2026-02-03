<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>

<tr>
    <th><label for="oidc.audience">Audience: <l:star/></label></th>
    <td>
        <props:textProperty name="oidc.audience" className="longField"/>
        <span class="smallNote">
            The audience claim (<code>aud</code>) for the OIDC token.<br/>
            Examples: <code>sts.amazonaws.com</code> (AWS), <code>https://iam.googleapis.com/...</code> (GCP)
        </span>
        <span class="error" id="error_oidc.audience"></span>
    </td>
</tr>

<tr class="advancedSetting">
    <th><label for="oidc.env.var">Environment Variable:</label></th>
    <td>
        <props:textProperty name="oidc.env.var" className="mediumField"/>
        <span class="smallNote">
            Environment variable name for the OIDC token. Default: <code>TEAMCITY_OIDC_TOKEN</code>
        </span>
    </td>
</tr>

<tr class="advancedSetting">
    <th><label for="oidc.parameter">Build Parameter:</label></th>
    <td>
        <props:textProperty name="oidc.parameter" className="mediumField"/>
        <span class="smallNote">
            Build parameter name for the OIDC token. Default: <code>teamcity.oidc.token</code>
        </span>
    </td>
</tr>
