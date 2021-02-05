<%--
  - Copyright (C) 2005-2008 Jive Software. All rights reserved.
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
--%>
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="org.jivesoftware.openfire.user.*,
                 org.jivesoftware.openfire.plugin.RegistrationPlugin,
                 org.jivesoftware.util.*,
                 gnu.inet.encoding.Stringprep,
                 gnu.inet.encoding.StringprepException,
                 org.xmpp.packet.JID"
%>
<%@ page import="org.jivesoftware.openfire.plugin.ReCaptchaUtil" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>

<html>
<head>
    <title><fmt:message key="registration.sign.up.title" /></title>
    <link rel="stylesheet" type="text/css" href="/style/global.css">
    <style type="text/css">
        .drop-shadow {
             font-weight: bold;
             font-size: 14pt;
             color: #EEEEEE;
             text-shadow: black 0.1em 0.1em 0.2em;
             padding-top: 21px;
             padding-bottom: 1em;
        }
    </style>
    <meta name="decorator" content="none"/>
</head>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<jsp:useBean id="errors" class="java.util.HashMap" />
<%  webManager.init(request, response, session, application, out);

    boolean create = request.getParameter("create") != null;
    String username = ParamUtils.getParameter(request,"username");
    String name = ParamUtils.getParameter(request,"name");
    String email = ParamUtils.getParameter(request,"email");
    String password = ParamUtils.getParameter(request,"password");
    String passwordConfirm = ParamUtils.getParameter(request,"passwordConfirm");
    String recaptchaResponse = ParamUtils.getParameter(request,"g-recaptcha-response");

    RegistrationPlugin plugin = (RegistrationPlugin) webManager.getXMPPServer().getPluginManager().getPlugin("registration");

    // Handle a request to create a user:
    if (create) {
        // Validate
        if (username == null) {
            errors.put("username","");
        }
        else {
            try {
                username = username.trim().toLowerCase();
                username = JID.escapeNode(username);
                username = Stringprep.nodeprep(username);
            }
            catch (StringprepException se) {
                errors.put("username", "");
            }
        }
        if (password == null) {
            errors.put("password","");
        }
        if (passwordConfirm == null) {
            errors.put("passwordConfirm","");
        }
        if (password != null && passwordConfirm != null && !password.equals(passwordConfirm)) {
            errors.put("passwordMatch","");
        }
        if (ReCaptchaUtil.reCaptchaEnabled()) {
            if ( !ReCaptchaUtil.verify(recaptchaResponse, request.getRemoteAddr() ) ) {
                errors.put("reCaptchaFail","");
            }
        }

        // do a create if there were no errors
        if (errors.size() == 0) {
            try {
                webManager.getUserManager().createUser(username, password, name, email);
                
                response.sendRedirect("sign-up.jsp?success=true");
                return;
            }
            catch (UserAlreadyExistsException e) {
                errors.put("usernameAlreadyExists","");
            }
            catch (Exception e) {
                errors.put("general","");
                Log.error(e);
            }
        }
    }

    session.setAttribute("headerText", plugin.getHeader());
    session.setAttribute("username", username);
    session.setAttribute("name", name);
    session.setAttribute("email", email);
%>

<body>

<div id="jive-header">
<table cellpadding="0" cellspacing="0" width="100%" border="0">
    <tbody>
        <tr><td class="drop-shadow">&nbsp;<c:out value="${headerText}"/></td></tr>
    </tbody>
</table>
</div>

<div id="jive-content">

<% if (!plugin.webEnabled()) { %>

<fmt:message key="registration.sign.up.unavailable" />

<% } else { %>

<p><fmt:message key="registration.sign.up.instructions" /></p>

<c:set var="submit" value="${param.create}"/>
<c:set var="errors" value="${errors}"/>

<%  if (!errors.isEmpty()) { %>

    <div class="jive-error">
    <table cellpadding="0" cellspacing="0" border="0">
    <tbody>
        <tr>
            <td class="jive-icon"><img src="images/error-16x16.gif" width="16" height="16" border="0"/></td>
            <td class="jive-icon-label">

            <% if (errors.get("general") != null) { %>
                <fmt:message key="registration.sign.up.error_creating_account" />
            <% } else if (errors.get("username") != null) { %>
                <fmt:message key="registration.sign.up.invalid_username" />
            <% } else if (errors.get("usernameAlreadyExists") != null) { %>
                <fmt:message key="registration.sign.up.user_exist" />
            <% } else if (errors.get("name") != null) { %>
                <fmt:message key="registration.sign.up.invalid_name" />
            <% } else if (errors.get("email") != null) { %>
                <fmt:message key="registration.sign.up.invalid_email" />
            <% } else if (errors.get("password") != null) { %>
                <fmt:message key="registration.sign.up.invalid_password" />
            <% } else if (errors.get("passwordMatch") != null) { %>
                <fmt:message key="registration.sign.up.invalid_match_password" />
            <% } else if (errors.get("passwordConfirm") != null) { %>
                <fmt:message key="registration.sign.up.invalid_password_confirm" />
            <% } else if (errors.get("reCaptchaFail") != null) { %>
                <fmt:message key="registration.sign.up.recaptcha_fail" />
            <% } %>
            </td>
        </tr>
    </tbody>
    </table>
    </div>
    <br>

<%  } else if (request.getParameter("success") != null) { %>

    <div class="jive-success">
    <table cellpadding="0" cellspacing="0" border="0">
    <tbody>
        <tr>
            <td class="jive-icon"><img src="images/success-16x16.gif" width="16" height="16" border="0"></td>
            <td class="jive-icon-label"><fmt:message key="registration.sign.up.success" /></td>
        </tr>
    </tbody>
    </table>
    </div><br>

<%  } %>

<form id="signup" name="f" action="sign-up.jsp" method="get">

<div class="jive-contentBoxHeader"><fmt:message key="registration.sign.up.create_account" /></div>
<div class="jive-contentBox">
    <div>
    <table cellpadding="3" cellspacing="0" border="0" width="100%">
    <tbody>
    <tr>
        <td width="1%" nowrap><label for="usernametf"><fmt:message key="registration.sign.up.username" />:</label> *</td>
        <td width="99%">
            <input type="text" name="username" size="30" maxlength="75" value="${fn:escapeXml(username)}" id="usernametf" autocomplete="off">
        </td>
    </tr>
    <tr>
        <td width="1%" nowrap>
            <label for="nametf"><fmt:message key="registration.sign.up.name" />:</label>
        </td>
        <td width="99%">
            <input type="text" name="name" size="30" maxlength="75" value="${fn:escapeXml(name)}" id="nametf">
        </td>
    </tr>
    <tr>
        <td width="1%" nowrap>
            <label for="emailtf"><fmt:message key="registration.sign.up.email" />:</label></td>
        <td width="99%">
            <input type="text" name="email" size="30" maxlength="75" value="${fn:escapeXml(email)}" id="emailtf">
        </td>
    </tr>
    <tr>
        <td nowrap>
            <label for="passtf"><fmt:message key="registration.sign.up.password" />:</label> *
        </td>
        <td width="99%">
            <input type="password" name="password" value="" size="20" maxlength="75" id="passtf">
        </td>
    </tr>
    <tr>
        <td width="1%" nowrap>
            <label for="confpasstf"><fmt:message key="registration.sign.up.confirm_password" />:</label> *
        </td>
        <td width="99%">
            <input type="password" name="passwordConfirm" value="" size="20" maxlength="75" id="confpasstf">
        </td>
    </tr>
    </tbody>
    </table>
    <br>
    <span class="jive-description">
    * <fmt:message key="registration.sign.up.required_fields" />
    </span>
    </div>
</div>

<% if (ReCaptchaUtil.reCaptchaEnabled()) { %>
    <button class="g-recaptcha" data-sitekey="<%=StringUtils.escapeHTMLTags(ReCaptchaUtil.getReCaptchaSiteKey())%>" data-callback='onSubmit' data-action='submit'><fmt:message key="registration.sign.up.create_account" /></button>
<% } else { %>
    <button data-callback='onSubmit' data-action='submit'><fmt:message key="registration.sign.up.create_account" /></button>
<% } %>

    <input type="hidden" name="create" value="true"/>
</form>

<%  if (ReCaptchaUtil.reCaptchaEnabled()) { %>
<script src="https://www.google.com/recaptcha/api.js"></script>
<%  } %>

<script>
function onSubmit(token) {
    document.getElementById("signup").submit();
}

document.f.username.focus();
</script>

<% } %>

</body>
</html>
