<%--
  Created by IntelliJ IDEA.
  User: Administrator
  Date: 11/27/11
  Time: 5:11 PM
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head><title>Simple jsp page</title></head>
  <body>
    <a href="<%=request.getSession().getAttribute("logoutUrl")%>">Logout</a>
  </body>
</html>