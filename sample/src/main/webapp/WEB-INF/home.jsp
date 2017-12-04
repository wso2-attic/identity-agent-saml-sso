<%-- 
    Document   : home
    Created on : Nov 7, 2017, 8:52:49 AM
    Author     : chiran
--%>
<%@page import="java.util.Iterator"%>
<%@page import="java.util.Map"%>
<%
    String logoutUrl = request.getSession().getAttribute("logoutUrl").toString();
    String principalName = request.getUserPrincipal().getName();
    String claims = " ";

    Map<String, String> claimsMap = (Map) request.getSession().getAttribute("claimsMap");
    for (Map.Entry entry : claimsMap.entrySet()) {
        claims += entry.getKey() + ", " + entry.getValue()+"</br>";
    }   
%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Home Page</title>
    </head>
    <body>
        <h1  style="text-align:center;"><img style="height:50px;width:50px;" src="images/greenTick.png">
            You have successfully logged in!</h1>
        <p>principal is <%=principalName%></p>
        <p>values in your claim map are as follows:</br><%=claims%></p>
        <h3>Click <a href="<%=logoutUrl%>"> here</a> to logout</h3>
    </body>
</html>
