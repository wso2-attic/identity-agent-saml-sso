<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Index Page</title>
        <link rel="stylesheet" href="css/style.css">
    </head>
    <body>
        <h2 style="text-align:center;font-size: 24px;color:red;">${message}<h2>
        <h2 style="text-align:center;font-size: 22px;">Choose your preferred mode of login to <img src="images/wso2-is.gif"/></h2>
        <div class="login-page">
            <div class="form">
              <form class="login-form">
                 <h2><a href="${pageContext.request.getContextPath()}/samlsso">Login via SAML SSO Agent</a></h2>
              </form>
            </div>
        </div>
    </body>
</html>
