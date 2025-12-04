<%@ Page Language="C#" AutoEventWireup="true" %>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Kerberos Delegation Test</title>
    <style>
        body { font-family: Segoe UI, Arial; margin: 20px; }
        .ok { color: green; }
        .warn { color: darkorange; }
    </style>
</head>
<body>
    <h2>Kerberos Delegation Test</h2>
    <p><strong>User Identity:</strong> <%= System.Web.HttpContext.Current.User?.Identity?.Name ?? "N/A" %></p>
    <p><strong>Is Authenticated:</strong> <%= System.Web.HttpContext.Current.User?.Identity?.IsAuthenticated %></p>
    <p><strong>Authentication Type:</strong> <%= System.Web.HttpContext.Current.Request?.LogonUserIdentity?.AuthenticationType ?? "N/A" %></p>

    <% 
        var authType = (System.Web.HttpContext.Current.Request?.LogonUserIdentity?.AuthenticationType ?? "").ToLower();
        if (authType == "kerberos") { %>
            <p class="ok">Kerberos detected — delegation likely working.</p>
    <%  } else { %>
            <p class="warn">Kerberos NOT detected — delegation may not be working. Ensure Negotiate is used and SPNs/delegation configured.</p>
    <%  } %>
</body>
</html>
