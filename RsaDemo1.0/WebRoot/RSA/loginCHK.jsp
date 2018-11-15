<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8"%>

<jsp:directive.page import="RSA.LoginAction"/>

<%
LoginAction la = new LoginAction();
la.execute(request ,response);
%>
pwd is [<%=request.getAttribute("pwd")%>]