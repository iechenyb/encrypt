package com;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.utils.JsonUtil;
import com.utils.RSAUtils;

/**
 * Servlet implementation class JieMiServlet
 */
public class JieMiServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// 获取数据
		String uname = request.getParameter("uname");
		String password = request.getParameter("password");
		String PRIVATEKEY = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAj3hZfehWrrwTIRrfdKSDDFp1E5PPWW+xdEAQwWGEtWLrpeU9zm1SIo5w4azPf0JF54q0LcqGDFlLeqHKMJe7OwIDAQABAkB2fw9jN6/ImFwwXpKrM2ltnZTPO6jplJ/7hSKRpirG6JSfNOQGV4JyinzoarDx6jSYwpAv7DMmC6ccxIfq6bqBAiEAzZdRjGCs6Fe3gh+s/Ck+a6KZhUI9Nvnqd4Bvl8lFakECIQCypceOGA00ygubaBSP+yvUAy2v8kyP/e1Pvq613aYuewIgMOwAGMJsgsFUxp8Y/8wksWI42+/+NxXTSGqEo37eiMECIF5ZV48f/LmIi6DD0zhHeto544MtAGp7vT2Eg1jhesbJAiEAk2iVqqG/NN071k78bN8dfYqP13V9bMF4ip28ZXIRKMg=";
		// 解密
		uname = RSAUtils.decryptDataOnJava(uname, PRIVATEKEY);
		password = RSAUtils.decryptDataOnJava(password, PRIVATEKEY);
		// 用map封装返回的数据
		HashMap<String, Object> result = new HashMap<String, Object>();
		result.put("uname", uname);
		result.put("password", password);

		response.getWriter().print(JsonUtil.toJson(result));

	}

}
