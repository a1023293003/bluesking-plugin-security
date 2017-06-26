package cn.bluesking.plugin.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.bluesking.framework.security.exception.AuthcException;

/**
 * Security助手类
 * 
 * @author 随心
 *
 */
public final class SecurityHelper {

	/**
	 * slf4j日志配置
	 */
	private static final Logger _LOG = LoggerFactory.getLogger(SecurityHelper.class);
	
	/**
	 * 登录
	 * @param userName [String]用户名
	 * @param password [String]密码
	 * @throws AuthcException 认证失败异常
	 */
	public static void login(String userName, String password) throws AuthcException {
		Subject currentUser = SecurityUtils.getSubject();
		if(currentUser != null) {
			UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
			try {
				currentUser.login(token);
			} catch(AuthenticationException e) {
				_LOG.error("登录失败！", e);
				throw new AuthcException(e);
			}
		}
	}
	
	/**
	 * 注销
	 */
	public static void logout() {
		Subject currentUser = SecurityUtils.getSubject();
		if(currentUser != null) {
			currentUser.logout();
		}
	}

}
