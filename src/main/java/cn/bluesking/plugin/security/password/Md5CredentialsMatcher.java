package cn.bluesking.plugin.security.password;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

import cn.bluesking.framework.util.CodecUtil;

/**
 * MD5密码匹配器
 * 
 * @author 随心
 *
 */
public class Md5CredentialsMatcher implements CredentialsMatcher {

	/**
	 * 密码匹配其核心逻辑
	 */
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		// 获取表单提交的密码,明文,尚未加密
		String submitted = String.valueOf(((UsernamePasswordToken) token).getPassword());
		// 获取数据库中存储的密码,已通过MD5加密
		String encrypted = String.valueOf(info.getCredentials());
		return CodecUtil.md5(submitted).equals(encrypted);
	}

}
