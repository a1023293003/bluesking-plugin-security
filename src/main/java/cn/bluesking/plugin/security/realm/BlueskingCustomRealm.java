package cn.bluesking.plugin.security.realm;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

import cn.bluesking.framework.security.BlueskingSecurity;
import cn.bluesking.plugin.security.SecurityConstant;
import cn.bluesking.plugin.security.password.Md5CredentialsMatcher;

/**
 * 基于Bluesking的自定义Realm
 * <br/>
 * (需要实现BlueskingSecurity接口)
 * 
 * @author 随心
 *
 */
public class BlueskingCustomRealm extends AuthorizingRealm {

	private final BlueskingSecurity blueskingSecurity;
	
	/**
	 * 附带初始化的构造方法
	 * @param blueskingSecurity
	 */
	public BlueskingCustomRealm(BlueskingSecurity blueskingSecurity) {
		this.blueskingSecurity = blueskingSecurity;
		super.setName(SecurityConstant.REALMS_CUSTOM);
		// 使用MD5加密算法
		super.setCredentialsMatcher(new Md5CredentialsMatcher());
	}
	
	/**
	 * 获取用户角色名集合以及权限名集合(用于授权)
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		if(principals == null) {
			throw new AuthorizationException("当事人信息参数不能为空！");
		}
		
		// 获取已认证用户的用户名
		String userName = (String) super.getAvailablePrincipal(principals);
		
		// 通过BlueskingSecurity接口并根据用户名获取角色名集合
		Set<String> roleNameSet = this.blueskingSecurity.getRoleNameSet(userName);
		
		// 通过BlueskingSecurity接口并根据用户角色名获取权限名集合
		Set<String> permissionNameSet = new HashSet<String>();
		
		if(roleNameSet != null && roleNameSet.size() > 0) {
			for(String roleName : roleNameSet) {
				Set<String> currentPermissionNameSet = 
						this.blueskingSecurity.getPermissionNameSet(roleName);
				permissionNameSet.addAll(currentPermissionNameSet);
			}
		}
		
		// 将角色名集合与权限名集合放入AuthorizationInfo对象中,便于后续授权操作
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		authorizationInfo.setRoles(roleNameSet);
		authorizationInfo.setStringPermissions(permissionNameSet);
		return authorizationInfo;
	}

	/**
	 * 获取表单用户名及对应数据库密码(用于认证)
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) 
			throws AuthenticationException {
		if(token == null) {
			throw new AuthorizationException("用户身份标识参数不可为空！");
		}
		
		// 通过AuthenticationToken对象获取表单提交的用户名
		String userName = ((UsernamePasswordToken) token).getUsername();
		
		// 通过BlueskingSecurity接口并根据用户名获取数据库中存放的密码
		String password = this.blueskingSecurity.getPassword(userName);
		
		// 将用户名密码放入AuthenticationInfo对象中,便于后续的认证操作
		SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo();
		authenticationInfo.setPrincipals(new SimplePrincipalCollection(userName, super.getName()));
		authenticationInfo.setCredentials(password);
		return authenticationInfo;
	}

}
