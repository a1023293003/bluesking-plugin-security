package cn.bluesking.plugin.security.realm;

import org.apache.shiro.realm.jdbc.JdbcRealm;

import cn.bluesking.framework.helper.DatabaseHelper;
import cn.bluesking.plugin.security.SecurityConfig;
import cn.bluesking.plugin.security.password.Md5CredentialsMatcher;

/**
 * 基于Bluesking的JDBC Realm
 * <br/>
 * (需提供bluesking.plugin.security.jdbc.*配置项)
 * 
 * @author 随心
 *
 */
public class BlueskingJdbcRealm extends JdbcRealm {

	public BlueskingJdbcRealm() {
		super.setDataSource(DatabaseHelper.getDataSource());
		super.setAuthenticationQuery(SecurityConfig.getJdbcAuthcQuery());
		super.setUserRolesQuery(SecurityConfig.getJdbcRolesQuey());
		super.setPermissionsQuery(SecurityConfig.getJdbcPermissionQuery());
		// 开启后可连接permission表进行查询
		super.setPermissionsLookupEnabled(true);
		// 用MD5加密
		super.setCredentialsMatcher(new Md5CredentialsMatcher());
	}
}
