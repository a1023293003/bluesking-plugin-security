package cn.bluesking.plugin.security;

import cn.bluesking.framework.helper.ConfigHelper;
import cn.bluesking.framework.security.BlueskingSecurity;
import cn.bluesking.framework.util.ReflectionUtil;

/**
 * 从配置文件中获取相关属性
 * 
 * @author 随心
 *
 */
public final class SecurityConfig {

	public static String getRealms() {
		return ConfigHelper.getString(SecurityConstant.REALMS);
	}

	/**
	 * 获取配置文件中根据用户名查询密码的SQL语句
	 * @return
	 */
	public static String getJdbcAuthcQuery() {
		return ConfigHelper.getString(SecurityConstant.JDBC_AUTHC_QUERY);
	}
	
	/**
	 * 获取配置文件中根据用户名查询角色名集合的SQL语句
	 * @return
	 */
	public static String getJdbcRolesQuey() {
		return ConfigHelper.getString(SecurityConstant.JDBC_ROLES_QUERY);
	}
	
	/**
	 * 获取配置文件中根据角色名查询权限名集合的SQL语句
	 * @return
	 */
	public static String getJdbcPermissionQuery() {
		return ConfigHelper.getString(SecurityConstant.JDBC_PERMISSIONS_QUERY);
	}
	
	/**
	 * 是否开启缓存
	 * @return
	 */
	public static boolean isCacheable() {
		return ConfigHelper.getBoolean(SecurityConstant.CACHE);
	}

	/**
	 * 获取BlueskingSecurity接口实现类
	 * @return
	 */
	public static BlueskingSecurity getBlueskingSecurity() {
		String className = ConfigHelper.getString(SecurityConstant.BLUESKING_SECURITY);
		return (BlueskingSecurity) ReflectionUtil.newInstance(className);
	}
}
