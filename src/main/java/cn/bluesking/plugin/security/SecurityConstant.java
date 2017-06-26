package cn.bluesking.plugin.security;

/**
 * 常量接口
 * 
 * @author 随心
 *
 */
public interface SecurityConstant {

	public final static String REALMS = "bluesking.plugin.security.realms";
	public final static String REALMS_JDBC = "jdbc";
	public final static String REALMS_CUSTOM = "custom";
	
	
	public final static String BLUESKING_SECURITY = "bluesking.plugin.security.custom.class";
	
	
	public final static String JDBC_AUTHC_QUERY = "bluesking.plugin.security.jdbc.authc_query";
	public final static String JDBC_ROLES_QUERY = "bluesking.plugin.security.jdbc.roles_query";
	public final static String JDBC_PERMISSIONS_QUERY = "bluesking.plugin.security.jdbc.permissions_query";
	
	
	public final static String CACHE = "bluesking.plugin.security.cache";
	
}
