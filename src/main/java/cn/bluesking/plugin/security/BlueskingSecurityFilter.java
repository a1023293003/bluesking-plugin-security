package cn.bluesking.plugin.security;

import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroFilter;

import cn.bluesking.framework.security.BlueskingSecurity;
import cn.bluesking.plugin.security.realm.BlueskingCustomRealm;
import cn.bluesking.plugin.security.realm.BlueskingJdbcRealm;

/**
 * 安全过滤器
 * 
 * @author 随心
 *
 */
public class BlueskingSecurityFilter extends ShiroFilter {

	@Override
	public void init() throws Exception {
		super.init();
		WebSecurityManager webSecurityManager = super.getSecurityManager();
		// 设置Realm,可以同时支持多个Realm,并按照先后顺序用逗号分隔
		setRealm(webSecurityManager);
	}
	
	/**
	 * 设置Realm
	 * @param webSecurityManager
	 */
	private void setRealm(WebSecurityManager webSecurityManager) {
		// 读取bluesking.plugin.security.realms配置项
		String securityRealms = SecurityConfig.getRealms();
		if(securityRealms != null) {
			// 根据逗号进行拆分
			String[] securityRealmsArray = securityRealms.split(",");
			if(securityRealmsArray.length > 0) {
				// 使Realm具备唯一性与顺序行
				Set<Realm> realms = new LinkedHashSet<Realm>();
				for(String securityRealm : securityRealmsArray) {
					if(securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_JDBC)) {
						// 添加基于JDBC的Realm,需配置相关SQL查询语句
						addJDBCRealm(realms);
					} else if(securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_CUSTOM)) {
						// 添加基于定制化的Realm,需要实现BlueskingSercurity接口
						addCustomRealm(realms);
					}
				}
				RealmSecurityManager realmSecurityManager = (RealmSecurityManager) webSecurityManager;
				// 设置Realm
				realmSecurityManager.setRealms(realms);
			}
		}
	}
	
	/**
	 * 添加JDBC数据域
	 * @param realms
	 */
	private void addJDBCRealm(Set<Realm> realms) {
		// 添加自己实现的基于JDBC的Realm
		BlueskingJdbcRealm blueskingJdbcRealm = new BlueskingJdbcRealm();
		realms.add(blueskingJdbcRealm);
	}
	
	/**
	 * 添加用户自定义数据域
	 * @param realms
	 */
	private void addCustomRealm(Set<Realm> realms) {
		// 读取bluesking.plugin.security.custom.class配置项
		BlueskingSecurity blueskingSecurity = SecurityConfig.getBlueskingSecurity();
		// 添加自己实现的Realm
		BlueskingCustomRealm blueskingCustomRealm = new BlueskingCustomRealm(blueskingSecurity);
		realms.add(blueskingCustomRealm);
	}
	
	/**
	 * 设置缓存
	 * @param webSecurityManager
	 */
	private void setCache(WebSecurityManager webSecurityManager) {
		// 读取bluesking.plugin.security.cache配置项
		if(SecurityConfig.isCacheable()) {
			CachingSecurityManager cachingSecurityManager = (CachingSecurityManager) webSecurityManager;
			// 使用基于内存的CacheManager
			CacheManager cacheManager = new MemoryConstrainedCacheManager();
			cachingSecurityManager.setCacheManager(cacheManager);
		}
	}
	
}
