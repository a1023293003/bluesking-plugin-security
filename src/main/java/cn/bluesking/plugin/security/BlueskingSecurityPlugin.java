package cn.bluesking.plugin.security;

import java.util.Set;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.apache.shiro.web.env.EnvironmentLoaderListener;

/**
 * Bluesking Security插件
 * 
 * @author 随心
 *
 */
public class BlueskingSecurityPlugin implements ServletContainerInitializer {

	@Override
	public void onStartup(Set<Class<?>> handlesType, ServletContext servletContext) throws ServletException {
		// 初始化参数
		servletContext.setInitParameter("shiroConfigLocations", "classpath:bluesking-security.ini");
		// 注册Listener
		servletContext.addListener(EnvironmentLoaderListener.class);
		// 注册Filter
		FilterRegistration.Dynamic blueskingSecurityFilter = servletContext.addFilter(
				"BlueskingSecurityFilter", BlueskingSecurityFilter.class);
		blueskingSecurityFilter.addMappingForUrlPatterns(null, false, "/*");
	}

}
