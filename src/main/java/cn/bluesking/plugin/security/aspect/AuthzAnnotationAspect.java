package cn.bluesking.plugin.security.aspect;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

import cn.bluesking.framework.annotation.Aspect;
import cn.bluesking.framework.annotation.Controller;
import cn.bluesking.framework.proxy.AspectProxy;
import cn.bluesking.framework.security.exception.AuthzException;
import cn.bluesking.plugin.security.annotation.User;

/**
 * 授权注解切面
 * 
 * @author 随心
 *
 */
@Aspect(Controller.class)
public class AuthzAnnotationAspect extends AspectProxy {

	/**
	 * 定义一个基于授权功能的注解类数组
	 */
	private static final Class[] ANNOTATION_CLASS_ARRAY = {
			User.class
	};
	
	/**
	 * 前置增强
	 */
	@Override
	public void before(Class<?> cls, Method method, Object[] params) throws Throwable {
		// 从目标类中获取对应的注解
		Annotation annotation = this.getAnnotation(cls, method);
		if(annotation != null) {
			// 判断注解类型
			Class<?> annotationType = annotation.annotationType();
			if(annotationType.equals(User.class)) {
				this.handleUser();
			}
		}
	}
	
	/**
	 * 从目标类与目标方法种获取相应的注解
	 * @param cls [Class<?>]目标类
	 * @param method [Method]目标方法
	 * @return [Annotation]找到则返回注解对象，否则返回null
	 */
	private Annotation getAnnotation(Class<?> cls, Method method) {
		// 遍历所有授权注解
		for(Class<? extends Annotation> annotationClass : ANNOTATION_CLASS_ARRAY) {
			// 首先判断目标方法上是否带有授权注解
			if(method.isAnnotationPresent(annotationClass)) {
				return method.getAnnotation(annotationClass);
			}
			// 然后判断目标类上是否带有授权注解
			if(cls.isAnnotationPresent(annotationClass)) {
				return cls.getAnnotation(annotationClass);
			}
		}
		// 若目标方法与目标类上均为带有授权注解，则返回空对象
		return null;
	}
	
	/**
	 * 判断用户是否已登录
	 * @throws AuthzException
	 */
	private void handleUser() throws AuthzException {
		Subject currentUser = SecurityUtils.getSubject();
		PrincipalCollection principals = currentUser.getPrincipals();
		if(principals == null || principals.isEmpty()) {
			throw new AuthzException("当前用户尚未登录");
		}
	}
}
