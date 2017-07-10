package cn.bluesking.plugin.security.tag;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.tags.RoleTag;

/**
 * 判断当前用户是否拥有其中所有权限(逗号分隔,表示"与"的关系)
 * 
 * @author 随心
 *
 */
public class HasAnyPermissionsTag extends RoleTag {

	/**
	 * 权限名分隔符
	 */
	private static final String PERMISSION_NAMES_DELIMITER = ",";
	
	@Override
	protected boolean showTagBody(String permissionName) {
		boolean hasAnyPermission = false;
		Subject subject = getSubject();
		if(subject != null) {
			String[] permissions = permissionName.split(PERMISSION_NAMES_DELIMITER);
			for(String permission : permissions) {
				if(subject.isPermitted(permission)) {
					hasAnyPermission = true;
					break;
				}
			}
		}
		return hasAnyPermission;
	}

}
