import { Role } from 'src/users/enums/role.enum';
import { PermissionType } from '../authorization/permission.type';

export interface ActiveUserData {
  sub: number; // Value of the ID
  email: string;
  role: Role;
  permissions: PermissionType[];
}
