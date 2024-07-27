import { Role } from 'src/users/enums/role.enum';

export interface ActiveUserData {
  sub: number; // Value of the ID
  email: string;
  role: Role;
}
