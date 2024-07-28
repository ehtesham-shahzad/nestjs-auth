import {
  Permission,
  PermissionType,
} from 'src/iam/authorization/permission.type';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { Role } from '../enums/role.enum';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ enum: Role, default: Role.Regular, type: 'enum' })
  role: Role;

  /**
   * In read world application we should have a dedicated permissions
   * table to store application specific permission.
   * Instead of storing permissions in a single column, there would be a Many to Many relation between user and permissions table.
   */
  @Column({ enum: Permission, default: [], type: 'json' })
  permissions: PermissionType[];
}
