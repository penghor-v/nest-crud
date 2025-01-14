import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

export enum Role {
  User = 'User',
  Admin = 'Admin',
}

@Schema()
export class User extends Document {
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: Role.User, enum: Role })
  role: Role;

  @Prop({ type: String, required: false }) // Optional
  hashedRefreshToken?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
