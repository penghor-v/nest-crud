import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from 'src/schemas/user.schema';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async register(username: string, email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new this.userModel({
      username,
      email,
      password: hashedPassword,
    });
    return user.save();
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userModel.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async login(user: any) {
    const payload = {
      email: user.email,
      sub: user._id,
      userId: user._id.toString(),
      role: user.role,
    };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '1m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '10m' });
    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshTokens(userId: string, rt: string) {
    const user = await this.usersService.findOne(userId);
    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Refresh token is not valid');
    }
    // compare the refresh token in the request body with the one stored in the DB
    if (!(await bcrypt.compare(rt, user.hashedRefreshToken))) {
      throw new UnauthorizedException('Refresh token is not valid');
    }

    const payload = {
      email: user.email,
      sub: user._id,
      userId: user._id.toString(),
      role: user.role,
    };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '1h' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    // Hash the refresh token before storing in DB
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.usersService.updateRefreshToken(userId, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }
}
