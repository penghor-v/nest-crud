import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Get,
  Res,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from 'src/jwt-auth/jwt-auth.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { plainToClass } from 'class-transformer';
import { validateOrReject } from 'class-validator';
import { LoginDto } from 'src/users/dto/login.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { User } from 'src/schemas/user.schema';
import { LoginResponseDto } from 'src/users/dto/login-response.dto.';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: CreateUserDto })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 401, description: 'Bad Request' })
  async register(@Body() createdUserDto: CreateUserDto, @Res() res) {
    try {
      const validatedUserDto = plainToClass(CreateUserDto, createdUserDto);
      await validateOrReject(validatedUserDto);

      const newUser = await this.authService.register(
        validatedUserDto.username,
        validatedUserDto.email,
        validatedUserDto.password,
      );
      return res.status(HttpStatus.CREATED).json(newUser);
    } catch (error) {
      console.error('Error during registration:', error);
      return res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: 'Registration failed' });
    }
  }

  @Post('login')
  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successfull',
    type: LoginResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async login(@Body() loginDto: LoginDto, @Res() res) {
    try {
      const validatedLoginDto = plainToClass(LoginDto, loginDto);
      await validateOrReject(validatedLoginDto);

      const user = await this.authService.validateUser(
        validatedLoginDto.email,
        validatedLoginDto.password,
      );
      if (!user) {
        return res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ message: 'Invalid credential' });
      }

      const loginResponse = await this.authService.login(user);
      return res.status(HttpStatus.OK).json(loginResponse);
    } catch (error) {
      console.error('Error during login:', error);
      return res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: 'Login failed' });
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'User profile', type: User })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@Request() req) {
    return req.user;
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('refresh')
  @HttpCode(200)
  async refresh(@Request() req, @Res() res) {
    try {
      const user = req.user;
      const tokens = await this.authService.refreshTokens(
        user.userId,
        user.refreshToken,
      );
      res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true });

      return res.json({ accessToken: tokens.accessToken });
    } catch (error) {
      console.error('Error refreshing token:', error);
      return res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: 'Refresh failed' });
    }
  }
}
