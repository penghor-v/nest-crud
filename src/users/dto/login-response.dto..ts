import { ApiProperty } from '@nestjs/swagger';

export class LoginResponseDto {
  @ApiProperty({ description: 'JWT access token' }) // Swagger decorator
  access_token: string;

  //   @ApiProperty({ description: 'User ID' })
  //   userId: string;

  //   @ApiProperty({ description: 'User Role', enum: ['User', 'Admin'] }) // Example using enum
  //   role: string;

  //   // Add other properties as needed (e.g., user's name, email, etc.)
  //   @ApiProperty({ description: "User's username" })
  //   username: string;
}
