import { ApiProperty } from "@nestjs/swagger";

export class LoginDTO {
  @ApiProperty({ default: 'john' })
  username: string;
  @ApiProperty({ default: 'changeme' })
  password: string;
}