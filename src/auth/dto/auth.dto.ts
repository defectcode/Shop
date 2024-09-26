import { IsEmail, isEmail, IsOptional, isString, IsString, MinLength } from "class-validator";

export class AuthDto {
    @IsOptional()
    @IsString()
    name: string

    @IsString({
        message: 'Email is compulsory'
    })

    @IsEmail()
    email: string

    @MinLength(6, {
        message: 'The password must be no less than 6 characters'
    })
    @IsString ({
        message: 'Password is compulsory'
    })
    password: string
}