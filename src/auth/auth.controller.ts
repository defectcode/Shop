import { Body, Controller, Get, HttpCode, Post, Req, Res, UnauthorizedException, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Request, Response, response } from 'express';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UsePipes(new ValidationPipe())
  @HttpCode(200)
  @Post('login')

  async login(
    @Body() dto: AuthDto, 
    @Res({passthrough: true}) res: Response
  ) {
    const { refreshToken, ...response} = await this.authService.login(dto)

    this.authService.addRefrashTokenToResponse(res, refreshToken)

    return response
  }

  @UsePipes(new ValidationPipe())
  @HttpCode(200)
  @Post('register')

  async register(
    @Body() dto: AuthDto,
    @Res({ passthrough: true}) res: Response
  ){
    const { refreshToken, ...response } = await this.authService.register(dto)

    this.authService.addRefrashTokenToResponse(res, refreshToken)

    return response
  }

  @UsePipes(new ValidationPipe())
  @HttpCode(200)
  @Post('login/access-token')

  async getNewTOkens(
    @Req() req: Request,
    @Res({ passthrough: true}) res: Response
  ){
    const refreshTokenFromCookies = req.cookies[this.authService.REFRESH_TOKEN_NAME]
    
    if(!refreshTokenFromCookies) {
      this.authService.removeRefreshTonekFromResponse(res)
      throw new UnauthorizedException("Refresh token it didn't pass")
    }

    const { refreshToken, ...response } = await this.authService.getNewTokens(refreshTokenFromCookies)

    this.authService.addRefrashTokenToResponse(res, refreshToken)

    return response
  }

  @HttpCode(200)
  @Post('logout')
  async logout(@Res({ passthrough: true}) res: Response) {
    this.authService.removeRefreshTonekFromResponse(res)
    return true
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(
    @Req() req: any,
    @Res({ passthrough: true }) res: Response
) {
  const { refreshToken, ...response } = await this.authService.validateOAuthLogin(req)

  this.authService.addRefrashTokenToResponse(res, refreshToken)

  return res.redirect(
    `${process.env['CLIENT_URL']}/dashboard?accessToken=${response.accessToken}`
  )
}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() _req) {}
}
