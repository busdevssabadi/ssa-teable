import {
  Body,
  ConflictException,
  Controller,
  Delete,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { generateUserId, SYSTEM_USER_ID } from '@teable/core';
import { PrismaService } from '@teable/db-main-prisma';
import * as bcrypt from 'bcrypt';
import { z } from 'zod';
import { SsaConfig } from '../../configs/ssa.config';
import type { ISsaConfig } from '../../configs/ssa.config';
import { ZodValidationPipe } from '../../zod.validation.pipe';
import { Public } from '../auth/decorators/public.decorator';
import { NotificationService } from '../notification/notification.service';
import { ssaNotifyRoSchema } from './ssa-notify.dto';
import type { ISsaNotifyRo } from './ssa-notify.dto';
import { SsaTokenGuard } from './ssa-token.guard';

const passwordSchema = z
  .string()
  .min(8, 'Minimum 8 chars')
  .regex(/^(?=.*[A-Z])(?=.*\d).{8,}$/i, 'Must contain at least one letter and one number');

const createUserSchema = z.object({
  email: z.string().trim().email(),
  password: passwordSchema,
  name: z.string().trim().min(1).max(100).optional(),
});

const resetPasswordSchema = z.object({
  password: passwordSchema,
});

type ICreateUserRo = z.infer<typeof createUserSchema>;
type IResetPasswordRo = z.infer<typeof resetPasswordSchema>;

/**
 * Internal API for SSA companion services (notify/ai/voice). Everything here
 * is `@Public()` for the *user* auth guard but protected by the shared-secret
 * `SsaTokenGuard` instead; with no token configured the routes fail closed.
 */
@Controller('api/ssa')
@Public()
@UseGuards(SsaTokenGuard)
export class SsaController {
  constructor(
    @SsaConfig() private readonly ssaConfig: ISsaConfig,
    private readonly notificationService: NotificationService,
    private readonly prismaService: PrismaService
  ) {}

  /** Liveness/config probe for companion services. */
  @Get('health')
  health(): {
    ok: boolean;
    singleTenant: boolean;
    eventsForwarding: boolean;
    timestamp: string;
  } {
    return {
      ok: true,
      singleTenant: this.ssaConfig.singleTenant,
      eventsForwarding: Boolean(this.ssaConfig.events.webhookUrl),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Creates an in-app (bell) notification and pushes it over the realtime
   * channel. Optionally emails the recipients when `emailConfig` exists on
   * their profile — emails are handled by the notify service itself.
   */
  @Post('notify')
  @HttpCode(200)
  async notify(@Body(new ZodValidationPipe(ssaNotifyRoSchema)) ro: ISsaNotifyRo) {
    return this.notificationService.sendCommonNotify({
      toUserId: ro.toUserId,
      toEmail: ro.toEmail,
      message: ro.message,
      severity: ro.severity,
      path: ro.path,
      fromUserId: ro.fromUserId ?? SYSTEM_USER_ID,
    });
  }

  /**
   * Admin-only user management for the SSA-Allowlist portal. The portal calls
   * these routes server-to-server with the shared `X-SSA-Token`; accounts are
   * written directly to the Teable Postgres with bcrypt password hashes.
   */
  @Get('admin/users')
  async listAdminUsers() {
    const users = await this.prismaService.user.findMany({
      where: { isSystem: null, isAdmin: null, deletedTime: null },
      select: {
        id: true,
        email: true,
        name: true,
        createdTime: true,
        lastSignTime: true,
      },
      orderBy: { createdTime: 'desc' },
    });

    return { users };
  }

  @Post('admin/users')
  @HttpCode(200)
  async createAdminUser(@Body(new ZodValidationPipe(createUserSchema)) ro: ICreateUserRo) {
    const email = ro.email.trim().toLowerCase();
    const existing = await this.prismaService.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(ro.password, salt);

    const user = await this.prismaService.user.create({
      data: {
        id: generateUserId(),
        email,
        name: ro.name?.trim() || email.split('@')[0],
        salt,
        password,
        notifyMeta: JSON.stringify({ email: true }),
        isAdmin: null,
        isSystem: null,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdTime: true,
        lastSignTime: true,
      },
    });

    return { user };
  }

  @Patch('admin/users/:id/password')
  @HttpCode(200)
  async resetAdminUserPassword(
    @Param('id') id: string,
    @Body(new ZodValidationPipe(resetPasswordSchema)) ro: IResetPasswordRo
  ) {
    const user = await this.prismaService.user.findFirst({
      where: { id, isSystem: null, isAdmin: null, deletedTime: null },
      select: { id: true },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(ro.password, salt);
    await this.prismaService.user.update({
      where: { id },
      data: { salt, password },
    });

    return { ok: true };
  }

  @Delete('admin/users/:id')
  @HttpCode(200)
  async deleteAdminUser(@Param('id') id: string) {
    const user = await this.prismaService.user.findFirst({
      where: { id, isSystem: null, isAdmin: null, deletedTime: null },
      select: { id: true },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const suffix = Math.random().toString(36).slice(2, 12);
    await this.prismaService.$tx(async () => {
      const prisma = this.prismaService.txClient();
      await prisma.accessToken.deleteMany({ where: { userId: id } });
      await prisma.account.deleteMany({ where: { userId: id } });
      await prisma.collaborator.deleteMany({ where: { principalId: id } });
      await prisma.userLastVisit.deleteMany({ where: { userId: id } });
      await prisma.user.update({
        where: { id },
        data: {
          email: `deleted-${suffix}@teable.ai`,
          name: 'Deleted User',
          deletedTime: new Date(),
          deactivatedTime: new Date(),
          permanentDeletedTime: new Date(),
        },
      });
    });

    return { ok: true };
  }
}
