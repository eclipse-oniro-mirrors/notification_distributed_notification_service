import type notificationManager from '@ohos.notificationManager';

export interface NotificationSlot {
  notificationType?: notificationManager.SlotType;
  notificationLevel?: notificationManager.SlotLevel;
  desc?: string;
  badgeFlag?: boolean;
  bypassDnd?: boolean;
  lockscreenVisibility?: number;
  vibrationEnabled?: boolean;
  sound?: string;
  lightEnabled?: boolean;
  lightColor?: number;
  vibrationValues?: Array<number>;
  readonly enabled?: boolean;
  readonly reminderMode?: number;
  readonly authorizedStatus?: number;
}

class NotificationSlotInner implements NotificationSlot {
  notificationType?: notificationManager.SlotType;
  notificationLevel?: notificationManager.SlotLevel;
  desc?: string;
  badgeFlag?: boolean;
  bypassDnd?: boolean;
  lockscreenVisibility?: number;
  vibrationEnabled?: boolean;
  sound?: string;
  lightEnabled?: boolean;
  lightColor?: number;
  vibrationValues?: Array<number>;
  readonly enabled?: boolean;
  readonly reminderMode?: number;
  readonly authorizedStatus?: number;
}