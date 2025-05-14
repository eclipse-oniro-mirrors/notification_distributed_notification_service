/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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