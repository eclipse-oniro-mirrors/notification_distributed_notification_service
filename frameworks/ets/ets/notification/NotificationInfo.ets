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
import { NotificationExtensionContent } from 'notification.NotificationExtensionContent';

export interface NotificationInfo {
  readonly hashCode: string;
  readonly notificationSlotType: notificationManager.SlotType;
  readonly content: NotificationExtensionContent;
  readonly bundleName: string;
  readonly appName?: string;
  readonly deliveryTime?: long;
  readonly groupName?: string;
  readonly appIndex: int;
}

class NotificationInfoInner implements NotificationInfo {
  public readonly hashCode: string = '';
  public readonly notificationSlotType: notificationManager.SlotType = 
      notificationManager.SlotType.UNKNOWN_TYPE;
  public readonly content: NotificationExtensionContent = { title: '', text: '' }
  public readonly bundleName: string = '';
  public readonly appName?: string | undefined;
  public readonly deliveryTime?: long | undefined;
  public readonly groupName?: string | undefined;
  public readonly appIndex: int = 0;
}