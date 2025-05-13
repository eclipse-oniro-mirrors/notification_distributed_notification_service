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
import image from '@ohos.multimedia.image';
import type notificationManager from '@ohos.notificationManager';
import type notificationSubscribe from '@ohos.notificationSubscribe';
import { NotificationContent } from 'notification.notificationContent';
import { NotificationActionButton } from 'notification.notificationActionButton';
import { NotificationTemplate } from 'notification.notificationTemplate';
import { NotificationFlags } from 'notification.notificationFlags';
import { WantAgent } from '@ohos.app.ability.wantAgent';
import { BundleOption } from 'notification.NotificationCommonDef';

export interface DistributedOptions {
  isDistributed?: boolean;
  supportDisplayDevices?: Array<string>;
  supportOperateDevices?: Array<string>;
  readonly remindType?: number;
}

class DistributedOptionsInner implements DistributedOptions {
  isDistributed?: boolean | undefined;
  supportDisplayDevices?: Array<string> | undefined;
  supportOperateDevices?: Array<string> | undefined;
  readonly remindType?: number | undefined;
}

export interface NotificationFilter {
  bundle: BundleOption;
  notificationKey: notificationSubscribe.NotificationKey;
  extraInfoKeys?: Array<string>;
}

class NotificationFilterInner implements NotificationFilter {
  bundle: BundleOption = {};
  notificationKey: notificationSubscribe.NotificationKey = {};
  extraInfoKeys?: Array<string> | undefined;
}

export interface NotificationCheckRequest {
  contentType: notificationManager.ContentType;
  slotType: notificationManager.SlotType;
  extraInfoKeys: Array<string>;
}

class NotificationCheckRequestInner implements NotificationCheckRequest {
  contentType: notificationManager.ContentType = notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT;
  slotType: notificationManager.SlotType = notificationManager.SlotType.OTHER_TYPES;
  extraInfoKeys: Array<string> = {};
}

export interface UnifiedGroupInfo {
  key?: string;
  title?: string;
  content?: string;
  sceneName?: string;
  extraInfo?: Record<string, Object>;
}

class UnifiedGroupInfoInner implements UnifiedGroupInfo {
  key?: string | undefined;
  title?: string | undefined;
  content?: string | undefined;
  sceneName?: string | undefined;
  extraInfo?: Record<string, Object> | undefined;
}

export interface NotificationRequest {
  content: NotificationContent;
  id?: number;
  appMessageId?: string;
  notificationSlotType?: notificationManager.SlotType;
  isOngoing?: boolean;
  isUnremovable?: boolean;
  updateOnly?: boolean;
  deliveryTime?: number;
  tapDismissed?: boolean;
  autoDeletedTime?: number;
  wantAgent?: WantAgent;
  extraInfo?: Record<string, Object>;
  color?: number;
  colorEnabled?: boolean;
  isAlertOnce?: boolean;
  isStopwatch?: boolean;
  isCountDown?: boolean;
  isFloatingIcon?: boolean;
  label?: string;
  badgeIconStyle?: number;
  showDeliveryTime?: boolean;
  actionButtons?: Array<NotificationActionButton>;
  smallIcon?: image.PixelMap;
  largeIcon?: image.PixelMap;
  overlayIcon?: image.PixelMap;
  groupName?: string;
  readonly creatorBundleName?: string;
  readonly creatorUid?: number;
  readonly creatorPid?: number;
  readonly creatorUserId?: number;
  readonly creatorInstanceKey?: number;
  sound?: string;
  classification?: string;
  readonly hashCode?: string;
  isRemoveAllowed?: boolean;
  readonly source?: number;
  template?: NotificationTemplate;
  distributedOption?: DistributedOptions;
  readonly deviceId?: string;
  readonly notificationFlags?: NotificationFlags;
  removalWantAgent?: WantAgent;
  badgeNumber?: number;
  representativeBundle?: BundleOption;
  readonly agentBundle?: BundleOption;
  unifiedGroupInfo?: UnifiedGroupInfo;
  notificationControlFlags?: number;
  readonly appInstanceKey?: string;
  forceDistributed?: boolean;
  notDistributed?: boolean;
}

class NotificationRequestInner implements NotificationRequest {
  content: NotificationContent = {};
  id?: number | undefined;
  appMessageId?: string | undefined;
  notificationSlotType?: notificationManager.SlotType | undefined;
  isOngoing?: boolean | undefined;
  isUnremovable?: boolean | undefined;
  updateOnly?: boolean | undefined;
  deliveryTime?: number | undefined;
  tapDismissed?: boolean | undefined;
  autoDeletedTime?: number | undefined;
  wantAgent?: WantAgent | undefined;
  extraInfo?: Record<string, Object> | undefined;
  color?: number | undefined;
  colorEnabled?: boolean | undefined;
  isAlertOnce?: boolean | undefined;
  isStopwatch?: boolean | undefined;
  isCountDown?: boolean | undefined;
  isFloatingIcon?: boolean | undefined;
  label?: string | undefined;
  badgeIconStyle?: number | undefined;
  showDeliveryTime?: boolean | undefined;
  actionButtons?: Array<NotificationActionButton> | undefined;
  smallIcon?: image.PixelMap | undefined;
  largeIcon?: image.PixelMap | undefined;
  overlayIcon?: image.PixelMap | undefined;
  groupName?: string | undefined;
  readonly creatorBundleName?: string | undefined;
  readonly creatorUid?: number | undefined;
  readonly creatorPid?: number | undefined;
  readonly creatorUserId?: number | undefined;
  readonly creatorInstanceKey?: number | undefined;
  sound?: string | undefined;
  classification?: string | undefined;
  readonly hashCode?: string | undefined;
  isRemoveAllowed?: boolean | undefined;
  readonly source?: number | undefined;
  template?: NotificationTemplate | undefined;
  distributedOption?: DistributedOptions | undefined;
  readonly deviceId?: string | undefined;
  readonly notificationFlags?: NotificationFlags | undefined;
  removalWantAgent?: WantAgent | undefined;
  badgeNumber?: number | undefined;
  representativeBundle?: BundleOption | undefined;
  readonly agentBundle?: BundleOption | undefined;
  unifiedGroupInfo?: UnifiedGroupInfo | undefined;
  notificationControlFlags?: number | undefined;
  readonly appInstanceKey?: string | undefined;
  forceDistributed?: boolean | undefined;
  notDistributed?: boolean | undefined;
}