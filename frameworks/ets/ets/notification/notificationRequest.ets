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
import { RecordData } from '@ohos.base';

export interface DistributedOptions {
    isDistributed?: boolean;
    supportDisplayDevices?: Array<string>;
    supportOperateDevices?: Array<string>;
    readonly remindType?: int;
}

class DistributedOptionsInner implements DistributedOptions {
    public isDistributed?: boolean | undefined;
    public supportDisplayDevices?: Array<string> | undefined;
    public supportOperateDevices?: Array<string> | undefined;
    public readonly remindType?: int | undefined;
}

export interface NotificationFilter {
    bundle: BundleOption;
    notificationKey: notificationSubscribe.NotificationKey;
    extraInfoKeys?: Array<string>;
}

class NotificationFilterInner implements NotificationFilter {
    public bundle: BundleOption = {};
    public notificationKey: notificationSubscribe.NotificationKey = {};
    public extraInfoKeys?: Array<string> | undefined;
}

export interface NotificationCheckRequest {
    contentType: notificationManager.ContentType;
    slotType: notificationManager.SlotType;
    extraInfoKeys: Array<string>;
}

class NotificationCheckRequestInner implements NotificationCheckRequest {
    public contentType: notificationManager.ContentType =
        notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT;
    public slotType: notificationManager.SlotType = notificationManager.SlotType.OTHER_TYPES;
    public extraInfoKeys: Array<string> = {};
}

export interface UnifiedGroupInfo {
    key?: string;
    title?: string;
    content?: string;
    sceneName?: string;
    extraInfo?: Record<string, RecordData>;
}

class UnifiedGroupInfoInner implements UnifiedGroupInfo {
    public key?: string | undefined;
    public title?: string | undefined;
    public content?: string | undefined;
    public sceneName?: string | undefined;
    public extraInfo?: Record<string, RecordData> | undefined;
}

export interface NotificationRequest {
    content: NotificationContent;
    id?: int;
    appMessageId?: string;
    notificationSlotType?: notificationManager.SlotType;
    isOngoing?: boolean;
    isUnremovable?: boolean;
    updateOnly?: boolean;
    deliveryTime?: long;
    tapDismissed?: boolean;
    autoDeletedTime?: long;
    wantAgent?: WantAgent;
    extraInfo?: Record<string, RecordData>;
    extendInfo?: Record<string, RecordData>;
    color?: long;
    colorEnabled?: boolean;
    isAlertOnce?: boolean;
    isStopwatch?: boolean;
    isCountDown?: boolean;
    isFloatingIcon?: boolean;
    label?: string;
    badgeIconStyle?: int;
    showDeliveryTime?: boolean;
    actionButtons?: Array<NotificationActionButton>;
    smallIcon?: image.PixelMap;
    largeIcon?: image.PixelMap;
    overlayIcon?: image.PixelMap;
    groupName?: string;
    readonly creatorBundleName?: string;
    readonly creatorUid?: int;
    readonly creatorPid?: int;
    readonly creatorUserId?: int;
    sound?: string;
    classification?: string;
    readonly hashCode?: string;
    isRemoveAllowed?: boolean;
    readonly source?: int;
    template?: NotificationTemplate;
    distributedOption?: DistributedOptions;
    readonly deviceId?: string;
    readonly notificationFlags?: NotificationFlags;
    removalWantAgent?: WantAgent;
    badgeNumber?: long;
    representativeBundle?: BundleOption;
    readonly agentBundle?: BundleOption;
    unifiedGroupInfo?: UnifiedGroupInfo;
    notificationControlFlags?: long;
    readonly appInstanceKey?: string;
    forceDistributed?: boolean;
    notDistributed?: boolean;
}

class NotificationRequestInner implements NotificationRequest {
    public content: NotificationContent = {};
    public id?: int | undefined;
    public appMessageId?: string | undefined;
    public notificationSlotType?: notificationManager.SlotType | undefined;
    public isOngoing?: boolean | undefined;
    public isUnremovable?: boolean | undefined;
    public updateOnly?: boolean | undefined;
    public deliveryTime?: long | undefined;
    public tapDismissed?: boolean | undefined;
    public autoDeletedTime?: long | undefined;
    public wantAgent?: WantAgent | undefined;
    public extraInfo?: Record<string, RecordData> | undefined;
    public extendInfo?: Record<string, RecordData> | undefined;
    public color?: long | undefined;
    public colorEnabled?: boolean | undefined;
    public isAlertOnce?: boolean | undefined;
    public isStopwatch?: boolean | undefined;
    public isCountDown?: boolean | undefined;
    public isFloatingIcon?: boolean | undefined;
    public label?: string | undefined;
    public badgeIconStyle?: int | undefined;
    public showDeliveryTime?: boolean | undefined;
    public actionButtons?: Array<NotificationActionButton> | undefined;
    public smallIcon?: image.PixelMap | undefined;
    public largeIcon?: image.PixelMap | undefined;
    public overlayIcon?: image.PixelMap | undefined;
    public groupName?: string | undefined;
    public readonly creatorBundleName?: string | undefined;
    public readonly creatorUid?: int | undefined;
    public readonly creatorPid?: int | undefined;
    public readonly creatorUserId?: int | undefined;
    public sound?: string | undefined;
    public classification?: string | undefined;
    public readonly hashCode?: string | undefined;
    public isRemoveAllowed?: boolean | undefined;
    public readonly source?: int | undefined;
    public template?: NotificationTemplate | undefined;
    public distributedOption?: DistributedOptions | undefined;
    public readonly deviceId?: string | undefined;
    public readonly notificationFlags?: NotificationFlags | undefined;
    public removalWantAgent?: WantAgent | undefined;
    public badgeNumber?: long | undefined;
    public representativeBundle?: BundleOption | undefined;
    public readonly agentBundle?: BundleOption | undefined;
    public unifiedGroupInfo?: UnifiedGroupInfo | undefined;
    public notificationControlFlags?: long | undefined;
    public readonly appInstanceKey?: string | undefined;
    public forceDistributed?: boolean | undefined;
    public notDistributed?: boolean | undefined;
}