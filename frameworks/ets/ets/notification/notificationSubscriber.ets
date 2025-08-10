/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { NotificationRequest, DistributedOptions, UnifiedGroupInfo } from 'notification.notificationRequest';
import { NotificationSortingMap } from 'notification.notificationSortingMap';
import notificationManager from '@ohos.notificationManager';
import { NotificationContent } from 'notification.notificationContent';

import image from '@ohos.multimedia.image';
// import type notificationManager from '@ohos.notificationManager';
// import type notificationSubscribe from '@ohos.notificationSubscribe';
// import { NotificationContent } from 'notification.notificationContent';
import { NotificationActionButton } from 'notification.notificationActionButton';
import { NotificationTemplate } from 'notification.notificationTemplate';
import { NotificationFlags } from 'notification.notificationFlags';
import { WantAgent } from '@ohos.app.ability.wantAgent';
import { BundleOption } from 'notification.NotificationCommonDef';


export interface NotificationSubscriber {
    onConsume?: (data: SubscribeCallbackData) => void;

    onCancel?: (data: SubscribeCallbackData) => void;

    onUpdate?: (data: NotificationSortingMap) => void;

    onConnect?: () => void;

    onDisconnect?: () => void;

    onDestroy?: () => void;

    onDoNotDisturbChanged?: (mode: notificationManager.DoNotDisturbDate) => void;

    onEnabledNotificationChanged?: (callbackData: EnabledNotificationCallbackData) => void;

    onBadgeChanged?: (data: BadgeNumberCallbackData) => void;

    onBadgeEnabledChanged?: BadgeEnabledChangedCallback;

    onBatchCancel?: (data: Array<SubscribeCallbackData>) => void;
}

export class NotificationSubscriberInner implements NotificationSubscriber {
    public onConsume?: (data: SubscribeCallbackData) => void;

    public onCancel?: (data: SubscribeCallbackData) => void;

    public onUpdate?: (data: NotificationSortingMap) => void;

    public onConnect?: () => void;

    public onDisconnect?: () => void;

    public onDestroy?: () => void;

    public onDoNotDisturbChanged?: (mode: notificationManager.DoNotDisturbDate) => void;

    public onEnabledNotificationChanged?: (callbackData: EnabledNotificationCallbackData) => void;

    public onBadgeChanged?: (data: BadgeNumberCallbackData) => void;

    public onBadgeEnabledChanged?: BadgeEnabledChangedCallback;

    public onBatchCancel?: (data: Array<SubscribeCallbackData>) => void;
}

export interface SubscribeCallbackData {
    readonly request: NotificationRequest;
    readonly sortingMap?: NotificationSortingMap;
    readonly reason?: int;
    readonly sound?: string;
    readonly vibrationValues?: Array<long>;
}

class SubscribeCallbackDataInner implements SubscribeCallbackData {
    public readonly request: NotificationRequest = {
        content: {},
        id: undefined,
        appMessageId: undefined,
        notificationSlotType: undefined,
        isOngoing: undefined,
        isUnremovable: undefined,
        updateOnly: undefined,
        deliveryTime: undefined,
        tapDismissed: undefined,
        autoDeletedTime: undefined,
        wantAgent: undefined,
        extraInfo: undefined,
        extendInfo: undefined,
        color: undefined,
        colorEnabled: undefined,
        isAlertOnce: undefined,
        isStopwatch: undefined,
        isCountDown: undefined,
        isFloatingIcon: undefined,
        label: undefined,
        badgeIconStyle: undefined,
        showDeliveryTime: undefined,
        actionButtons: undefined,
        smallIcon: undefined,
        largeIcon: undefined,
        overlayIcon: undefined,
        groupName: undefined,
        creatorBundleName: undefined,
        creatorUid: undefined,
        creatorPid: undefined,
        creatorUserId: undefined,
        sound: undefined,
        classification: undefined,
        hashCode: undefined,
        isRemoveAllowed: undefined,
        source: undefined,
        template: undefined,
        distributedOption: undefined,
        deviceId: undefined,
        notificationFlags: undefined,
        removalWantAgent: undefined,
        badgeNumber: undefined,
        representativeBundle: undefined,
        agentBundle: undefined,
        unifiedGroupInfo: undefined,
        notificationControlFlags: undefined,
        appInstanceKey: undefined,
        forceDistributed: undefined,
        notDistributed: undefined
    };
    public readonly sortingMap?: NotificationSortingMap;
    public readonly reason?: int;
    public readonly sound?: string;
    public readonly vibrationValues?: Array<long>;
}

export interface EnabledNotificationCallbackData {
    readonly bundle: string;
    readonly uid: int;
    readonly enable: boolean;
}

class EnabledNotificationCallbackDataInner implements EnabledNotificationCallbackData {
    public readonly bundle: string = '';
    public readonly uid: int = -1;
    public readonly enable: boolean = false;
}

export interface BadgeNumberCallbackData {
    readonly bundle: string;
    readonly uid: int;
    readonly badgeNumber: int;
    readonly instanceKey?: int;
    readonly appInstanceKey?: string;
}

class BadgeNumberCallbackDataInner implements BadgeNumberCallbackData {
    public readonly bundle: string = '';
    public readonly uid: int = -1;
    public readonly badgeNumber: int = -1;
    public readonly instanceKey?: int;
    public readonly appInstanceKey?: string;
}

export type BadgeEnabledChangedCallback = (data: EnabledNotificationCallbackData) => void;