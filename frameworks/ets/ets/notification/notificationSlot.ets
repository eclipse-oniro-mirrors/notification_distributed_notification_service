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
    lockscreenVisibility?: int;
    vibrationEnabled?: boolean;
    sound?: string;
    lightEnabled?: boolean;
    lightColor?: int;
    vibrationValues?: Array<long>;
    readonly enabled?: boolean;
    readonly reminderMode?: int;
    readonly authorizedStatus?: int;
}

class NotificationSlotInner implements NotificationSlot {
    public notificationType?: notificationManager.SlotType;
    public notificationLevel?: notificationManager.SlotLevel;
    public desc?: string;
    public badgeFlag?: boolean;
    public bypassDnd?: boolean;
    public lockscreenVisibility?: int;
    public vibrationEnabled?: boolean;
    public sound?: string;
    public lightEnabled?: boolean;
    public lightColor?: int;
    public vibrationValues?: Array<long>;
    public readonly enabled?: boolean;
    public readonly reminderMode?: int;
    public readonly authorizedStatus?: int;
}