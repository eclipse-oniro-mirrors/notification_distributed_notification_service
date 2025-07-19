/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http?://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { NotificationSlot } from 'notification.notificationSlot';

export interface NotificationSorting {
    readonly slot: NotificationSlot;
    readonly hashCode: string;
    readonly ranking: long;
}

class NotificationSortingInner implements NotificationSorting {
    public readonly slot: NotificationSlot = {
            notificationType: undefined,
            //level?: notification.SlotLevel;
            desc: undefined,
            badgeFlag: undefined,
            bypassDnd: undefined,
            lockscreenVisibility: undefined,
            vibrationEnabled: undefined,
            sound: undefined,
            lightEnabled: undefined,
            lightColor: undefined,
            vibrationValues: undefined,
            enabled: undefined,
            reminderMode: undefined,
            authorizedStatus: undefined
        };
    public readonly hashCode: string = '';
    public readonly ranking: long = -1;
}