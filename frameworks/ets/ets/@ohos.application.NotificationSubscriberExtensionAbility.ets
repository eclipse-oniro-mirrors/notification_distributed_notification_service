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

import type NotificationSubscriberExtensionContext from '@ohos.application.NotificationSubscriberExtensionContext';
import { NotificationInfo } from 'notification.NotificationInfo'

export default class NotificationSubscriberExtensionAbility {

  context: NotificationSubscriberExtensionContext = {};

  onDestroy(): void {}

  onReceiveMessage(notificationInfo: NotificationInfo): void {
    console.log('onReceiveMessage, notificationInfo:' + notificationInfo.hashCode);
  }

  onCancelMessages(hashCodes: Array<string>): void {
    console.log('onCancelMessages, hashCodes:' + hashCodes);
  }
}
