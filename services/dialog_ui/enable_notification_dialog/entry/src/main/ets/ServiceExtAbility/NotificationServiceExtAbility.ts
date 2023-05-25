/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import extension from '@ohos.app.ability.ServiceExtensionAbility';
import window from '@ohos.window';
import display from '@ohos.display';
const TAG = 'NotificationDialog_Service';

export default class NotificationDialogServiceExtensionAbility extends extension {
  onCreate(want) {
      console.debug(TAG, "onCreate, want: " + JSON.stringify(want));
      globalThis.notificationExtensionContext = this.context;
      globalThis.closeDialog = () => {
          console.info(TAG, 'click waiting for a response');
          globalThis.notificationExtensionContext.terminateSelf();
      }
  };

  onRequest(want, startId) {
    globalThis.abilityWant = want;
    console.log(TAG, 'globalThis.resolution' + JSON.stringify(globalThis.resolution));
    display.getDefaultDisplay().then(() => {
      this.createWindow('EnableNotificationDialog' + startId, window.WindowType.TYPE_SYSTEM_ALERT);
    });
  }

  onDestroy() {
    console.info(TAG, 'onDestroy.');
  }

  private async createWindow(name: string, windowType: number) {
    console.info(TAG, 'create window');
    try {
      const win = await window.create(globalThis.notificationExtensionContext, name, windowType);
      await win.show();
      await win.setWindowLayoutFullScreen(true);
      await win.loadContent('pages/notificationDialog');
      await win.setBackgroundColor('#00000000');
    } catch {
      console.error(TAG, 'window create failed!');
    }
  }
};
