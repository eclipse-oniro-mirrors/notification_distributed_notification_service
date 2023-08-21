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
import deviceInfo from '@ohos.deviceInfo';
const TAG = 'NotificationDialog_Service';

let winNum = 1;
let win;
export default class NotificationDialogServiceExtensionAbility extends extension {
  onCreate(want): void {
    console.debug(TAG, 'onCreate, want: ' + JSON.stringify(want));
    globalThis.notificationExtensionContext = this.context;
    globalThis.closeDialog = (): void => {
      console.info(TAG, 'click waiting for a response');
      if (win !== undefined) {
        win.destroyWindow();
      }
      globalThis.notificationExtensionContext.terminateSelf();
    };
  };

  onRequest(want, startId): void {
    globalThis.abilityWant = want;

    if (want['parameters']['callerToken'] !== undefined && want['parameters']['callerToken'] != null) {
      globalThis.callerToken = want['parameters']['callerToken'];
    }
    display.getDefaultDisplay().then(() => {

      if (globalThis.callerToken != null) {
        if (winNum > 1) {
          win.destroy();
          winNum--;
        }
        this.createWindow('EnableNotificationDialog' + startId, window.WindowType.TYPE_DIALOG);
        winNum++;
      } else {
        this.createWindow('EnableNotificationDialog' + startId, window.WindowType.TYPE_SYSTEM_ALERT);
      }

    });
  }

  onDestroy(): void {
    console.info(TAG, 'onDestroy.');
  }

  private async createWindow(name: string, windowType: number) {
    console.info(TAG, 'create window');
    try {
      win = await window.create(globalThis.notificationExtensionContext, name, windowType);

      if (globalThis.callerToken != null) {
        await win.bindDialogTarget(globalThis.callerToken.value, () => {
          win.destroyWindow();
          winNum--;
          if (winNum === 0) {
            globalThis.selectExtensionContext.terminateSelf();
          }
        });
      }

      await win.show();
      if (deviceInfo.deviceType === 'default' || deviceInfo.deviceType === 'phone') {
        let def = display.getDefaultDisplaySync();
        win.moveTo(0, 0);
        win.resetSize(def.width, def.height);
      } else {
        let def = display.getDefaultDisplaySync();
        let topMargin = 60;
        let bottomMargin = 96;
        win.moveTo(0, def.densityPixels * topMargin);
        win.resetSize(def.width, def.height - def.densityPixels * bottomMargin - def.densityPixels * topMargin);
      }
      await win.loadContent('pages/notificationDialog');
      await win.setBackgroundColor('#00000000');
    } catch {
      console.error(TAG, 'window create failed!');
    }
  }
};
