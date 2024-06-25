/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import display from '@ohos.display';
import emitter from '@ohos.events.emitter';
import extension from '@ohos.app.ability.ServiceExtensionAbility';
import window from '@ohos.window';
import CommonEventManager from '@ohos.commonEventManager';
import type Want from '@ohos.app.ability.Want';
import UIExtensionAbility from '@ohos.app.ability.UIExtensionAbility';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import uiExtensionHost from '@ohos.uiExtensionHost';
import StartOptions from '@ohos.app.ability.StartOptions';



const TAG = 'NotificationDialog_Service ';

const enableNotificationDialogDestroyedEvent = {
  eventId: 1,
  priority: emitter.EventPriority.LOW
};

const COMMON_EVENT_NAME = 'OnNotificationServiceDialogClicked';
enum DialogStatus {
  ALLOW_CLICKED,
  DENY_CLICKED,
  DIALOG_CRASHED,
  DIALOG_SERVICE_DESTROYED
};

async function handleDialogQuitException(want: Want): Promise<void> {
  CommonEventManager.publish(
    COMMON_EVENT_NAME,
    {
      code: DialogStatus.DIALOG_CRASHED,
      data: want.parameters.from.toString(),
    } as CommonEventManager.CommonEventPublishData,
    () => { console.info(TAG, 'publish DIALOG_CRASHED succeeded'); }
  );
}


export class EnableNotificationDialog {
  static ENABLE_NOTIFICATION_DIALOG_NAME = 'EnableNotificationDialog';
  static DIALOG_PATH = 'pages/notificationDialog';
  static TRANSPARANT_COLOR = '#00000000';

  id: number;
  want: Want;
  window: window.Window;
  extensionWindow:uiExtensionHost.UIExtensionHostWindowProxy;
  storage: LocalStorage;

  constructor(id: number, want: Want) {
    this.id = id;
    this.want = want;
    this.window = undefined;
    this.extensionWindow = undefined;
  }

  async createWindow(windowType: window.WindowType, context, displayRect): Promise<void> {
    try {
      let winArgs = {
        'name': `${EnableNotificationDialog.ENABLE_NOTIFICATION_DIALOG_NAME}${this.id}`,
        'windowType': windowType,
        'ctx': context
      };
      let win = await window.createWindow(winArgs);
      this.window = win;
      let shouldHide = true;

      if (windowType === window.WindowType.TYPE_DIALOG) {
        await win.bindDialogTarget(this.want.parameters.callerToken['value'],
          async (): Promise<void> => {
            console.info(TAG, `window ${this.id} died`);
            await this.destroyException();
          }
        );
      }

      this.storage = new LocalStorage({
        'dialog': this
      });
      await win.moveWindowTo(displayRect.left, displayRect.top);
      await win.resize(displayRect.width, displayRect.height);
      await win.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);
      try {
        await win.hideNonSystemFloatingWindows(shouldHide);
      } catch (err) {
        console.error(TAG, 'window hideNonSystemFloatingWindows failed!');
      }
      await win.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
      await win.showWindow();
      await win.setWindowLayoutFullScreen(true);
    } catch (err) {
      if (this.window !== undefined) {
        await this.destroyWindow();
      }
      console.error(TAG, 'window create failed!');
      throw new Error('Failed to create window');
    }
  }


  async createUiExtensionWindow(session: UIExtensionContentSession): Promise<void> {
    try {
      let extensionWindow = session.getUIExtensionHostWindowProxy();
      this.extensionWindow = extensionWindow;
      let shouldHide = true;

      this.storage = new LocalStorage({
        'dialog': this,
        'session': session
      });
      await session.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);
      try {
        await extensionWindow.hideNonSecureWindows(shouldHide);
      } catch (err) {
        console.error(TAG, 'window hideNonSecureWindows failed!');
      }
      await session.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
    } catch (err) {
      console.error(TAG, 'window create failed!');
      throw new Error('Failed to create window');
    }
  }

  async publishButtonClickedEvent(enabled: boolean): Promise<void> {
    CommonEventManager.publish(
      COMMON_EVENT_NAME,
      {
        code: enabled ? DialogStatus.ALLOW_CLICKED : DialogStatus.DENY_CLICKED,
        data: this.want.parameters.from.toString(),
      } as CommonEventManager.CommonEventPublishData,
      () => { console.info(TAG, 'publish CLICKED succeeded'); }
    );
  }

  async destroyException(): Promise<void> {
    await handleDialogQuitException(this.want);
  }

  async destroy(): Promise<void> {
    if (this.window !== undefined) {
      emitter.emit(enableNotificationDialogDestroyedEvent, {
        data: {
          'id': this.id
        }
      });
      await this.destroyWindow();
    }
  }

  async destroyWindow(): Promise<void> {
    await this.window.destroyWindow();
    this.window = undefined;
  }
};



class NotificationDialogServiceExtensionAbility extends UIExtensionAbility {

  onCreate() {
    console.log(TAG, `UIExtAbility onCreate`);
    AppStorage.SetOrCreate('context', this.context);
  
  }

  async onSessionCreate(want: Want, session: UIExtensionContentSession) {
    console.log(TAG, `UIExtAbility onSessionCreate`);    
    try {
      let bundleName  = want.parameters['ohos.aafwk.param.callerBundleName'];
      if(want.parameters['from'] === undefined){
        want.parameters['from'] = bundleName;
        want.parameters['stageModel'] = true;
      }else{
        want.parameters['stageModel'] = false;
      }
      let dialog = new EnableNotificationDialog(1, want);
      await dialog.createUiExtensionWindow(session);
    } catch (err) {
      console.error(TAG, `Failed to handle onSessionCreate`);
      await handleDialogQuitException(want);
    }
  }

  onForeground() {
    console.log(TAG, `UIExtAbility onForeground`);
  }

  onBackground() {
    console.log(TAG, `UIExtAbility onBackground`);
  }

  onSessionDestroy(session: UIExtensionContentSession) {
    console.log(TAG, `UIExtAbility onSessionDestroy`);
  }

  onDestroy() {
    console.info(TAG, 'UIExtAbility onDestroy.');
    this.context.terminateSelf();
  }
}


export default NotificationDialogServiceExtensionAbility;
