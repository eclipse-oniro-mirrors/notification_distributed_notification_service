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

const UPDATE_INIT = -1;
const UPDATE_NUM = 1;
const UPDATE_BOUNDARY = 100;


let systemLanguage: string; 

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
      data: want.parameters.bundleName.toString(),
      parameters: {
        bundleName: want.parameters.bundleName.toString(),
        bundleUid: want.parameters.bundleUid.toString()
      }
    } as CommonEventManager.CommonEventPublishData,
    () => { console.info(TAG, 'publish DIALOG_CRASHED succeeded'); }
  );
}


export class EnableNotificationDialog {
  static ENABLE_NOTIFICATION_DIALOG_NAME = 'EnableNotificationDialog';
  static DIALOG_PATH = 'pages/notificationDialog';
  static TRANSPARANT_COLOR = '#00000000';
  static SCENEBOARD_BUNDLE = 'com.ohos.sceneboard';

  id: number;
  want: Want;
  window: window.Window;
  extensionWindow:uiExtensionHost.UIExtensionHostWindowProxy;
  storage: LocalStorage;
  stageModel: boolean;

  constructor(id: number, want: Want, stageModel: boolean) {
    this.id = id;
    this.want = want;
    this.stageModel = stageModel;
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


  async createUiExtensionWindow(session: UIExtensionContentSession, stageModel: boolean): Promise<void> {
    try {
      let extensionWindow = session.getUIExtensionHostWindowProxy();
      this.extensionWindow = extensionWindow;
      let shouldHide = true;

      this.storage = new LocalStorage({
        'dialog': this,
        'session': session
      });

      if (stageModel) {
        let subWindowOpts : window.SubWindowOptions = {
          'title': '',
          decorEnabled: false,
          isModal: true,
          isTopmost: true
        };
        let subWindow = await extensionWindow.createSubWindowWithOptions('subWindowForHost' + Date(), subWindowOpts);
        let dis = display.getDefaultDisplaySync();
        await subWindow?.resize(dis.width, dis.height);
        await subWindow.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);
        await subWindow.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
        await subWindow.showWindow();
      } else {
        await session.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);  
      }
      try {    
        await extensionWindow.hideNonSecureWindows(shouldHide);
      } catch (err) {
        console.error(TAG, 'window hideNonSecureWindows failed!');
      }
      if (!stageModel) {
        await session.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
      }
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
        data: this.want.parameters.bundleName.toString(),
        parameters: {
          bundleName: this.want.parameters.bundleName.toString(),
          bundleUid: this.want.parameters.bundleUid.toString()
        }
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

  onConfigurationUpdate(newConfig) {
    console.log(TAG, 'onConfigurationUpdate');
    if (systemLanguage !== newConfig.language) {
      console.log(TAG, `onConfigurationUpdate newConfig is ${JSON.stringify(newConfig)}`);
      systemLanguage = newConfig.language;
      let isUpdate:number = AppStorage.get('isUpdate');
      if (isUpdate === undefined || isUpdate > UPDATE_BOUNDARY) {
        AppStorage.setOrCreate('isUpdate', UPDATE_NUM);
      } else {
        AppStorage.setOrCreate('isUpdate', ++isUpdate);
      }
    }
  }
    

  onCreate() {
    console.log(TAG, `UIExtAbility onCreate`);
    AppStorage.setOrCreate('context', this.context);
    AppStorage.setOrCreate('isUpdate', UPDATE_INIT);
    systemLanguage = this.context.config.language; 
  }

  async onSessionCreate(want: Want, session: UIExtensionContentSession) {
    try {
      let stageModel = false;
      let bundleName = want.parameters['ohos.aafwk.param.callerBundleName'];
      let bundleUid = want.parameters['ohos.aafwk.param.callerUid'];
      if (bundleName !== EnableNotificationDialog.SCENEBOARD_BUNDLE) {
        want.parameters.bundleName = bundleName;
        want.parameters.bundleUid = bundleUid;
        stageModel = true;
      } else {
        stageModel = false;
      }
      console.log(TAG, `UIExtAbility onSessionCreate bundleName ${want.parameters.bundleName}`
        + `uid ${want.parameters.bundleUid}`);
      let dialog = new EnableNotificationDialog(1, want, stageModel);
      await dialog.createUiExtensionWindow(session, stageModel);
      AppStorage.setOrCreate('clicked', false);
      AppStorage.setOrCreate('dialog', dialog);
    } catch (err) {
      console.error(TAG, `Failed to handle onSessionCreate`);
      await handleDialogQuitException(want);
    }
  }

  onForeground() {
    console.log(TAG, `UIExtAbility onForeground`);
    let dialog = AppStorage.get<EnableNotificationDialog>('dialog');
    try {
      dialog?.extensionWindow?.hideNonSecureWindows(true);
    } catch (err) {
      console.error(TAG, 'onForeground hideNonSecureWindows failed!');
    }  
  }

  onBackground() {
    console.log(TAG, `UIExtAbility onBackground`);
    let dialog = AppStorage.get<EnableNotificationDialog>('dialog');
    try {
      dialog?.extensionWindow?.hideNonSecureWindows(false);
    } catch (err) {
      console.error(TAG, 'onBackground hideNonSecureWindows failed!');
    }
  }

  async onSessionDestroy(session: UIExtensionContentSession) {
    console.log(TAG, `UIExtAbility onSessionDestroy`);  
    if (AppStorage.get('clicked') === false) {
      console.log(TAG, `UIExtAbility onSessionDestroy unclick destory`);
      let dialog = AppStorage.get<EnableNotificationDialog>('dialog');
      await dialog?.destroyException();
    }
  }

  onDestroy() {
    console.info(TAG, 'UIExtAbility onDestroy.');
    this.context.terminateSelf();
  }
}


export default NotificationDialogServiceExtensionAbility;
