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
import configPolicy from '@ohos.configPolicy';
import fs from '@ohos.file.fs';
import Constants from '../common/constant';


const TAG = 'NotificationDialog_Service ';

const UPDATE_INIT = 1;
const UPDATE_NUM = 1;
const UPDATE_BOUNDARY = 100;

let eventSubscriber:CommonEventManager.CommonEventSubscriber;

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
  static SYSTEMUI_BUNDLE = 'com.ohos.systemui';

  id: number;
  want: Want;
  window: window.Window;
  extensionWindow:uiExtensionHost.UIExtensionHostWindowProxy;
  storage: LocalStorage;
  stageModel: boolean;
  subWindow: window.Window;

  constructor(id: number, want: Want, stageModel: boolean) {
    this.id = id;
    this.want = want;
    this.stageModel = stageModel;
    this.window = undefined;
    this.extensionWindow = undefined;
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
      
      let hasConfig = true;
      try {
        let filePaths = await configPolicy.getCfgFiles(Constants.CCM_CONFIG_PATH);
        if (filePaths.length === 0) {
          console.info(TAG, 'not get any configFile');
          hasConfig = false;
        }
      } catch (err) {
        console.error(TAG, 'Failed get ccm files');
      }

      if (stageModel && hasConfig) {
        let subWindowOpts : window.SubWindowOptions = {
          'title': '',
          decorEnabled: false,
          isModal: true,
          isTopmost: true
        };
        let subWindow = await extensionWindow.createSubWindowWithOptions('subWindowForHost' + Date(), subWindowOpts);
        this.subWindow = subWindow;
        let windowRect  = extensionWindow.properties?.uiExtensionHostWindowProxyRect;
        await subWindow.moveWindowTo(windowRect?.left, windowRect?.top);
        await subWindow.resize(windowRect?.width, windowRect?.height);
        console.info(TAG, `size : ${windowRect.left} ${windowRect.top} ${windowRect.width}  ${windowRect.height}`);
        await subWindow.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);
        try {
          await subWindow.hideNonSystemFloatingWindows(true);
        } catch (err) {
          console.error(TAG, 'subWindow hideNonSystemFloatingWindows failed!');
        }
        await subWindow.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
        await subWindow.showWindow();
      } else {
        await session.loadContent(EnableNotificationDialog.DIALOG_PATH, this.storage);  
        try {    
          await extensionWindow.hideNonSecureWindows(shouldHide);
        } catch (err) {
          console.error(TAG, 'window hideNonSecureWindows failed!');
        }
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

  onCreate() {
    console.log(TAG, `UIExtAbility onCreate`);
    AppStorage.setOrCreate('context', this.context);
    AppStorage.setOrCreate('isUpdate', UPDATE_INIT);
    AppStorage.setOrCreate('clicked', false);
    this.subscribe();
  
  }

  async onSessionCreate(want: Want, session: UIExtensionContentSession) {
    try {
      let stageModel = false;
      let bundleName = want.parameters['ohos.aafwk.param.callerBundleName'];
      let bundleUid = want.parameters['ohos.aafwk.param.callerUid'];
      if (bundleName !== EnableNotificationDialog.SCENEBOARD_BUNDLE &&
        bundleName !== EnableNotificationDialog.SYSTEMUI_BUNDLE) {
        want.parameters.bundleName = bundleName;
        want.parameters.bundleUid = bundleUid;
        stageModel = true;
      } else {
        stageModel = false;
      }
      console.log(TAG, `UIExtAbility onSessionCreate bundleName ${want.parameters.bundleName}` +
        `uid ${want.parameters.bundleUid}`);    
      let dialog = new EnableNotificationDialog(1, want, stageModel);
      await dialog.createUiExtensionWindow(session, stageModel);
      AppStorage.setOrCreate('dialog', dialog);
    } catch (err) {
      console.error(TAG, `Failed to handle onSessionCreate`);
      await handleDialogQuitException(want);
    }
  }

  onForeground() {
    console.log(TAG, `UIExtAbility onForeground`);
    let dialog = AppStorage.get<EnableNotificationDialog>('dialog');
    
    if (dialog?.subWindow !== undefined) {
      try {
        dialog?.subWindow?.hideNonSystemFloatingWindows(true);
      } catch (err) {
        console.error(TAG, 'onForeground hideNonSystemFloatingWindows failed!');
      } 
    } else {
      try {
        dialog?.extensionWindow?.hideNonSecureWindows(true);
      } catch (err) {
        console.error(TAG, 'onForeground hideNonSecureWindows failed!');
      }  
    }
  }

  onBackground() {
    console.log(TAG, `UIExtAbility onBackground`);
    let dialog = AppStorage.get<EnableNotificationDialog>('dialog');

    if (dialog?.subWindow !== undefined) {
      try {
        dialog?.subWindow?.hideNonSystemFloatingWindows(false);
      } catch (err) {
        console.error(TAG, 'onBackground hideNonSystemFloatingWindows failed!');
      } 
    } else {
      try {
        dialog?.extensionWindow?.hideNonSecureWindows(false);
      } catch (err) {
        console.error(TAG, 'onBackground hideNonSecureWindows failed!');
      }  
    }
  }

  async onSessionDestroy(session: UIExtensionContentSession): Promise<void> {
    console.log(TAG, `UIExtAbility onSessionDestroy`);  
    if (AppStorage.get('clicked') === false) {
      console.log(TAG, `UIExtAbility onSessionDestroy unclick destory`);
      let dialog = AppStorage.get<EnableNotificationDialog>('dialog');
      await dialog?.destroyException();
    }
  }

  async onDestroy() {
    console.info(TAG, 'UIExtAbility onDestroy.');
    await this.unsubscribe();
    await this.sleep(500);
    this.context.terminateSelf();
  }

  async sleep(ms: number): Promise<void> {
      return new Promise(resolve => setTimeout(resolve, ms));
  }

  async subscribe() {
    CommonEventManager.createSubscriber(
      { events: ['usual.event.BUNDLE_RESOURCES_CHANGED'] }, (err, subscriber) => {
      if (err?.code) {
        console.error(TAG, `createSubscriber callBack err = ${JSON.stringify(err)}`);
      } else {
        eventSubscriber = subscriber;
        console.log(TAG, "create subscriber succeed");
        if (eventSubscriber != null) {
          console.log(TAG, "subscriber subscribe BUNDLE_RESOURCES_CHANGED event");
          CommonEventManager.subscribe(eventSubscriber, (err, data) => {
            if (err?.code) {
              console.error(TAG, `subscribe callBack err= ${JSON.stringify(err)}`);
            } else {
              console.log(TAG, `subscribe callBack data= ${JSON.stringify(data)}`);
              if(data.parameters?.bundleResourceChangeType == 1){
                console.log(TAG, `BUNDLE_RESOURCES_CHANGED-language change`);
                let isUpdate:number = AppStorage.get('isUpdate');
                if (isUpdate === undefined || isUpdate > UPDATE_BOUNDARY) {
                  AppStorage.setOrCreate('isUpdate', UPDATE_NUM);
                } else {
                  AppStorage.setOrCreate('isUpdate', ++isUpdate);
                }
              }
            }
          })
        } else {
          console.info(TAG, "need create subscriber");
        }
      }
    });
  }

  async unsubscribe() {
    try {
      if (eventSubscriber != null) {
        CommonEventManager.unsubscribe(eventSubscriber, (err) => {});
      }      
    } catch (err) {
      console.info("ubsubscribe fail");
    }
  }
}


export default NotificationDialogServiceExtensionAbility;
