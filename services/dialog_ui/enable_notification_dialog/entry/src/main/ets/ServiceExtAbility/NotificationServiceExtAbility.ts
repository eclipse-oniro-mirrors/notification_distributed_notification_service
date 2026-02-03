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
import uiExtension from '@ohos.arkui.uiExtension';
import StartOptions from '@ohos.app.ability.StartOptions';
import configPolicy from '@ohos.configPolicy';
import fs from '@ohos.file.fs';
import Constants from '../common/constant';
import DisplayUtils from '../common/displayUtils';
import bundleManager from '@ohos.bundle.bundleManager';

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
  DIALOG_SERVICE_DESTROYED,
  REMOVE_BUNDLE,
  DIALOG_OPEN
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

interface NotificationConfig {
  deviceInfo: DeviceInfo;
  banAffectContentWhiteList: string[];
}

interface DeviceInfo {
  isWatch: boolean;
  isCar: boolean;
  isPc: boolean;
  isTv: boolean;
}

export class EnableNotificationDialog {
  static ENABLE_NOTIFICATION_DIALOG_NAME = 'EnableNotificationDialog';
  static DIALOG_PATH = 'pages/notificationDialog';
  static WATCH_DIALOG_PATH = 'pages/watchNotificationDialog';
  static PC_DIALOG_PATH = 'pages/pcNotificationDialog';
  static TV_DIALOG_PATH = 'pages/tvNotificationDialog';
  static CAR_DIALOG_PATH = 'pages/carNotificationDialog';
  static EMPTY_PAGE_PATH = 'pages/emptyPage';
  static MASK_COLOR = '#33000000';
  static TRANSPARANT_COLOR = '#00000000';
  static SCENEBOARD_BUNDLE = 'com.ohos.sceneboard';
  static SYSTEMUI_BUNDLE = 'com.ohos.systemui';

  id: number;
  want: Want;
  window: window.Window;
  extensionWindow:uiExtension.WindowProxy;
  storage: LocalStorage;
  stageModel: boolean;
  subWindow: window.Window;
  initSubWindowSize: boolean;
  innerLake: boolean;
  easyAbroad: boolean;
  path: string;
  hasConfig: boolean;
  isPcDevice:boolean;
  banAffectContent: boolean;

  constructor(id: number, want: Want, stageModel: boolean, innerLake: boolean, easyAbroad: boolean) {
    this.id = id;
    this.want = want;
    this.stageModel = stageModel;
    this.window = undefined;
    this.extensionWindow = undefined;
    this.initSubWindowSize = false;
    this.innerLake = innerLake;
    this.easyAbroad = easyAbroad;
    this.path = EnableNotificationDialog.DIALOG_PATH;
    this.hasConfig = true;
    this.isPcDevice = false;
    this.banAffectContent = false;
  }


  async createUiExtensionWindow(session: UIExtensionContentSession, stageModel: boolean): Promise<void> {
    try {
      let extensionWindow = session.getUIExtensionWindowProxy();
      this.extensionWindow = extensionWindow;
      let shouldHide = true;

      this.storage = new LocalStorage({
        'dialog': this,
        'session': session
      });
      
      await this.readConfig();
      if (stageModel && this.hasConfig) {
        let subWindowOpts : window.SubWindowOptions = {
          'title': '',
          decorEnabled: false,
          isModal: true,
          isTopmost: true
        };
        let subWindow = await extensionWindow.createSubWindowWithOptions('subWindowForHost' + Date(), subWindowOpts);
        this.subWindow = subWindow;
        
        if (this.isPcDevice) {
          extensionWindow.on('rectChange', uiExtension.RectChangeReason.HOST_WINDOW_RECT_CHANGE, (data):void => {
            console.info(TAG, 'uec rect change');
            let uecRectChangeNum:number = AppStorage.get('uecRectChangeNum');
            if (uecRectChangeNum === undefined || uecRectChangeNum > UPDATE_BOUNDARY) {
              AppStorage.setOrCreate('uecRectChangeNum', UPDATE_NUM);
            } else {
              AppStorage.setOrCreate('uecRectChangeNum', ++uecRectChangeNum);
            }
          });
        }
        try {
          await subWindow.setFollowParentWindowLayoutEnabled(true);
          this.initSubWindowSize = true;
        } catch (err) {
          console.error(TAG, `setFollowParentWindowLayoutEnabled failed! ${err.code} ${err.message}`);
        }
        await subWindow.loadContent(this.path, this.storage);
        try {
          await subWindow.hideNonSystemFloatingWindows(true);
        } catch (err) {
          console.error(TAG, 'subWindow hideNonSystemFloatingWindows failed!');
        }

        await subWindow.setWindowBackgroundColor(EnableNotificationDialog.TRANSPARANT_COLOR);
        await subWindow.showWindow();
      } else {
        await session.loadContent(this.path, this.storage);  
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

async readConfig(): Promise<void> {
    try {
      let filePaths = await configPolicy.getCfgFiles(Constants.CCM_CONFIG_PATH);
      if (filePaths.length === 0) {
        console.info(TAG, 'not get any configFile');
        this.hasConfig = false;
      }
      for (let i = 0; i < filePaths.length; i++) {
        let res = fs.accessSync(filePaths[i]);
        if (!res) {
          console.error(TAG, 'accessSync false');
          return;
        }
        let fileContent = fs.readTextSync(filePaths[i]);
        let config: NotificationConfig = JSON.parse(fileContent);
        if (config.deviceInfo !== undefined) {
          let deviceInfo: DeviceInfo = config.deviceInfo;
          if (deviceInfo.isWatch !== undefined) {
            this.path = EnableNotificationDialog.WATCH_DIALOG_PATH;
            console.info(TAG, 'watch request');
          }
          if (deviceInfo.isPc !== undefined) {
            this.path = EnableNotificationDialog.PC_DIALOG_PATH;
            this.isPcDevice = true;
            console.info(TAG, 'pc request');
          }
          if (deviceInfo.isTv !== undefined) {
            this.path = EnableNotificationDialog.TV_DIALOG_PATH;
            console.info(TAG, 'tv request');
          }
          if (deviceInfo.isCar !== undefined) {
            this.path = EnableNotificationDialog.CAR_DIALOG_PATH;
            console.info(TAG, 'car request');
          }
        }
        if (config.banAffectContentWhiteList !== undefined && 
          config.banAffectContentWhiteList.includes(this.want.parameters.bundleName.toString())) {
            this.banAffectContent = true;
        }
      }
    } catch (err) {
      console.error(TAG, 'Failed get ccm files');
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

  async dialogOpenEvent(): Promise<void> {
    CommonEventManager.publish(
      COMMON_EVENT_NAME,
      {
        code: DialogStatus.DIALOG_OPEN,
        data: this.want.parameters.bundleName.toString(),
        parameters: {
          bundleName: this.want.parameters.bundleName.toString(),
          bundleUid: this.want.parameters.bundleUid.toString()
        }
      } as CommonEventManager.CommonEventPublishData,
      () => { console.info(TAG, 'publish DIALOG OPEN event succeeded'); }
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
      let innerLake = false;
      let easyAbroad = false;
      if (bundleName !== EnableNotificationDialog.SCENEBOARD_BUNDLE &&
        bundleName !== EnableNotificationDialog.SYSTEMUI_BUNDLE) {
        want.parameters.bundleName = bundleName;
        want.parameters.bundleUid = bundleUid;
        stageModel = true;
        console.log(TAG, `stage model`);
      } else {
        stageModel = false;
        innerLake = Boolean(want.parameters.innerLake);
        easyAbroad = Boolean(want.parameters.easyAbroad);
        console.log(TAG, ` un stage model innerLake = ${innerLake},  easyAbroad = ${easyAbroad}`);
      }
      console.log(TAG, `UIExtAbility onSessionCreate bundleName ${want.parameters.bundleName}` +
        `uid ${want.parameters.bundleUid}`);    
        let dialog = new EnableNotificationDialog(1, want, stageModel, innerLake, easyAbroad);
      await dialog.createUiExtensionWindow(session, stageModel);
      AppStorage.setOrCreate('dialog', dialog);
    } catch (err) {
      console.error(TAG, `Failed to handle onSessionCreate`);
      await handleDialogQuitException(want);
      this.context.terminateSelf();
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

  async onDestroy(): Promise<void> {
    console.info(TAG, 'UIExtAbility onDestroy.');
    await this.unsubscribe();
    await this.sleep(500);
    this.context.terminateSelf();
  }

  async sleep(ms: number): Promise<void> {
      return new Promise(resolve => setTimeout(resolve, ms));
  }

  async subscribe(): Promise<void> {
    await CommonEventManager.createSubscriber(
      { events: ['usual.event.BUNDLE_RESOURCES_CHANGED'] })
      .then((subscriber:CommonEventManager.CommonEventSubscriber) => {
        eventSubscriber = subscriber;
      })
      .catch((err) => {
        console.log(TAG, `subscriber createSubscriber error code is ${err.code}, message is ${err.message}`);
      });

    if (eventSubscriber === null) {
      console.log(TAG, 'need create subscriber');
      return;
    }
    CommonEventManager.subscribe(eventSubscriber, (err, data) => {
      if (err?.code) {
        console.error(TAG, `subscribe callBack err= ${JSON.stringify(err)}`);
      } else {
        console.log(TAG, `subscribe callBack data= ${JSON.stringify(data)}`);
        if (data.parameters?.bundleResourceChangeType !== 1) {
          return;
        }
        console.log(TAG, `BUNDLE_RESOURCES_CHANGED-language change`);
        let isUpdate:number = AppStorage.get('isUpdate');
        if (isUpdate === undefined || isUpdate > UPDATE_BOUNDARY) {
          AppStorage.setOrCreate('isUpdate', UPDATE_NUM);
        } else {
          AppStorage.setOrCreate('isUpdate', ++isUpdate);
        }
      }
    });
  }

  async unsubscribe(): Promise<void> {
    try {
      if (eventSubscriber != null) {
        CommonEventManager.unsubscribe(eventSubscriber, (err) => {});
      }      
    } catch (err) {
      console.info('ubsubscribe fail');
    }
  }
}


export default NotificationDialogServiceExtensionAbility;
