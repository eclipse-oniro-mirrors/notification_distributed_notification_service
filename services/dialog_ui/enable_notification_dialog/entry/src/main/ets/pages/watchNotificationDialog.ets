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

import bundleResourceManager from '@ohos.bundle.bundleResourceManager';
import display from '@ohos.display';
import window from '@ohos.window';
import { titleTrim } from '../common/utils';
import Constants from '../common/constant';
import fs from '@ohos.file.fs';
import configPolicy from '@ohos.configPolicy';
import { EnableNotificationDialog } from '../ServiceExtAbility/NotificationServiceExtAbility';
import { Callback} from '@ohos.base';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';

const TAG = 'NotificationDialog_Service ';
const permission: Record<string, Resource> = {
  'label': $r('app.string.group_label_notification'),
  'icon': $r('app.media.ic_public_ring'),
  'reason': $r('app.string.reason'),
};

let storage = LocalStorage.getShared();

@Entry(storage)
@Component
struct NotificationDialogPage {
  @StorageLink('isUpdate') isUpdate: number = -1;
  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: PermissionDialog({ isUpdate: $isUpdate }),
    autoCancel: false,
    alignment: DialogAlignment.TopStart,
    customStyle: false,
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
      console.info(TAG, `dialog onWillDismiss reason= : ${JSON.stringify(dismissDialogAction.reason)}`);
    },
    width: '466px',
    height: '466px'
  });

  build() {}

  aboutToAppear() {
    this.privacyDialogController.open();
  }

  onPageShow() {
    this.isUpdate++;
  }
}

@CustomDialog
struct PermissionDialog {
  @State appName: string = '';
  @State isBottomPopover: boolean = true;
  @StorageLink('clicked') clicked: boolean = false;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  session?: UIExtensionContentSession;
  controller?: CustomDialogController;
  @State buttonWidthAllow: number = 0;
  @State buttonWidthDeny: number = 0;
  @State buttonWidth: string | number = 'auto';

  build() {
    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {   
      Column() {
        Scroll() {
          Column() {
            Row() {
              Image(permission.icon)
                .width('92px')
                .height('92px')
                .margin({
                  top: 8
                })
            }

            Row() {
              Flex({ justifyContent: FlexAlign.Center }) {
                Text() {
                  Span(getContext(this).resourceManager.getStringSync(permission.label.id).replace('%s', this.appName))
                }
                .fontSize('36px')
                .fontColor('#FFFFFF')
                .fontWeight(500)
                .lineHeight('Auto')
                .margin({
                  top: 12,
                  left: 26,
                  right: 26
                })
                .textAlign(TextAlign.Center)
              }
            }

            Row() {
              Flex({ justifyContent: FlexAlign.Center }) {
                Button() {
                  Text($r('app.string.ALLOW'))
                  .fontColor('#FFFFFF')
                  .fontWeight(500)
                  .minFontSize('27px')
                  .maxFontSize('30px')
                  .maxLines(1)
                  .textOverflow({overflow: TextOverflow.MARQUEE})
                }
                .onClick(async (): Promise<void> => {
                  await this.enableNotification(true);
                })
                .backgroundColor('#FF1F71FF')
                .width(this.buttonWidth)
                .height('80px')  
                .constraintSize({ 
                    minWidth: '232px',
                    maxWidth: '362px'
                })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                  console.info(`onSizeChange-allow, newValue=${newValue?.width}.`)
                  this.buttonWidthAllow = newValue?.width as number;
                  this.updateButtonWidth();
                })
              }
              .margin({top:16})
            }

            Row() {
              Flex({ justifyContent: FlexAlign.Center }) {
                Button() {
                  Text($r('app.string.BAN'))
                  .fontColor('#5EA1FF')
                  .fontWeight(500)
                  .minFontSize('27px')
                  .maxFontSize('30px')
                  .maxLines(1)
                  .textOverflow({overflow: TextOverflow.MARQUEE})
                }
                .onClick(async (): Promise<void> => {
                  await this.enableNotification(false);
                })
                .backgroundColor('#405ea1ff')
                .width(this.buttonWidth)
                .height('80px')  
                .constraintSize({ 
                    minWidth: '232px',
                    maxWidth: '362px'
                })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                  console.info(TAG, `onSizeChange-deny, newValue=${newValue?.width}.`)
                  this.buttonWidthDeny = newValue?.width as number;
                  this.updateButtonWidth();
                })
              }
              .margin({
                top:12,
                bottom:36})
            }
          }
        }
        .scrollBar(BarState.Off)
      } 
    }
    .margin({
      top: 0,
      left: 0,
      right: 0,
      bottom: 0
    })
    .width('100%')
    .height('100%')
    .backgroundColor('#ff000000')
    
  }

  async updateApplicationName(bundleName: string): Promise<void> {
    console.info(TAG, `updateApplicationName bundleName: ${bundleName}`);
    try {
      let bundleFlags = bundleResourceManager.ResourceFlag.GET_RESOURCE_INFO_ALL;
      let resourceInfo = bundleResourceManager.getBundleResourceInfo(bundleName, bundleFlags);
      console.info(TAG, `applicationName name : ${JSON.stringify(resourceInfo.label)}`);
      let appName = resourceInfo.label;
      this.appName = titleTrim(appName);
      console.info(TAG, `hap label: ${this.appName}`);
    } catch (err) {
      console.error(TAG, `applicationName error : ${err?.code}`);
    }
  }

  async updateIsBottomPopover(): Promise<void> {
    let dis = display.getDefaultDisplaySync();
    let isVertical = dis.width <= dis.height;
    try {
      if (display.isFoldable()) {
        let foldStatus = display.getFoldStatus();
        if (foldStatus == display.FoldStatus.FOLD_STATUS_EXPANDED ||
          foldStatus == display.FoldStatus.FOLD_STATUS_HALF_FOLDED) {
            this.isBottomPopover = false;
            return;
        }
      }
    } catch (err) {
      console.error(TAG, 'Failed to get the device foldable status. Code: ${err?.code}');
    }

    // read ccm configs
    let isBottomPopoverTemp = false;
    try {
      let filePaths = await configPolicy.getCfgFiles(Constants.CCM_CONFIG_PATH);
      for (let i = 0; i < filePaths.length; i++) {
        let res = fs.accessSync(filePaths[i]);
        if (res) {
          let fileContent = fs.readTextSync(filePaths[i]);
          let config: NotificationConfig = JSON.parse(fileContent);
          if (config.notificationAuthorizationWindow != undefined) {
            let windowConfig: NotificationAuthorizationWindow = config.notificationAuthorizationWindow;
            if (windowConfig.isBottomPopover != undefined) {
              isBottomPopoverTemp = windowConfig.isBottomPopover;
            }
          }
        }
      }
    } catch (error) {
      console.log(TAG, 'Failed get ccm files, Cause: ${err?.code}');
    }
    this.isBottomPopover = isBottomPopoverTemp && isVertical;
  }

  async updateStatus(): Promise<void> {
    let bundleNameObj = this.dialog?.want.parameters?.bundleName;
    let bundleName = bundleNameObj ? bundleNameObj.toString() : '';
    await this.updateApplicationName(bundleName);
    await this.updateIsBottomPopover();
  }

  async updateOnPageShow(): Promise<void> {
    if (this.isUpdate > 0) {
      await this.updateStatus();
    }
  }

  async aboutToAppear(): Promise<void> {
    this.dialog = storage.get('dialog') as EnableNotificationDialog;
    this.session = storage.get('session') as UIExtensionContentSession;
    try {
      await this.updateStatus();
    } catch (err) {
      console.error(TAG, `aboutToAppear error : ${err?.code}`);
      await this.dialog?.destroyException();
      await this.session?.terminateSelf();
    }
  }

  async aboutToDisappear(): Promise<void> {
    console.info(TAG, `aboutToDisappear`);
    this.session?.terminateSelf();
  }

  async enableNotification(enabled: boolean): Promise<void> {
    console.info(TAG, `NotificationDialog enableNotification: ${enabled}`);
    try {
      await this.dialog?.publishButtonClickedEvent(enabled);
      this.clicked = true;
    } catch (err) {
      console.error(TAG, `NotificationDialog enable error, code is ${err?.code}`);
      await this.dialog?.destroyException();
    } finally {
      await this.dialog?.subWindow?.destroyWindow();
      this.session?.terminateSelf();
    }
  }

  async updateButtonWidth(): Promise<void> {
    if(this.buttonWidthAllow > 0 && this.buttonWidthDeny > 0) {
      console.info(TAG, 'updateButtonWidth');
      if (this.buttonWidthAllow > this.buttonWidthDeny) {
        this.buttonWidth = this.buttonWidthAllow;
      } else {
        this.buttonWidth = this.buttonWidthDeny;
      }
    }
  }
}

interface NotificationConfig {
  notificationAuthorizationWindow: NotificationAuthorizationWindow;
}

interface NotificationAuthorizationWindow {
  isBottomPopover: boolean;
}

interface NotificationConfigAbc {
  deviceType: DeviceType;
}

interface DeviceType {
  isWatch: boolean;
}
