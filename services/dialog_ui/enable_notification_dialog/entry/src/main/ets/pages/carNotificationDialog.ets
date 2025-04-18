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

import bundleResourceManager from '@ohos.bundle.bundleResourceManager';
import window from '@ohos.window';
import { titleTrim, calOverLine, getFontSizeScale, getLimitFontSize } from '../common/utils';
import Constants from '../common/constant';
import { EnableNotificationDialog } from '../ServiceExtAbility/NotificationServiceExtAbility';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import { MeasureOptions } from '@ohos.measure';
import common from '@ohos.app.ability.common';
import uiextension from '@ohos.arkui.uiExtension';

const TAG = 'NotificationDialog_Service ';

let storage = LocalStorage.getShared();

@Extend(Button) function customizeButton() {
  .type(ButtonType.Normal)
  .fontColor('#E6FFFFFF')
  .fontSize(getLimitFontSize(16, getFontSizeScale(getContext(this) as common.UIAbilityContext, 2)))
  .fontWeight(FontWeight.Medium)
  .height(40)
  .width('50%')
  .borderRadius(20)
  .backgroundColor('#33F1F3F5')
  .flexGrow(Constants.FLEX_GROW)
  .outline({ width: 0.5, color: '#26FFFFFF', radius: 20 })
}

@Entry(storage)
@Component
struct NotificationDialogPage {
  @StorageLink('isUpdate') isUpdate: number = 0;

  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: PermissionDialog({ isUpdate: $isUpdate }),
    autoCancel: false,
    alignment: DialogAlignment.Center,
    customStyle: true,
    cornerRadius: 24,
    maskColor: '#CC000000',
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
      console.info(TAG, `dialog onWillDismiss reason= : ${JSON.stringify(dismissDialogAction.reason)}`);
    }
  });

  build() {}

  aboutToAppear() {
    this.privacyDialogController.open();
  }

  onPageShow() {
  }
}

@CustomDialog
struct PermissionDialog {
  @State appName: string = '';
  @State naviHeight: number = 0;
  @State isBottomPopover: boolean = false;
  @StorageLink('clicked') clicked: boolean = false;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  session?: UIExtensionContentSession;
  controller?: CustomDialogController;
  @State titleOverLine: boolean = false;
  @State contentOverLine: boolean = false;

  build() {
    Row() {
      Flex({ justifyContent: FlexAlign.Center, alignItems: this.isBottomPopover ? ItemAlign.End : ItemAlign.Center }) {
        Column() {
          Scroll() {
            Column() {
              Row() {
                Image($r('app.media.bell'))
                  .width(32)
                  .height(32)
                  .margin({ top: 24, bottom: 8 })
                  .draggable(false)
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text($r('app.string.group_label_notification', this.appName))
                    .fontSize(getLimitFontSize(20, getFontSizeScale(getContext(this) as common.UIAbilityContext, 2)))
                    .lineHeight(27)
                    .fontColor('#E6FFFFFF')
                    .fontWeight(FontWeight.Bold)
                    .heightAdaptivePolicy(TextHeightAdaptivePolicy.MAX_LINES_FIRST)
                    .maxLines(2)
                    .width('100%')
                    .textOverflow({overflow: TextOverflow.Ellipsis})
                    .textAlign(this.titleOverLine ? TextAlign.Start : TextAlign.Center)
                }
                .margin({ left: 24, right: 24, top: 16, bottom: 18 })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                  let containerWidth = newValue.width as number;
                  let options: MeasureOptions = {
                    textContent: $r('app.string.group_label_notification', this.appName),
                    fontSize: getLimitFontSize(20, getFontSizeScale(getContext(this) as common.UIAbilityContext, 2)),
                    fontWeight: FontWeight.Bold,
                  };
                  this.titleOverLine = calOverLine(containerWidth, options, this.getUIContext().getMeasureUtils());
                  console.info(TAG, `onSizeChange title isOverLine: ${this.titleOverLine}`);
                })
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text() {
                    Span($r('app.string.reason_tv'))
                  }
                  .lineHeight(19)
                  .fontSize(14)
                  .width('100%')
                  .fontWeight(FontWeight.Medium)
                  .fontColor('#E6FFFFFF')
                  .textAlign(this.contentOverLine ? TextAlign.Start : TextAlign.Center)
                }
                .margin({ left: 24, right: 24 })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                  let containerWidth = newValue.width as number;
                  let options: MeasureOptions = {
                    textContent: $r('app.string.reason_tv'),
                    fontSize: getLimitFontSize(14,
                      getFontSizeScale(getContext(this) as common.UIAbilityContext)),
                    fontWeight: FontWeight.Medium,
                  };
                  this.contentOverLine = calOverLine(containerWidth, options, this.getUIContext().getMeasureUtils());
                  console.info(TAG, `onSizeChange content isOverLine: ${this.contentOverLine}`);
                })
              }
              Row() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Button($r('app.string.BAN'))
                    .onClick(async (): Promise<void> => {
                      await this.enableNotification(false);
                    })
                    .customizeButton()
                    .margin({right: 8})
                  Button($r('app.string.ALLOW'))
                    .onClick(async (): Promise<void> => {
                      await this.enableNotification(true);
                    })
                    .customizeButton()
                    .margin({left: 8})
                }
                .margin({ left: 24, right: 24, top: 24, bottom: 24 })
              }
            }
          }
          .constraintSize({ maxHeight: '80%'})
        }
        .width(440)
        .borderRadius(24)
        .backgroundEffect({ radius: 40, color: '#1AFFFFFF' })
        .outline({ width: 0.5, color: '#26FFFFFF', radius: 24 })
        .clip(true)
      }
      .backgroundEffect({ radius: 40})
      .width('100%')
      .height('100%')
    }
  }

  async aboutToAppear(): Promise<void> {
    this.dialog = storage.get('dialog') as EnableNotificationDialog;
    this.session = storage.get('session') as UIExtensionContentSession;
    this.updateAvoidWindow();
    this.updateSubWindowSize();
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

  async updateOnPageShow(): Promise<void> {
    if (this.isUpdate > 0) {
      await this.updateStatus();
    }
  }

  async updateStatus(): Promise<void> {
    let bundleNameObj = this.dialog?.want.parameters?.bundleName;
    let bundleName = bundleNameObj ? bundleNameObj.toString() : '';
    await this.updateApplicationName(bundleName);
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

  updateAvoidWindow(): void {
    let type = window.AvoidAreaType.TYPE_SYSTEM;
    try {
      this.dialog?.extensionWindow.on('avoidAreaChange', (data): void => {
        if (data.type == window.AvoidAreaType.TYPE_SYSTEM) {
          console.info(TAG, `avoidAreaChange: ${JSON.stringify(data)}`);
          this.naviHeight = data.area.bottomRect.height;
        }
      });
      let avoidArea = this.dialog?.extensionWindow.getWindowAvoidArea(type);
      if (avoidArea != undefined) {
        console.info(TAG, `avoidArea: ${JSON.stringify(avoidArea)}`);
        this.naviHeight = avoidArea.bottomRect.height;
      }
    } catch (err) {
      console.error(TAG, `Failed to obtain the area. Cause: ${err?.code}`);
    }
  }

  updateSubWindowSize(): void {
    try {
      this.dialog?.extensionWindow.on('rectChange', uiextension.RectChangeReason.HOST_WINDOW_RECT_CHANGE, (data):void => {
        let windowRect = this.dialog?.extensionWindow.properties?.uiExtensionHostWindowProxyRect;
        console.info(TAG, `windowRectChange event, size = ${windowRect?.left}-${windowRect?.top}-${windowRect?.width}-${windowRect?.height}`);
        this.dialog?.subWindow?.moveWindowTo(windowRect?.left, windowRect?.top);
        this.dialog?.subWindow?.resize(windowRect?.width, windowRect?.height);
      });
    } catch (err) {
      console.error(TAG, `updateSubWindowSize error. Cause: ${err?.code}`);
    }
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
}
