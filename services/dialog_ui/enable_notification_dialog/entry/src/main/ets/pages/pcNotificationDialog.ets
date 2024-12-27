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
import {
  titleTrim, 
  calContainerWidth,
  getFontSizeScale,
  sourceToVp,
  getLimitFontSize } from '../common/utils';
import Constants from '../common/constant';
import fs from '@ohos.file.fs';
import configPolicy from '@ohos.configPolicy';
import { EnableNotificationDialog } from '../ServiceExtAbility/NotificationServiceExtAbility';
import { Callback} from '@ohos.base';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import { MeasureOptions } from '@ohos.measure';
import { MeasureUtils } from '@ohos.arkui.UIContext';
import common from '@ohos.app.ability.common';
import uiextension from '@ohos.arkui.uiExtension';

const TAG = 'NotificationDialog_Service ';

const permission: Record<string, Resource> = {
  'label': $r('app.string.group_label_notification'),
  'icon': $r('app.media.ic_public_ring'),
  'reason': $r('app.string.reason_simple'),
};

let storage = LocalStorage.getShared();

@Extend(Button) function customizeButton() {
  .type(ButtonType.Normal)
  .backgroundColor($r('sys.color.comp_background_tertiary'))
  .fontColor($r('sys.color.font_emphasize'))
  .fontSize(
    getLimitFontSize(
      sourceToVp($r('sys.float.Body_L')),
      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
  )
  .fontWeight(FontWeight.Medium)
  .height(Constants.PC_BUTTON_HEIGHT)
  .width('50%')
  .borderRadius(Constants.PC_RDIUS_8)
  .flexGrow(Constants.FLEX_GROW)
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
    cornerRadius: Constants.PC_RDIUS_16,
    maskColor: $r('sys.color.ohos_id_color_mask_thin'),
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
  @State titleContainerWidth: string | number = 'auto';

  build() {
    Row() {
      Flex({ justifyContent: FlexAlign.Center, alignItems: this.isBottomPopover ? ItemAlign.End : ItemAlign.Center }) {
        Column() {
          Scroll() {
            Column() {
              Row() {
                Image(permission.icon)
                .width(Constants.DIALOG_ICON_WIDTH)
                .height(Constants.DIALOG_ICON_HEIGHT)
                .margin({
                  top: Constants.PC_ICON_MARGIN_TOP
                })
                .draggable(false)
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text($r('app.string.group_label_notification', this.appName))
                  .fontSize($r('sys.float.Title_S'))
                  .fontColor($r('sys.color.font_primary'))
                  .fontWeight(FontWeight.Bold)
                  .minFontSize(
                    getLimitFontSize(Constants.TITLE_MIN_FONT_SIZE,
                      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
                  )
                  .maxFontSize(
                    getLimitFontSize(sourceToVp($r('sys.float.Title_S')),
                      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
                  )
                  .heightAdaptivePolicy(TextHeightAdaptivePolicy.MAX_LINES_FIRST)
                  .maxLines(2)
                  .textOverflow({overflow: TextOverflow.Ellipsis})
                  .width(this.titleContainerWidth)
                  .textAlign(TextAlign.Center)
                }
                .margin({
                  left: Constants.PC_TITLE_MARGIN_SIDE,
                  right: Constants.PC_TITLE_MARGIN_SIDE,
                  top: Constants.PC_TITLE_MARGIN_TOP,
                })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                    let containerWidth = newValue.width as number;
                    let options: MeasureOptions = {
                      textContent: $r('app.string.group_label_notification', this.appName),
                      fontSize: getLimitFontSize(sourceToVp($r('sys.float.Title_S')),
                      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX)),
                      fontWeight: FontWeight.Bold,
                    };
                    this.titleContainerWidth = calContainerWidth(containerWidth, options,
                      Constants.CROSS_LINE_RATIO, this.getUIContext().getMeasureUtils());
                    console.info(TAG, `onSizeChange titleContainerWidth: ${this.titleContainerWidth}`);
                  })
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text() {
                    Span(permission.reason)
                  }
                  .fontSize(
                    getLimitFontSize(sourceToVp($r('sys.float.Body_L')),
                      getFontSizeScale(getContext(this) as common.UIAbilityContext))
                  )
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('sys.color.font_primary'))
                  .margin({
                    left: Constants.PC_CONTENT_MARGIN_SIDE,
                    right: Constants.PC_CONTENT_MARGIN_SIDE,
                    top: Constants.PC_CONTENT_MARGIN_TOP
                  })
                }
              }
              Row() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Button($r('app.string.BAN'))
                    .onClick(async (): Promise<void> => {
                    await this.enableNotification(false);
                    })
                    .customizeButton()
                  Divider()
                    .color($r('sys.color.comp_divider'))
                    .vertical(true)
                    .height(Constants.DIVIDER_HEIGHT)
                    .strokeWidth(Constants.DIVIDER_WIDTH)
                    .margin({left: Constants.BUTTON_LEFT, right: Constants.BUTTON_RIGHT})
                  Button($r('app.string.ALLOW'))
                    .onClick(async (): Promise<void> => {
                      await this.enableNotification(true);
                    })
                    .customizeButton()
                }
                .margin({ 
                  left: Constants.PC_OPERATE_MARGIN_SIDE, 
                  right: Constants.PC_OPERATE_MARGIN_SIDE, 
                  top: Constants.PC_OPERATE_MARGIN_TOP,
                  bottom: Constants.PC_OPERATE_MARGIN_BUTTOM 
                })
              }
            }
          }
          .constraintSize({ maxHeight: Constants.MAXIMUM_HEADER_HEIGHT })
        }
        .borderRadius(Constants.PC_RDIUS_16)
        .backgroundBlurStyle(BlurStyle.COMPONENT_ULTRA_THICK)
        .width(Constants.PC_DIALOG_WIDTH)
        .outline({
            width: 1,
            color: Constants.PC_OUTLINE_COLOR,
            radius: Constants.PC_RDIUS_16
          })
        .clip(true)
      }
      .width(Constants.FULL_WIDTH)
      .height(Constants.FULL_HEIGHT)
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