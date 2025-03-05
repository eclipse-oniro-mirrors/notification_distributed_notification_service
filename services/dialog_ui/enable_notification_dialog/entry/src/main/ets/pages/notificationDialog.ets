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

const TAG = 'NotificationDialog_Service ';
const permission: Record<string, Resource> = {
  'label': $r('app.string.group_label_notification'),
  'icon': $r('app.media.ic_public_ring'),
  'reason': $r('app.string.reason'),
};
const bottomPopoverTypes = ['default', 'phone'];

let storage = LocalStorage.getShared();

@Extend(Button) function customizeButton() {
  .backgroundColor(Color.Transparent)
  .fontColor($r('app.color.button_text'))
  .fontSize(
    getLimitFontSize(
      Constants.TEXT_MIDDLE_FONT_SIZE,
      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
  )
  .fontWeight(FontWeight.Medium)
  .height(Constants.BUTTON_HEIGHT)
  .flexGrow(Constants.FLEX_GROW)
  .width('50%')
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
    maskColor: $r('app.color.mask_thin'),
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
  @State isBottomPopover: boolean = true;
  @StorageLink('clicked') clicked: boolean = false;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  session?: UIExtensionContentSession;
  controller?: CustomDialogController;
  @State titleContainerWidth: string | number = 'auto';
  @State maxHeight: string|number = '85%';

  build() {
    Row(){
      Flex({ justifyContent: FlexAlign.Center, alignItems: this.isBottomPopover ? ItemAlign.End : ItemAlign.Center }) {
        Column() {
          Scroll() {
            Column() {
              Row() {
                Image(permission.icon)
                .width(Constants.DIALOG_ICON_WIDTH)
                .height(Constants.DIALOG_ICON_HEIGHT)
                .margin({
                  top: Constants.DIALOG_ICON_MARGIN_TOP
                })
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text($r('app.string.group_label_notification', this.appName))
                  .fontSize($r('sys.float.ohos_id_text_size_headline8'))
                  .fontColor($r('app.color.text_primary'))
                  .fontWeight(FontWeight.Bold)
                  .minFontSize(
                    getLimitFontSize(Constants.TITLE_MIN_FONT_SIZE,
                      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
                  )
                  .maxFontSize(
                    getLimitFontSize(sourceToVp($r('sys.float.ohos_id_text_size_headline8')),
                      getFontSizeScale(getContext(this) as common.UIAbilityContext, Constants.FONT_SCALE_MAX))
                  )
                  .heightAdaptivePolicy(TextHeightAdaptivePolicy.MAX_LINES_FIRST)
                  .maxLines(2)
                  .textOverflow({overflow: TextOverflow.Ellipsis})
                  .width(this.titleContainerWidth)
                  .textAlign(TextAlign.Center)
                }
                .margin({
                  top: Constants.DIALOG_REQ_MARGIN_TOP,
                  bottom:Constants.DIALOG_REQ_MARGIN_BUTTOM,
                  left: Constants.DIALOG_REQ_MARGIN_LEFT,
                  right: Constants.DIALOG_REQ_MARGIN_RIGHT
                })
                .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                  let containerWidth = newValue.width as number;
                  let options: MeasureOptions = {
                    textContent: $r('app.string.group_label_notification', this.appName),
                    fontSize: getLimitFontSize(sourceToVp($r('sys.float.ohos_id_text_size_headline8')),
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
                  .fontSize(Constants.DIALOG_DESP_FONT_SIZE)
                  .fontWeight(FontWeight.Regular)
                  .fontColor($r('app.color.text_primary'))
                  .lineHeight(Constants.DIALOG_DESP_LINE_HEIGHT)
                }
                .margin({
                  top: Constants.DIALOG_DESP_MARGIN_TOP,
                  left: Constants.DIALOG_DESP_MARGIN_LEFT,
                  right: Constants.DIALOG_DESP_MARGIN_RIGHT,
                  bottom: Constants.DIALOG_DESP_MARGIN_BOTTOM
                })
              }
              Row() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Button($r('app.string.BAN'))
                    .onClick(async (): Promise<void> => {
                    await this.enableNotification(false);
                    })
                    .customizeButton()
                  Divider()
                    .color($r('app.color.comp_divider'))
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
                .margin({ left: Constants.BUTTON_MARGIN_LEFT, right: Constants.BUTTON_MARGIN_RIGHT })
              }
            }
          }
        }
        .borderRadius(Constants.DIALOG_PRIVACY_BORDER_RADIUS)
        .backgroundBlurStyle(BlurStyle.COMPONENT_ULTRA_THICK)
        .width(Constants.FULL_WIDTH)
        .padding({ bottom: Constants.DIALOG_PADDING_BOTTOM })
        .clip(true)
      }
    }
    .margin({
      left: this.isBottomPopover ? Constants.DIALOG_MARGIN_VERTICAL : Constants.DIALOG_MARGIN,
      right: this.isBottomPopover ? Constants.DIALOG_MARGIN_VERTICAL : Constants.DIALOG_MARGIN,
      bottom: this.isBottomPopover ? this.naviHeight : 0
    })
    .constraintSize({ 
      maxHeight: this.maxHeight,
      maxWidth: Constants.MAX_DIALOG_WIDTH
    })
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
      this.dialog?.extensionWindow.on('windowSizeChange', (data):void => {
        let windowRect = this.dialog?.extensionWindow.properties?.uiExtensionHostWindowProxyRect;
        console.info(TAG, `windowSizeChange event, size = ${windowRect?.left}-${windowRect?.top}-${windowRect?.width}-${windowRect?.height}`);
        if (!this.dialog?.initSubWindowSize && windowRect.width > 0 && windowRect.height > 0) {
          console.info(TAG, `windowSizeChange first time update`);
          this.dialog?.subWindow?.moveWindowToGlobal(windowRect?.left, windowRect?.top);
          this.dialog?.subWindow?.resize(windowRect?.width, windowRect?.height);
          this.dialog.initSubWindowSize = true;
        }
        this.updatemaxHeight();
      });
    } catch (err) {
      console.error(TAG, `updateSubWindowSize error. Cause: ${err?.code}`);
    }
  }

  updatemaxHeight(): void {
    try {
      let windowRect = this.dialog?.extensionWindow.properties?.uiExtensionHostWindowProxyRect;
      let height = windowRect?.height;
      let navigationArea = this.dialog?.extensionWindow.getWindowAvoidArea(
          window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR);
      let navigationHeight = navigationArea?.bottomRect?.height;
      let systemArea = this.dialog?.extensionWindow.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM);
      let statusBarHeight = systemArea?.topRect?.height;
      console.info(TAG, `windowHeight ${windowRect?.height} 
          navigationHeight ${navigationHeight} statusBarHeight ${statusBarHeight} `);
      if (height > 0 && (height - navigationHeight - statusBarHeight) > 0 ) {
        this.maxHeight = px2vp((height - navigationHeight - statusBarHeight) * 0.9);
      }
    } catch (err) {
      console.error(TAG, `updatemaxHeight error. Cause: ${err?.code}`);
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
    this.updateAvoidWindow();
    this.updateSubWindowSize();
    this.updatemaxHeight();
    try {
      await this.updateStatus();
      await this.dialog?.dialogOpenEvent();
    } catch (err) {
      console.error(TAG, `aboutToAppear error : ${err?.code}`);
      await this.dialog?.destroyException();
      await this.session?.terminateSelf();
    }
  }

  async registerFoldableCallback(): Promise<void> {
    let callback: Callback<display.FoldDisplayMode> = async (data: display.FoldDisplayMode) => {
      try {
        let win = this.dialog.window;
        let dis = display.getDefaultDisplaySync();
        await win.moveWindowTo(0, 0);
        await win.resize(dis.width, dis.height);
        await this.updateStatus();
      } catch (err) {
        console.error(TAG, 'Failed to touch callback. Code: ${err?.code}');
      }
    };
    try {
      display.on('foldDisplayModeChange', callback);
    } catch (err) {
      console.error(TAG, 'Failed to register callback. Code: ${err?.code}');
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
}

interface NotificationConfig {
  notificationAuthorizationWindow: NotificationAuthorizationWindow;
}

interface NotificationAuthorizationWindow {
  isBottomPopover: boolean;
}
