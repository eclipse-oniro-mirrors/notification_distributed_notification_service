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

import bundleManager from '@ohos.bundle.bundleManager';
import deviceInfo from '@ohos.deviceInfo';
import display from '@ohos.display';
import notification from '@ohos.notification';
import window from '@ohos.window';
import { titleTrim } from '../common/utils';
import Constants from '../common/constant';
import { EnableNotificationDialog } from '../ServiceExtAbility/NotificationServiceExtAbility';

const TAG = 'NotificationDialog_Service ';
const permission: Record<string, Resource> = {
  'label': $r('app.string.group_label_notification'),
  'icon': $r('app.media.ic_public_ring'),
  'reason': $r('app.string.reason'),
};
const bottomPopoverTypes = ['default', 'phone'];

let storage = LocalStorage.getShared();

@Extend(Button) function customizeButton() {
  .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
  .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
  .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
  .fontWeight(FontWeight.Medium)
  .height(Constants.BUTTON_HEIGHT)
  .flexGrow(Constants.FLEX_GROW)
}

@Entry(storage)
@Component
struct NotificationDialogPage {
  @State isUpdate: number = -1;

  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: PermissionDialog({ isUpdate: $isUpdate }),
    autoCancel: false,
    alignment: DialogAlignment.Center,
    customStyle: true
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
  @State naviHeight: number = 0;
  @State isBottomPopover: boolean = true;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  controller?: CustomDialogController;

  build() {
    GridRow({ columns: { xs: Constants.XS_COLUMNS, sm: Constants.SM_COLUMNS, md: Constants.MD_COLUMNS, lg: Constants.LG_COLUMNS }, gutter: Constants.DIALOG_GUTTER }) {
      GridCol({ span: { xs: Constants.XS_SPAN, sm: Constants.SM_SPAN, md: Constants.DIALOG_MD_SPAN, lg: Constants.DIALOG_LG_SPAN },
        offset: {xs: Constants.XS_OFFSET, sm: Constants.SM_OFFSET, md: Constants.DIALOG_MD_OFFSET, lg: Constants.DIALOG_LG_OFFSET} }) {
        Flex({ justifyContent: FlexAlign.Center, alignItems: this.isBottomPopover ? ItemAlign.End : ItemAlign.Center }) {
          Column() {
            Image(permission.icon)
              .width(Constants.DIALOG_ICON_WIDTH)
              .height(Constants.DIALOG_ICON_HEIGHT)
              .fillColor($r('sys.color.ohos_id_color_text_primary'))
              .margin({
                top: Constants.DIALOG_ICON_MARGIN_TOP
              })
            Scroll() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start }) {
                    Text() {
                      Span($r('app.string.whether_to_allow'))
                      Span(this.appName)
                      Span($r('app.string.quotes'))
                      Span(permission.label)
                    }
                    .fontSize(Constants.DIALOG_REQ_FONT_SIZE)
                    .fontColor($r('sys.color.ohos_id_color_text_primary'))
                    .fontWeight(FontWeight.Medium)
                    .lineHeight(Constants.DIALOG_REQ_LINE_HEIGHT)
                    .margin({
                      top: Constants.DIALOG_REQ_MARGIN_TOP,
                      left: Constants.DIALOG_REQ_MARGIN_LEFT,
                      right: Constants.DIALOG_REQ_MARGIN_RIGHT
                    })
                  }
                }
                Row() {
                  Flex({ justifyContent: FlexAlign.Start }) {
                    Text() {
                      Span(permission.reason)
                    }
                    .fontSize(Constants.DIALOG_DESP_FONT_SIZE)
                    .fontColor($r('sys.color.ohos_id_color_text_secondary'))
                    .lineHeight(Constants.DIALOG_DESP_LINE_HEIGHT)
                    .margin({
                      top: Constants.DIALOG_DESP_MARGIN_TOP,
                      left: Constants.DIALOG_DESP_MARGIN_LEFT,
                      right: Constants.DIALOG_DESP_MARGIN_RIGHT,
                      bottom: Constants.DIALOG_DESP_MARGIN_BOTTOM
                    })
                  }
                }
              }
            }
            .constraintSize({ maxHeight: Constants.MAXIMUM_HEADER_HEIGHT })
            Row() {
              Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                Button($r('app.string.BAN'))
                  .onClick(async (): Promise<void> => {
                    await this.enableNotification(false);
                  })
                  .customizeButton()
                Divider()
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .vertical(true)
                  .height(Constants.DIVIDER_HEIGHT)
                  .opacity(.2)
                Button($r('app.string.ALLOW'))
                  .onClick(async (): Promise<void> => {
                    await this.enableNotification(true);
                  })
                  .customizeButton()
              }
              .margin({ left: Constants.BUTTON_MARGIN_LEFT, right: Constants.BUTTON_MARGIN_RIGHT })
            }
          }
          .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
          .borderRadius(Constants.DIALOG_PRIVACY_BORDER_RADIUS)
          .width(Constants.FULL_WIDTH)
          .padding({ bottom: Constants.DIALOG_PADDING_BOTTOM })
          .margin({ bottom: $r('sys.float.ohos_id_dialog_margin_bottom') })
          .clip(true)
        }
        .width(Constants.FULL_WIDTH)
        .height(Constants.FULL_HEIGHT)
      }
    }
    .margin({
      left: this.isBottomPopover ? Constants.DIALOG_MARGIN_VERTICAL : Constants.DIALOG_MARGIN,
      right: this.isBottomPopover ? Constants.DIALOG_MARGIN_VERTICAL : Constants.DIALOG_MARGIN,
      bottom: this.isBottomPopover ? this.naviHeight : 0
    })
  }

  async updateApplicationName(bundleName: string): Promise<void> {
    console.info(TAG, `updateApplicationName bundleName: ${bundleName}`);
    try {
      let applicationInfo = await bundleManager.getApplicationInfo(bundleName,
        bundleManager.ApplicationFlag.GET_APPLICATION_INFO_DEFAULT);
      let extensionContext = AppStorage.Get('context') as Context;
      let context = extensionContext.createBundleContext(bundleName);
      let appName = context.resourceManager.getStringSync(applicationInfo.labelId);
      this.appName = titleTrim(appName);
      console.info(TAG, `hap label: ${applicationInfo.label}, value ${this.appName}`);
    } catch (err) {
      console.error(TAG, `applicationName error : ${JSON.stringify(err)}`);
    }
  }

  updateAvoidWindow(): void {
    let type = window.AvoidAreaType.TYPE_SYSTEM;
    try {
      this.dialog.window.on('avoidAreaChange', (data): void => {
        if (data.type == window.AvoidAreaType.TYPE_SYSTEM) {
          console.info(TAG, `avoidAreaChange: ${JSON.stringify(data)}`);
          this.naviHeight = data.area.bottomRect.height;
        }
      });
      let avoidArea = this.dialog.window.getWindowAvoidArea(type);
      console.info(TAG, `avoidArea: ${JSON.stringify(avoidArea)}`);
      this.naviHeight = avoidArea.bottomRect.height;
    } catch (err) {
      console.error(TAG, `Failed to obtain the area. Cause: ${JSON.stringify(err)}`);
    }
  }

  updateIsBottomPopover(): void {
    let dis = display.getDefaultDisplaySync();
    let isVertical = dis.width <= dis.height;
    this.isBottomPopover = bottomPopoverTypes.includes(deviceInfo.deviceType) && isVertical;
  }

  async updateStatus(): Promise<void> {
    let bundleNameObj = this.dialog.want.parameters.from;
    let bundleName = bundleNameObj ? bundleNameObj.toString() : '';
    await this.updateApplicationName(bundleName);
    this.updateIsBottomPopover();
  }

  async updateOnPageShow(): Promise<void> {
    if (this.isUpdate > 0) {
      await this.updateStatus();
    }
  }

  async aboutToAppear(): Promise<void> {
    this.dialog = storage.get('dialog') as EnableNotificationDialog;
    this.updateAvoidWindow();
    try {
      await this.updateStatus();
    } catch (err) {
      console.error(TAG, `aboutToAppear error : + ${JSON.stringify(err)}`);
      await this.dialog.destroyException();
    }
  }

  async enableNotification(enabled: boolean): Promise<void> {
    console.info(TAG, `NotificationDialog enableNotification: ${enabled}`);
    let fromObj = this.dialog.want.parameters.from;
    let bundleOption = {
      bundle: fromObj ? fromObj.toString() : ''
    } as notification.BundleOption;
    console.info(TAG, 'NotificationDialog before enableNotification', JSON.stringify(bundleOption));
    try {
      await notification.enableNotification(bundleOption, enabled);
    } catch (err) {
      console.error(TAG, `NotificationDialog enable error, code is ${err.code}`);
    } finally {
      await this.dialog.destroy();
    }
  }
}
