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
import {
  isDrp,
  isOvVersion, 
  isEuropeRegion } from '../common/utils';

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
    customStyle: true,
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
      console.info(TAG, `dialog onWillDismiss reason= : ${JSON.stringify(dismissDialogAction.reason)}`);
    }
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
  private context: Context = getContext(this);
  private drpScroller: Scroller = new Scroller();
  private defaultScroller:Scroller = new Scroller();
  @State appName: string = '';
  @State isBottomPopover: boolean = true;
  @StorageLink('clicked') clicked: boolean = false;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  session?: UIExtensionContentSession;
  controller?: CustomDialogController;
  @State buttonWidthAllow: number = 0;
  @State buttonWidthDeny: number = 0;
  @State buttonWidth: number = 120;
  @State europeRegion: boolean = false;
  @State allowPressed: boolean = false;
  @State denyPressed: boolean = false;
  @State drpDevice: boolean = false;
  @State drpAllowButtonMinWidth: string = '280px';
  @State drpDenyButtonMinWidth: string = '280px';
  @State allowMinFontSize: string = '27px';
  @State allowMaxFontSize: string = '30px';
  @State allowButtonHeight:string = '80px';
  @State denyMinFontSize: string = '27px';
  @State denyMaxFontSize: string = '30px';
  @State denyButtonHeight:string = '80px';
  @State scrollBarIndexWidth: string = '11px';
  @State scrollBarIndexHeight: string = '16px';
  @State scrollBarIndexMargin: string = '1px';
  @State scrollBarWidth: string = '12px';
  @State scrollBarHeight: string = '74px';
  @State scrollBarRadius: string = '8px';
  @State lastTouchY: number = 0;
  

  build() {
    Row(){
      Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {   
        Stack({alignContent: Alignment.TopEnd}) {
          Scroll(this.drpDevice ? this.drpScroller : this.defaultScroller) {
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
                  .fontSize(this.drpDevice ? '38px' : '36px')
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
                    .fontColor(this.europeRegion ? '#5EA1FF' : '#FFFFFF')
                    .fontWeight(500)
                    .minFontSize(this.allowMinFontSize)
                    .maxFontSize(this.allowMaxFontSize)
                    .maxLines(1)
                    .textOverflow({overflow: TextOverflow.MARQUEE})
                  }
                  .onClick(async (): Promise<void> => {
                    await this.enableNotification(true);
                  })
                  .backgroundColor(this.europeRegion ? '#405ea1ff' : '#FF1F71FF')
                  .width(this.drpDevice && this.allowPressed ? this.buttonWidth * 0.95 : this.buttonWidth)
                  .height(this.allowButtonHeight)  
                  .constraintSize({ 
                      minWidth: this.drpDevice ? this.drpAllowButtonMinWidth : '232px',
                      maxWidth: this.drpDevice ? '428px' :'362px'
                  })
                  .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                    console.info(`onSizeChange-allow, newValue=${newValue?.width}.`)
                    this.buttonWidthAllow = newValue?.width as number;
                    this.updateButtonWidth();
                  })
                  .gesture(
                    LongPressGesture({duration:200})
                      .onAction(() => {
                        this.allowPressed = true;
                        if (this.drpDevice) {
                          this.allowMinFontSize = '34px';
                          this.allowMaxFontSize = '34px';
                          this.allowButtonHeight = '76px';
                          this.drpAllowButtonMinWidth = '266px';
                        }
                      })
                      .onActionEnd(() => {
                        this.allowPressed = false;
                        if (this.drpDevice) {
                          this.allowMinFontSize = '36px';
                          this.allowMaxFontSize = '36px';
                          this.allowButtonHeight = '80px';
                          this.drpAllowButtonMinWidth = '280px';
                        }
                      })
                  )
                }
                .margin({top:16})
              }

              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Button() {
                    Text($r('app.string.BAN'))
                    .fontColor('#5EA1FF')
                    .fontWeight(500)
                    .minFontSize(this.denyMinFontSize)
                    .maxFontSize(this.denyMaxFontSize)
                    .maxLines(1)
                    .textOverflow({overflow: TextOverflow.MARQUEE})
                  }
                  .onClick(async (): Promise<void> => {
                    await this.enableNotification(false);
                  })
                  .backgroundColor('#405ea1ff')
                  .width(this.drpDevice && this.denyPressed ? this.buttonWidth * 0.95 : this.buttonWidth)
                  .height(this.denyButtonHeight)
                  .constraintSize({ 
                      minWidth: this.drpDevice ? this.drpDenyButtonMinWidth : '232px',
                      maxWidth: this.drpDevice ? '428px' :'362px'
                  })
                  .onSizeChange((oldValue: SizeOptions, newValue: SizeOptions) => {
                    console.info(TAG, `onSizeChange-deny, newValue=${newValue?.width}.`)
                    this.buttonWidthDeny = newValue?.width as number;
                    this.updateButtonWidth();
                  })
                  .gesture(
                    LongPressGesture({duration:200})
                      .onAction(() => {
                        this.denyPressed = true;
                        if (this.drpDevice) {
                          this.denyMinFontSize = '34px';
                          this.denyMaxFontSize = '34px';
                          this.denyButtonHeight = '76px';
                          this.drpDenyButtonMinWidth = '266px';
                        }
                        
                      })
                      .onActionEnd(() => {
                        this.denyPressed = false;
                        if (this.drpDevice) {
                          this.denyMinFontSize = '36px';
                          this.denyMaxFontSize = '36px';
                          this.denyButtonHeight = '80px';
                          this.drpDenyButtonMinWidth = '280px';
                        }
                      })
                  )
                }
                .margin({
                  top:12,
                  bottom:36})
              }
            }
          }
          .scrollBar(BarState.Off)

          ScrollBar({
            scroller: this.drpScroller,
            direction: ScrollBarDirection.Vertical,
            state: BarState.Auto
          }) {
            Text()
            .width(this.scrollBarIndexWidth)
            .height(this.scrollBarIndexHeight)
            .borderRadius(this.scrollBarRadius)
            .backgroundColor(Color.White)
            .focusable(false)
            .margin({
              top: 'this.scrollBarIndexMargin',
              left: 'this.scrollBarIndexMargin'
            })
          }
          .borderRadius(this.scrollBarRadius)
          .width(this.scrollBarWidth)
          .height(this.scrollBarHeight)
          .backgroundColor('#26FFFFFF')
          .backdropBlur(30)
          .margin({
            top: '84px',
            right: '4px'
          })
          .responseRegion({
            x: '-42px',
            y: '0px',
            width: '400%',
            height: '200%'
          })
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.scrollBarIndexWidth = '40px';
              this.scrollBarIndexHeight = '58px';
              this.scrollBarIndexMargin = '3px';
              this.scrollBarWidth = '48px';
              this.scrollBarHeight = '240px';
              this.scrollBarRadius = '32px';
              this.lastTouchY = event.touches[0].y;
            } else if (event.type === TouchType.Up || event.type === TouchType.Cancel) {
              this.scrollBarIndexWidth = '11px';
              this.scrollBarIndexHeight = '16px';
              this.scrollBarIndexMargin = '1px';
              this.scrollBarWidth = '12px';
              this.scrollBarHeight = '74px';
              this.scrollBarRadius = '8px';
            } else if (event.type === TouchType.Move) {
              const currentY: number = event.touches[0].y;
              const deltaY: number = currentY - this.lastTouchY;
              this.drpScroller.scrollBy(0, deltaY);
            }
          })
        } 
      }
    }
    .margin({
      top: 0,
      left: 0,
      right: 0,
      bottom: 0
    })
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
      this.europeRegion = isOvVersion() && isEuropeRegion(this.context);
      this.drpDevice = isDrp();
      if(this.drpDevice) {
        this.allowMinFontSize = '36px';
        this.allowMaxFontSize = '36px';
        this.denyMinFontSize = '36px';
        this.denyMaxFontSize = '36px';
      }
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
    if (this.buttonWidthAllow > 0 && this.buttonWidthDeny > 0) {
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