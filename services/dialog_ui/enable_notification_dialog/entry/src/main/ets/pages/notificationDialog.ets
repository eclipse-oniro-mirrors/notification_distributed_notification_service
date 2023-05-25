/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import notification from '@ohos.notification'
import rpc from '@ohos.rpc';
import mediaquery from '@ohos.mediaquery'
import deviceInfo from '@ohos.deviceInfo';
import emitter from '@ohos.events.emitter'
import { NotificationDialogBody } from '../pages/notifybody'

class Proxy extends rpc.RemoteProxy {
}

@Entry
@Component
struct NotificationDialog {
  controller: CustomDialogController
  private TAG = "[NotificationDialog_Service]"
  listener = mediaquery.matchMediaSync('(orientation: landscape)')
  @State isLand: boolean = false
  onLand = (mediaQueryResult) => {
    if (mediaQueryResult.matches) {
      this.isLand = true
    } else {
      this.isLand = false
    }
  }

  build() {
    if (this.isLand || !(deviceInfo.deviceType == 'default' || deviceInfo.deviceType == 'phone')) {
      //horizontal
      Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
        NotificationDialogBody()
      }
      .width("100%")
      .height("100%")
    } else {
      //vertical
      Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.End }) {
        NotificationDialogBody()
      }
      .width("100%")
      .height("100%")
      .padding({bottom: 48})
    }
  }

  async privacyChose(flag) {
    console.info("NotificationDialog privacyChose: " + flag)
    let enable = flag;
    let bundleOption = {
      bundle: globalThis.abilityWant.parameters['from']
    }
    console.info("NotificationDialog before enableNotification")
    await notification.enableNotification(bundleOption, enable, (err) => {
      if (err.code) {
        console.error('Start enableNotification failed. ErrCode: ' + JSON.stringify(err.code));
        return
      }
    })
    globalThis.closeDialog()
  }

  aboutToAppear() {
    console.log(this.TAG, "dialog page appears")
    this.listener.on('change', this.onLand)

    var innerEvent = {
      eventId: 99
    };
    var callback = (eventData) => {
      console.info('NotificationDialog callback:' + JSON.stringify(eventData));
      if (eventData) {
        this.privacyChose(eventData.data.agree)
      }
    };
    emitter.on(innerEvent, callback);
  }
}