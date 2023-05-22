/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

class Proxy extends rpc.RemoteProxy {
}

@Entry
@Component
struct NotificationDialog {
  controller: CustomDialogController
  private TAG = "[NotificationDialog_Service]"

  build() {
    Flex({direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center}) {
      Column() {
        Text($r("app.string.if_allow_to_publish_notification"))
          .width("350vp")
          .fontSize(21)
          .fontColor("#182431")
          .fontWeight(400)
          .opacity(1)
          .maxLines(2)
          .textAlign(TextAlign.Center)
          .margin({ bottom: 8 })


        Row() {
          Button() {
            Row() {
              Text($r("app.string.ban"))
                .textAlign(TextAlign.Center)
                .fontSize("22fp")
                .fontWeight(500)
                .fontColor("#0D81F2")
            }
          }
          .onClick(() => {
            let popFlag = false
            this.privacyChose(popFlag)
            console.info("after privacyChose")
          })
          .width("116vp")
          .height("40vp")
          .margin({
            top: "9vp",
            right: "8vp",
            bottom: "9vp"
          })
          .backgroundColor("#FFFFFF")

          Text()
            .backgroundColor('#e1e1e1')
            .height('22fp')
            .width('1px')

          Button() {
            Row() {
              Text($r("app.string.allow"))
                .textAlign(TextAlign.Center)
                .fontSize("22fp")
                .fontWeight(500)
                .fontColor("#0D81F2")
            }
          }
          .onClick(() => {
            let popFlag = true
            this.privacyChose(popFlag)
            console.info("after privacyChose")
          })
          .width("116vp")
          .height("40vp")
          .margin({ top: "9vp", bottom: "9vp", left: "8vp" })
          .backgroundColor("#FFFFFF")
        }
        .height(56)
      }
      .borderRadius(24)
      .alignItems(HorizontalAlign.Center)
      .backgroundColor("#FFFFFF")
      .padding({left:24, top:24, right:24})
    }
    .width("100%")
    .height("100%")
  }

  async privacyChose(flag) {
    let enable = flag;
    let bundleOption = {
      bundle: globalThis.abilityWant.parameters['from']
    }
    console.info("before enableNotification")
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
  }
}