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
  @State private want: any = undefined
  @State private uid: any = undefined
  @State private style: any = {}
  @State token_: any = undefined
  @State popWidth: any = undefined
  @State popHeight: any = undefined
  @State bundleName: any = undefined
  controller: CustomDialogController
  private TAG = "[NotificationDialog_Service]"

  build() {
    Flex({direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center}) {
      Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
        Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
          Text($r("app.string.if_allow_to_publish_notification"))
            .width("350vp")
            .height("22vp")
            .margin({ top: 32 })
            .fontSize(21)
            .fontColor("#182431")
            .fontWeight(400)
            .opacity(1)
            .textAlign(TextAlign.Center)
        }

        Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center }) {
          Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center }) {
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
            .margin({ top: "9vp", right: "8vp", bottom: "9vp", left: "8vp" })
            .backgroundColor("#FFFFFF")
          }
          .margin({ top: 15, right: 5, bottom: 8, left: 8 })

          Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center }) {
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
            .margin({ top: "9vp", right: "8vp", bottom: "9vp", left: "8vp" })
            .backgroundColor("#FFFFFF")
          }
          .margin({ top: 15, right: 8, bottom: 8, left: 5 })
        }
      }
      .width(px2vp(globalThis.width))
      .height(px2vp(globalThis.height))
      .borderRadius(32)
      .backgroundColor("#FFFFFF")
    }
    .width("100%")
    .height("100%")
  }

  async privacyChose(flag) {
    let enable = flag;
    let bundleOption = {
      bundle: globalThis.bundleName
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
    this.want = globalThis.abilityWant
    this.style = globalThis.style
    this.token_ = globalThis.abilityWant.parameters['tokenId'].value
    globalThis.bundleName = globalThis.abilityWant.parameters['from']
  }
}