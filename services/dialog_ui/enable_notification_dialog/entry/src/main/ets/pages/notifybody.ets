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

import emitter from '@ohos.events.emitter'

@Component
export struct NotificationDialogBody {

  build() {
        Column() {
          Text($r('app.string.if_allow_to_publish_notification'))
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
                Text($r('app.string.ban'))
                  .textAlign(TextAlign.Center)
                  .fontSize("22fp")
                  .fontWeight(500)
                  .fontColor("#0D81F2")
              }
            }
            .onClick(() => {
              var eventData = {
                data: {
                  "agree": false,
                }};
              var innerEvent = {
                eventId: 99,
                priority: emitter.EventPriority.HIGH
              };
              emitter.emit(innerEvent, eventData);
              console.info("after privacyChose")
            })
            .width("116vp")
            .height("40vp")
            .margin({ top: "9vp", bottom: "9vp", left: "8vp" })
            .backgroundColor("#FFFFFF")

            Text()
              .backgroundColor('#e1e1e1')
              .height('22fp')
              .width('1px')

            Button() {
              Row() {
                Text($r('app.string.allow'))
                  .textAlign(TextAlign.Center)
                  .fontSize("22fp")
                  .fontWeight(500)
                  .fontColor("#0D81F2")
              }
            }
            .onClick(() => {
              console.info("after privacyChose")
              var eventData = {
                data: {
                  "agree": true,
                }};
              var innerEvent = {
                eventId: 99,
                priority: emitter.EventPriority.HIGH
              };
              emitter.emit(innerEvent, eventData);
            })
            .width("116vp")
            .height("40vp")
            .margin({ top: "9vp", right: "8vp", bottom: "9vp" })
            .backgroundColor("#FFFFFF")
          }
          .height(56)
        }
        .width('80%')
        .borderRadius(24)
        .alignItems(HorizontalAlign.Center)
        .backgroundColor("#FFFFFF")
        .borderColor('#e1e1e1')
        .borderWidth('1px')
        .padding({left:24, top:24, right:24})
  }
  aboutToAppear(): void {
  }
}