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

import rpc from '@ohos.rpc';
import mediaquery from '@ohos.mediaquery'
import deviceInfo from '@ohos.deviceInfo';
import { NotificationDialogBody } from '../pages/notifybody'

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
    if (this.isLand || deviceInfo.deviceType !== 'default') {
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
}