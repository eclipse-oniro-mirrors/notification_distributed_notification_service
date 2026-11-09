/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { DialogScrollType } from './DialogScrollViewModel';

@Observed
export class DialogScrollState {
  // Real height of the dialog
  public dialogRealHeight: number = 0;
  // Height of the title area, including the icon and the title
  public titleAreaHeight: number = 0;
  // Height of the content area, including the permission usage reason
  public contentAreaHeight: number = 0;
  // Height of the button area
  public buttonHeight: number = 0;
  // Scroll type of the dialog
  public dialogScrollType: DialogScrollType = DialogScrollType.NONE;
}
