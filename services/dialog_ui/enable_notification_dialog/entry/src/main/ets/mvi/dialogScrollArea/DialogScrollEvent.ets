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

// The dialog area whose height changed
export enum DialogArea {
  DIALOG = 'dialog',
  TITLE = 'title',
  CONTENT = 'content',
  BUTTON = 'button'
}

// Height change event of a dialog area, dispatched by onAreaChange
// and processed by DialogScrollViewModel to determine the dialog scroll type.
export class DialogHeightChangeEvent {
  public readonly area: DialogArea;
  public readonly height: number;

  constructor(area: DialogArea, height: number) {
    this.area = area;
    this.height = height;
  }
}
