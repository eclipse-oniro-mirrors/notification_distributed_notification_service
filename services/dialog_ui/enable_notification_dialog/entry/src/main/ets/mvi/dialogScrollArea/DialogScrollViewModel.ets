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

import Constants from '../../common/constant';
import { DialogArea, DialogHeightChangeEvent } from './DialogScrollEvent';
import { DialogScrollState } from './DialogScrollState';

const TAG = 'NotificationDialog_Service ';

export enum DialogScrollType {
  // The whole dialog scrolls
  ALL_SCROLL = 'allScroll',
  // The title and the content scroll together
  TITLE_CONTENT_SCROLL = 'titleContentScroll',
  // Only the content area scrolls
  CONTENT_SCROLL = 'contentScroll',
  // No scrolling
  NONE = 'none'
}

export class DialogScrollViewModel {
  private _viewState?: DialogScrollState;

  public getViewState(): DialogScrollState {
    if (this._viewState == null || this._viewState === undefined) {
      this._viewState = new DialogScrollState();
    }
    return this._viewState;
  }

  public processEvent(event: DialogHeightChangeEvent): void {
    switch (event.area) {
      case DialogArea.DIALOG:
        this.dialogRealHeightChange(event.height);
        break;
      case DialogArea.TITLE:
        this.titleAreaHeightChange(event.height);
        break;
      case DialogArea.CONTENT:
        this.contentAreaHeightChange(event.height);
        break;
      case DialogArea.BUTTON:
        this.buttonHeightChange(event.height);
        break;
      default:
        break;
    }
  }

  // Set when the dialog real height arrives before the title, button and content heights.
  // The scroll type must then be recalculated once those heights are updated.
  private needChangeScrollType: boolean = false;

  // Sum of the real heights of all dialog parts: title area + content area + button area
  private getAllHeight(viewState: DialogScrollState) {
    return viewState.titleAreaHeight + viewState.contentAreaHeight + viewState.buttonHeight;
  }

  /**
   * 1: No scrolling when the dialog height is greater than or equal to title + content + button.
   * 2: When the dialog height is less than button + 100vp, the title and content scroll area is
   *    shorter than 100vp, so the whole dialog scrolls.
   * 3: When the dialog height is less than title + button + 100vp, the content scroll area is
   *    shorter than 100vp, so the button stays fixed and the title scrolls together with the content.
   * 4: When the dialog height is less than title + content + button, the title and button stay
   *    fixed and only the content scrolls.
   * */
  private setDialogScrollType(viewState: DialogScrollState) {
    const allHeight = this.getAllHeight(viewState);
    console.info(TAG, `allHeight=${allHeight}`);
    const dialogRealHeight = viewState.dialogRealHeight + Constants.MINIMUM_PRECISION;
    if (dialogRealHeight >= allHeight) {
      viewState.dialogScrollType = DialogScrollType.NONE;
    } else if (dialogRealHeight < viewState.buttonHeight + Constants.MIN_SCROLL_AREA_HEIGHT) {
      viewState.dialogScrollType = DialogScrollType.ALL_SCROLL;
    } else if (dialogRealHeight <
      viewState.buttonHeight + viewState.titleAreaHeight + Constants.MIN_SCROLL_AREA_HEIGHT) {
      viewState.dialogScrollType = DialogScrollType.TITLE_CONTENT_SCROLL;
    } else {
      viewState.dialogScrollType = DialogScrollType.CONTENT_SCROLL;
    }
    console.info(TAG, `scrollType=${viewState.dialogScrollType}, th=${viewState.titleAreaHeight}, ` +
      `ch=${viewState.contentAreaHeight}, bh=${viewState.buttonHeight}, dh=${viewState.dialogRealHeight}`);
  }

  /**
   * 1: Triggered after the dialog real height changes.
   * 2: The scroll type must be recalculated afterwards.
   * */
  private dialogRealHeightChangeHandler(viewState: DialogScrollState) {
    // Wait until every area has been laid out and has a real height
    if (viewState.titleAreaHeight === 0 || viewState.contentAreaHeight === 0 || viewState.buttonHeight === 0 ||
      viewState.dialogRealHeight === 0) {
      return;
    }
    this.setDialogScrollType(viewState);
  }

  /**
   * Check whether all areas have been laid out
   * */
  private checkAreaChangeComplete(viewState: DialogScrollState) {
    return viewState.titleAreaHeight !== 0 &&
      viewState.contentAreaHeight !== 0 &&
      viewState.buttonHeight !== 0 &&
      viewState.dialogRealHeight !== 0;
  }

  /**
   * 1: When the dialog real height arrives before the title, button and content heights,
   *    recalculate the scroll type once all of them are available.
   * */
  private areaChangeHandler(viewState: DialogScrollState) {
    if (this.needChangeScrollType) {
      if (this.checkAreaChangeComplete(viewState)) {
        console.info(TAG, `area change and set scroll type`);
        this.dialogRealHeightChangeHandler(viewState);
        this.needChangeScrollType = false;
      }
    }
  }

  private dialogRealHeightChange(height: number) {
    const viewState = this.getViewState();
    console.info(TAG, `dialog real height = ${height}`);
    viewState.dialogRealHeight = height;
    if (this.checkAreaChangeComplete(viewState)) {
      console.info(TAG, `dialog real height change and set scroll type`);
      this.dialogRealHeightChangeHandler(viewState);
    } else {
      this.needChangeScrollType = true;
    }
  }

  private contentAreaHeightChange(height: number) {
    const viewState = this.getViewState();
    if (height === viewState.contentAreaHeight) {
      return;
    }
    console.info(TAG, `content area height = ${height}`);
    viewState.contentAreaHeight = height;
    this.areaChangeHandler(viewState);
  }

  private titleAreaHeightChange(height: number) {
    const viewState = this.getViewState();
    if (height === viewState.titleAreaHeight) {
      return;
    }
    console.info(TAG, `title area height = ${height}`);
    viewState.titleAreaHeight = height;
    this.areaChangeHandler(viewState);
  }

  private buttonHeightChange(height: number) {
    const viewState = this.getViewState();
    if (height === viewState.buttonHeight) {
      return;
    }
    console.info(TAG, `button height = ${height}`);
    viewState.buttonHeight = height;
    this.needChangeScrollType = true;
    this.areaChangeHandler(viewState);
  }
}
