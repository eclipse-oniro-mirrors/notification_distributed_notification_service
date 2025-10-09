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

import Constants from './constant';
import { MeasureOptions } from '@ohos.measure';
import { MeasureUtils } from '@ohos.arkui.UIContext';
import common from '@ohos.app.ability.common';
import uiextension from '@ohos.arkui.uiExtension';
import window from '@ohos.window';
import display from '@ohos.display';

const TAG = 'NotificationDialog_Service ';
const DEFAULT_DISPLAY_ID: number = 0;

/**
 * Omit display when application name is too long
 * @param {String} Application name
 */
export function titleTrim(title: string): string {
  let length = title.length;
  if (length > Constants.MAXIMUM_HEADER_LENGTH) {
    let str = '';
    str = title.substring(0, Constants.MAXIMUM_HEADER_LENGTH) + '...';
    return str;
  } else {
    return title;
  }
}

export function calOverLine(containerWidth: number, options: MeasureOptions,
  measureUtils: MeasureUtils) : boolean {
    let crossLineFlag: boolean = false;
    try {
      let textWidth = px2vp(measureUtils.measureText(options));
      crossLineFlag = (textWidth > containerWidth);
    } catch (err) {
      console.error(TAG, `cal over line failed, code=${err?.code0}, msg=${err?.message}.`);
    }
    return crossLineFlag;
  }

export function calContainerWidth(
  containerWidth: number,
  options: MeasureOptions,
  crossLineRatio: number,
  measureUtils: MeasureUtils) : string | number {
    let targetContainerWidth: string | number = 'auto';
    try {
      let textWidth = px2vp(measureUtils.measureText(options));
      let ratio = (textWidth % containerWidth) / containerWidth;
      let crossLineFlag: boolean = (textWidth > containerWidth) && (textWidth < 2 * containerWidth);
      if (crossLineFlag && ratio < crossLineRatio) {
        targetContainerWidth = containerWidth / Constants.CROSS_LINE_RESIZE_PARAM;
        console.info(TAG, 'afford condition, cal new width.');
      }
    } catch (err) {
      console.error(TAG, `refresh width failed, code=${err?.code0}, msg=${err?.message}.`);
    }
    return targetContainerWidth;
  }

export function getFontSizeScale(context: common.UIAbilityContext, maxScale: number = 3.2): number {
  let fontSizeScale = context.config?.fontSizeScale;
  console.log(TAG, `fontSizeScale = ${fontSizeScale}`);
  if(fontSizeScale === undefined) {
    return Constants.FONT_SCALE_DEFAULT;
  }
  return fontSizeScale > maxScale ? maxScale : fontSizeScale;
}

export function sourceToVp(source: Resource): number {
  return px2vp(getContext().resourceManager.getNumber(source.id));
}

export function getLimitFontSize(fontSizeScale: number, sourceFontSize: number): string {
  return `${sourceFontSize * fontSizeScale}vp`;
}

export function shouldMoveToDisplayCenter(comW: number, comH: number,
  windowPoxy: uiExtension.WindowProxy,
  win: window.Window, dis: display.Display): boolean {
  try {
    if (windowPoxy === undefined) {
      console.error(TAG, `windowPoxy is null`);
      return false;
    }
    let windowRect = windowPoxy.properties?.uiExtensionHostWindowProxyRect;
    if (windowRect === undefined) {
      console.error(TAG, `windowRect is null`);
      return false;
    }
    if (win === undefined) {
      console.error(TAG, `window is null`);
      return false;
    }
    if (dis === undefined) {
      console.error(TAG, `display is null`);
      return false;
    }
    
    console.info(TAG, `display W=${dis.width}, H=${dis.height} avaliableH=${dis.availableHeight}`);
    console.info(TAG, `compoment W=${comW}, H=${comH}`);
    console.info(TAG, `windowRect L=${windowRect.left} T=${windowRect.top} W=${windowRect.width} H=${windowRect.height}`);

    let leftMargin = (windowRect.width - comW) /2;
    let topMargin = (windowRect.height - comH) /2;
    let leftTopXPos = windowRect.left + leftMargin;
    let leftTopYPos = windowRect.top + topMargin;
    let rightBottomXPos = leftTopXPos + comW;
    let rightBottomYPos = leftTopYPos + comH;
    console.info(TAG, `comPos info LTX=${leftTopXPos} LTY=${leftTopYPos} RBX=${rightBottomXPos} RBY=${rightBottomYPos}`);

    if (leftTopXPos < 0 || rightBottomXPos > dis.width || leftTopYPos < 0) {
      return true;
    }

    let displayId = win.getWindowProperties().displayId;
    let foldStatus = display.getFoldStatus();
    let disPlayValidHeight = 0;
    let chargeCrossAxis = false;
    if (foldStatus === display.FoldStatus.FOLD_STATUS_EXPANDED) {
      disPlayValidHeight = dis.height - Constants.PC_DOCK_HEIGHT; 
    } else {
      disPlayValidHeight = (dis.availableHeight !== undefined && dis.availableHeight <= dis.height) ?
        dis.availableHeight : dis.height;
      if (displayId === DEFAULT_DISPLAY_ID) {
        chargeCrossAxis = true;
      }
    }

    if (chargeCrossAxis) {
      if (disPlayValidHeight > leftTopYPos && disPlayValidHeight < rightBottomYPos) {
          return true;
        }
    } else {
      if (rightBottomYPos > disPlayValidHeight) {
          return true;
      }
    }
  } catch (err) {
    console.error(TAG, `shouldMoveToDisplayCenter failed, code=${err?.code}, msg=${err?.message}.`);
  }
  return false;
}
