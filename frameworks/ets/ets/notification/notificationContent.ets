/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import image from '@ohos.multimedia.image';
import { Resource } from 'global.resource';
import type notificationManager from '@ohos.notificationManager';

type IconType = Resource | image.PixelMap;

class RecordTools {
  public static GetKeys(record: Record<string, NullishType>): Array<string> {
    try {
      let keys: Array<string> = Object.keys(record); 
      return keys;
    } catch (err) {
      return {};
    }
  }
}

export interface NotificationBasicContent {

    title: string;

    text: string;

    additionalText?: string;

    lockscreenPicture?: image.PixelMap;

    structuredText?: Map<string, string>;
}

class NotificationBasicContentInner implements NotificationBasicContent {

    public title: string = '';

    public text: string = '';

    public additionalText?: string | undefined;

    public lockscreenPicture?: image.PixelMap | undefined;

    public structuredText?: Map<string, string>;
}

export interface NotificationLongTextContent extends NotificationBasicContent {

    longText: string;

    briefText: string;

    expandedTitle: string;
}

class NotificationLongTextContentInner implements NotificationLongTextContent {

  public title: string = '';

  public text: string = '';

  public additionalText?: string;

  public lockscreenPicture?: image.PixelMap | undefined;

  public structuredText?: Map<string, string>;

  public longText: string = '';

  public briefText: string = '';

  public expandedTitle: string = '';
}

export enum LiveViewStatus {

    LIVE_VIEW_CREATE = 0,

    LIVE_VIEW_INCREMENTAL_UPDATE = 1,

    LIVE_VIEW_END = 2,

    LIVE_VIEW_FULL_UPDATE = 3
}

export enum LiveViewTypes {

    LIVE_VIEW_ACTIVITY = 0,

    LIVE_VIEW_INSTANT = 1,

    LIVE_VIEW_LONG_TERM = 2
}

export interface NotificationLiveViewContent extends NotificationBasicContent {

    status: LiveViewStatus;

    version?: number;

    extraInfo?: Record<string, Object>;

    pictureInfo?: Record<string, Array<image.PixelMap>>;

    isLocalUpdateOnly?: boolean;
}

class NotificationLiveViewContentInner implements NotificationLiveViewContent {

    public title: string = '';

    public text: string = '';

    public additionalText?: string | undefined;

    public lockscreenPicture?: image.PixelMap | undefined;

    public structuredText?: Map<string, string>;

    public status: LiveViewStatus = LiveViewStatus.LIVE_VIEW_CREATE;

    public version?: number | undefined;

    public extraInfo?: Record<string, Object> | undefined;

    public pictureInfo?: Record<string, Array<image.PixelMap>> | undefined;

    public isLocalUpdateOnly?: boolean | undefined;
}

export interface NotificationMultiLineContent extends NotificationBasicContent {

    briefText: string;

    longTitle: string;

    lines: Array<string>;
}

class NotificationMultiLineContentInner implements NotificationMultiLineContent {

    public title: string = '';

    public text: string = '';

    public additionalText?: string | undefined;

    public lockscreenPicture?: image.PixelMap | undefined;

    public structuredText?: Map<string, string>;

    public briefText: string = '';

    public longTitle: string = '';

    public lines: Array<string> = {};
}

export interface NotificationPictureContent extends NotificationBasicContent {

    briefText: string;

    expandedTitle: string;

    picture: image.PixelMap;
}

class NotificationPictureContentInner implements NotificationPictureContent {
    private CreatePixelMap() : image.PixelMap {
      let opts: image.InitializationOptions = { size: { height: 4, width: 6 } }
      return image.createPixelMapSync(opts);
    }

    public title: string = '';

    public text: string = '';

    public additionalText?: string | undefined;

    public lockscreenPicture?: image.PixelMap | undefined;

    public structuredText?: Map<string, string>;

    public briefText: string = '';

    public expandedTitle: string = '';

    public picture: image.PixelMap = this.CreatePixelMap();
}

export interface NotificationSystemLiveViewContent extends NotificationBasicContent {

    typeCode: number;

    capsule?: NotificationCapsule;

    button?: NotificationButton;

    cardButtons?: Array<NotificationIconButton>;

    time?: NotificationTime;

    progress?: NotificationProgress;

    liveViewType?: LiveViewTypes;
}

class NotificationSystemLiveViewContentInner implements NotificationSystemLiveViewContent {
    private CreatePixelMap() : image.PixelMap {
      let opts: image.InitializationOptions = { size: { height: 4, width: 6 } }
      return image.createPixelMapSync(opts);
    }

    public title: string = '';

    public text: string = '';

    public additionalText?: string | undefined;

    public lockscreenPicture?: image.PixelMap | undefined;

    public structuredText?: Map<string, string>;

    public briefText: string = '';

    public expandedTitle: string = '';

    public picture: image.PixelMap = this.CreatePixelMap();

    public typeCode: number = 0;

    public capsule?: NotificationCapsule | undefined;

    public button?: NotificationButton | undefined;

    public cardButtons?: Array<NotificationIconButton> | undefined;

    public time?: NotificationTime | undefined;

    public progress?: NotificationProgress | undefined;

    public liveViewType?: LiveViewTypes | undefined;
}

export interface NotificationCapsule {

    title?: string;

    icon?: image.PixelMap;

    backgroundColor?: string;

    content?: string;

    time?: number;

    capsuleButtons?: Array<NotificationIconButton>;
}

class NotificationCapsuleInner implements NotificationCapsule {

    public title?: string | undefined;

    public icon?: image.PixelMap | undefined;

    public backgroundColor?: string | undefined;

    public content?: string | undefined;

    public time?: number | undefined;

    public capsuleButtons?: Array<NotificationIconButton> | undefined;
}

export interface NotificationIconButton {

    name: string;

    iconResource: IconType;

    text?: string;

    hidePanel?: boolean;
}

class NotificationIconButtonInner implements NotificationIconButton {

    private CreatePixelMap() : image.PixelMap {
      let opts: image.InitializationOptions = { size: { height: 4, width: 4 } }
      return image.createPixelMapSync(opts);
    }

    public name: string = '';

    public iconResource: IconType = this.CreatePixelMap();

    public text?: string | undefined;

    public hidePanel?: boolean | undefined;
}

export interface NotificationButton {

    names?: Array<string>;

    icons?: Array<image.PixelMap>;

    iconsResource?: Array<Resource>;
}

class NotificationButtonInner implements NotificationButton {

    public names?: Array<string> | undefined;

    public icons?: Array<image.PixelMap> | undefined;

    public iconsResource?: Array<Resource> | undefined;
}

export interface NotificationTime {

    initialTime?: number;

    isCountDown?: boolean;

    isPaused?: boolean;

    isInTitle?: boolean;
}

class NotificationTimeInner implements NotificationTime {

    public initialTime?: number | undefined;

    public isCountDown?: boolean | undefined;

    public isPaused?: boolean | undefined;

    public isInTitle?: boolean | undefined;
}

export interface NotificationProgress {

    maxValue?: number;

    currentValue?: number;

    isPercentage?: boolean;
}

class NotificationProgressInner implements NotificationProgress {

    public maxValue?: number | undefined;

    public currentValue?: number | undefined;

    public isPercentage?: boolean | undefined;
}

export interface NotificationContent {

    notificationContentType?: notificationManager.ContentType;

    normal?: NotificationBasicContent;

    longText?: NotificationLongTextContent;

    multiLine?: NotificationMultiLineContent;

    picture?: NotificationPictureContent;

    systemLiveView?: NotificationSystemLiveViewContent;

    liveView?: NotificationLiveViewContent;
}

class NotificationContentInner implements NotificationContent {

    public notificationContentType?: notificationManager.ContentType | undefined;

    public normal?: NotificationBasicContent | undefined;

    public longText?: NotificationLongTextContent | undefined;

    public multiLine?: NotificationMultiLineContent | undefined;

    public picture?: NotificationPictureContent | undefined;

    public systemLiveView?: NotificationSystemLiveViewContent | undefined;

    public liveView?: NotificationLiveViewContent | undefined;
}