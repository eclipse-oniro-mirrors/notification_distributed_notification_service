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

export default class Constants {
    // grid useSizeType
    static GUTTER = 0;
    static XS_COLUMNS = 2;
    static XS_SPAN = 2;
    static XS_OFFSET = 0;
    static SM_COLUMNS = 4;
    static SM_SPAN = 4;
    static SM_OFFSET = 0;
    static MD_COLUMNS = 8;
    static MD_SPAN = 8;
    static MD_OFFSET = 0;
    static LG_COLUMNS = 12;
    static LG_SPAN = 8;
    static LG_OFFSET = 2;

    static DIALOG_GUTTER = 16;
    static DIALOG_MARGIN = 16;
    static DIALOG_MARGIN_VERTICAL = 12;
    static DIALOG_MD_SPAN = 4;
    static DIALOG_MD_OFFSET = 2;
    static DIALOG_LG_SPAN = 4;
    static DIALOG_LG_OFFSET = 4;

    // 100% width,height
    static FULL_WIDTH = '100%';
    static FULL_HEIGHT = '100%';

    // public property style
    static PERMISSION = 1;
    static APPLICATION = 0;
    static LAYOUT_WEIGHT = 1;
    static FLEX_GROW = 1;
    static TEXT_BIG_FONT_SIZE = 20;
    static TEXT_MIDDLE_FONT_SIZE = 16;
    static TEXT_SMALL_FONT_SIZE = 14;
    static TEXT_SMALLER_FONT_SIZE = 12;
    static TEXT_LINE_HEIGHT = 22;
    static TEXT_BIG_LINE_HEIGHT = 28;
    static TEXT_SMALL_LINE_HEIGHT = 19;
    static CONSTRAINTSIZE_MINHEIGHT = 48;
    static LISTITEM_ROW_HEIGHT = 48;
    static LISTITEM_PADDING_LEFT = 24;
    static LIST_PADDING_LEFT = 12
    static LISTITEM_PADDING_RIGHT = 24;
    static LISTITEM_PADDING_LEFT_RECORD = 32;
    static LISTITEM_PADDING_RIGHT_RECORD = 50;
    static LISTITEM_MARGIN_BOTTOM = 12;
    static LISTITEM_HEIGHT_PERMISSION = 64;
    static LISTITEM_HEIGHT_APPLICATION = 72;
    static IMAGE_HEIGHT = 24;
    static IMAGE_WIDTH = 12;
    static IMAGE_HEIGHT_RECORD = 12;
    static IMAGE_WIDTH_RECORD = 24;
    static IMAGE_HEIGHT_RECORD_APPLICATION = 16;
    static IMAGE_WIDTH_RECORD_APPLICATION = 16;
    static TITLE_MARGIN_BOTTOM = 16;
    static SUBTITLE_MIN_HEIGHT = 48;
    static SUBTITLE_LINE_HEIGHT = 24;
    static SUBTITLE_PADDING_TOP = 16;
    static SUBTITLE_PADDING_BOTTOM = 8;
    static TAB_HEIGHT = 56;
    static TAB_LINE_HEIGHT = 100;
    static TAB_INNER_PADDING = 8;
    static TAB_DECORATION_HEIGHT = 2;
    static TAB_DECORATION_POSITION_Y = 6;
    static DEFAULT_PADDING_START = 12;
    static DEFAULT_PADDING_END = 12;
    static DEFAULT_PADDING_TOP = 12;
    static DEFAULT_PADDING_BOTTOM = 12;
    static DEFAULT_MARGIN_START = 12;
    static DEFAULT_MARGIN_END = 12;
    static DEFAULT_MARGIN_TOP = 12;
    static DEFAULT_MARGIN_BOTTOM = 12;
    static DEFAULT_SLIDER_WIDTH = 60;
    static DEFAULT_SLIDER_HEIGHT = 40;
    static OFFSET = 100;
    static CLICK_SHADOW_LENGTH = 48;
    static DIVIDER = '1px';
    static DIVIDER_HEIGHT = 24;
    static DIVIDER_MARGIN_RIGHT_PERMISSION = 52;
    static DIVIDER_MARGIN_RIGHT_APPLICATION = 68;

    static START_SUBSCRIPT = 0;
    static END_SUBSCRIPT = 500;
    static MAXIMUM_HEADER_LINES = 1;
    static MAXIMUM_HEADER_WIDTH = 200;
    static MAXIMUM_HEADER_HEIGHT = 500;
    static MAXIMUM_HEADER_LENGTH = 1000;

    static RECORD_PADDING_BOTTOM = '20%';

    // icon of dialog
    static DIALOG_ICON_WIDTH = 24;
    static DIALOG_ICON_HEIGHT = 24;
    static DIALOG_ICON_MARGIN_TOP = 23;

    // label text of dialog
    static DIALOG_LABEL_FONT_SIZE = 10;
    static DIALOG_LABEL_MARGIN_TOP = 2;
    static DIALOG_LABEL_LINE_HEIGHT = 14;

    // request text of dialog
    static DIALOG_REQ_FONT_SIZE = 16;
    static DIALOG_REQ_MARGIN_TOP = 16;
    static DIALOG_REQ_MARGIN_LEFT = 24;
    static DIALOG_REQ_MARGIN_RIGHT = 24;
    static DIALOG_REQ_LINE_HEIGHT = 22;

    // description text of dialog
    static DIALOG_DESP_FONT_SIZE = 14;
    static DIALOG_DESP_MARGIN_TOP = 2;
    static DIALOG_DESP_MARGIN_LEFT = 24;
    static DIALOG_DESP_MARGIN_RIGHT = 24;
    static DIALOG_DESP_MARGIN_BOTTOM = 8;
    static DIALOG_DESP_LINE_HEIGHT = 19;

    static BUTTON_MARGIN_TOP = 8;
    static BUTTON_MARGIN_LEFT = 16;
    static BUTTON_MARGIN_RIGHT = 16;
    static BUTTON_HEIGHT = 40;

    static DIALOG_PRIVACY_BORDER_RADIUS = 32;
    static DIALOG_PADDING_BOTTOM = 16;

    // ccm config path
    static CCM_CONFIG_PATH = "etc/notification/notification_config.json";
}
