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

import { BundleOption } from 'notification.NotificationCommonDef';
import { BusinessError, AsyncCallback, RecordData } from '@ohos.base';
import { NotificationSlot } from 'notification.notificationSlot';
import { NotificationRequest, NotificationCheckRequest } from 'notification.notificationRequest';
import UIAbilityContext from 'application.UIAbilityContext';
import { NotificationBasicContent } from 'notification.notificationContent';
import { NotificationLongTextContent } from 'notification.notificationContent';
import { NotificationMultiLineContent } from 'notification.notificationContent';
import { NotificationPictureContent } from 'notification.notificationContent';
import { NotificationSystemLiveViewContent } from 'notification.notificationContent';
import { NotificationContent } from 'notification.notificationContent';
import { NotificationTemplate } from 'notification.notificationTemplate';
import { DistributedOptions } from 'notification.notificationRequest';
import { NotificationLiveViewContent } from 'notification.notificationContent';
import { UnifiedGroupInfo } from 'notification.notificationRequest';
import { NotificationFilter } from 'notification.notificationRequest';
import image from '@ohos.multimedia.image';

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Error) => void;
type CallbackForCheckInfo =
    (checkInfo: notificationManager.NotificationCheckInfo)=> notificationManager.NotificationCheckResult;
type CallbackForBadgeQuery = (bundle: BundleOption) => Promise<long>;

const ERROR_OK = 0;
const ERROR_PARAM_INVALID = 401;
const ERROR_INTERNAL_ERROR = 160001;
const MAX_USER_ID = 10736;

const rejectInternalError: BusinessError<string> = {code: ERROR_INTERNAL_ERROR, data: "Internal error."};
const callbackInternalError: BusinessError = {code: ERROR_INTERNAL_ERROR, data: undefined};
const successCallbackError: BusinessError = {code: ERROR_OK, data: undefined};

const errorParamInvalid: BusinessError = {code: ERROR_PARAM_INVALID, message: "Invalid parameter"};

export default namespace notificationManager {
    loadLibraryWithPermissionCheck("notification_manager_ani.z", "@ohos.notificationManager")
    export enum SlotType {
        UNKNOWN_TYPE = 0,
        SOCIAL_COMMUNICATION = 1,
        SERVICE_INFORMATION = 2,
        CONTENT_INFORMATION = 3,
        LIVE_VIEW = 4,
        CUSTOMER_SERVICE = 5,
        EMERGENCY_INFORMATION = 10,
        OTHER_TYPES = 0xFFFF,
    }

    export enum ContentType {
        NOTIFICATION_CONTENT_BASIC_TEXT,
        NOTIFICATION_CONTENT_LONG_TEXT,
        NOTIFICATION_CONTENT_PICTURE,
        NOTIFICATION_CONTENT_CONVERSATION,
        NOTIFICATION_CONTENT_MULTILINE,
        NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW,
        NOTIFICATION_CONTENT_LIVE_VIEW,
    }

    export enum SlotLevel {
        LEVEL_NONE = 0,
        LEVEL_MIN = 1,
        LEVEL_LOW = 2,
        LEVEL_DEFAULT = 3,
        LEVEL_HIGH = 4,
    }

    export enum DoNotDisturbType {
        TYPE_NONE = 0,
        TYPE_ONCE = 1,
        TYPE_DAILY = 2,
        TYPE_CLEARLY = 3,
    }

    export interface DoNotDisturbDate {
        type: DoNotDisturbType;
        begin: Date;
        end: Date;
    }

    class DoNotDisturbDateInner implements DoNotDisturbDate {
        type: DoNotDisturbType;
        begin: Date;
        end: Date;
    }

    export interface NotificationSetting {
        vibrationEnabled: boolean;
        soundEnabled: boolean;
    }

    class NotificationSettingInner implements NotificationSetting {
        vibrationEnabled: boolean = false;
        soundEnabled: boolean = false;
    }

    export interface DoNotDisturbProfile {
        id: long;
        name: string;
        trustlist?: Array<BundleOption>;
    }

    class DoNotDisturbProfileInner implements DoNotDisturbProfile {
        id: long = -1;
        name: string = "";
        trustlist?: Array<BundleOption> = new Array<BundleOption>();
    }

    export interface ButtonOptions {
        buttonName: string;
    }

    class ButtonOptionsInner implements ButtonOptions {
        buttonName: string = "";
    }

    export interface SystemLiveViewSubscriber {
        onResponse?: (notificationId: int, buttonOptions: ButtonOptions) => void;
    }

    class SystemLiveViewSubscriberInner implements SystemLiveViewSubscriber {
        onResponse?: (notificationId: int, buttonOptions: ButtonOptions) => void;
    }

    export enum DeviceRemindType {
        IDLE_DONOT_REMIND = 0,
        IDLE_REMIND = 1,
        ACTIVE_DONOT_REMIND = 2,
        ACTIVE_REMIND = 3,
    }

    export enum SourceType {
        TYPE_NORMAL = 0,
        TYPE_CONTINUOUS = 1,
        TYPE_TIMER = 2
    }

    export enum RingtoneType {
        RINGTONE_TYPE_SYSTEM = 0,
        RINGTONE_TYPE_LOCAL = 1,
        RINGTONE_TYPE_ONLINE = 2,
        RINGTONE_TYPE_NONE = 3
    }

    export enum PriorityNotificationType {
        OTHER = 'OTHER',
        PRIMARY_CONTACT = 'PRIMARY_CONTACT',
        AT_ME = 'AT_ME',
        URGENT_MESSAGE = 'URGENT_MESSAGE',
        SCHEDULE_REMINDER = 'SCHEDULE_REMINDER',
        PAYMENT_DUE = 'PAYMENT_DUE',
        TRANSACTION_ALERT = 'TRANSACTION_ALERT',
        EXPRESS_PROGRESS = 'EXPRESS_PROGRESS',
        MISS_CALL = 'MISS_CALL',
        TRAVEL_ALERT = 'TRAVEL_ALERT',
        ACCOUNT_ALERT = 'ACCOUNT_ALERT',
        APPOINTMENT_REMINDER = 'APPOINTMENT_REMINDER',
        TRAFFIC_NOTICE = 'TRAFFIC_NOTICE',
        KEY_PROGRESS = 'KEY_PROGRESS',
        PUBLIC_EVENT = 'PUBLIC_EVENT',
        IOT_WARNING = 'IOT_WARNING',
        CUSTOM_KEYWORD = 'CUSTOM_KEYWORD'
    }

    export enum PriorityEnableStatus {
        DISABLE = 0,
        ENABLE_BY_INTELLIGENT = 1,
        ENABLE = 2
    }

    export interface DistributedBundleEnableInfo {
        bundleName: string;
        uid: int;
        enable?: boolean;
    }

    class DistributedBundleEnableInfoInner implements DistributedBundleEnableInfo {
        bundleName: string = "";
        uid: int = -1;
        enable?: boolean | undefined;
    }

    export enum SwitchState {
        USER_MODIFIED_OFF = 0,
        USER_MODIFIED_ON = 1,
        SYSTEM_DEFAULT_OFF = 2,
        SYSTEM_DEFAULT_ON = 3,
    }

    interface EnableSlotParameter {
        bundle: BundleOption;
        type: SlotType;
        enable: boolean;
        isForceControl: boolean;
    }

    export native function nativeCancelAll(callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelWithId(id: int, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelWithIdLabel(id: int, label: string,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelWithBundle(bundle: BundleOption, id: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeDisplayBadge(bundle: BundleOption, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsBadgeDisplayed(bundle: BundleOption,
        callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativeGetBadgeNumber(callback?: AsyncCallback<long>): Promise<long>;
    export native function nativeSetBadgeNumber(badgeNumber: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetBadgeNumberByBundle(bundle: BundleOption, badgeNumber: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeOnBadgeNumberQuery(callback: CallbackForBadgeQuery): void;
    export native function nativeOffBadgeNumberQuery(): void;
    export native function nativeHandleBadgeNumberPromise(bundle: BundleOption, badgeNumber: long): void;

    export native function nativeGetActiveNotificationCount(callback?: AsyncCallback<long>): Promise<long>;
    export native function nativeGetActiveNotifications(
        callback?: AsyncCallback<Array<NotificationRequest>>): Promise<Array<NotificationRequest>>;
    export native function nativeGetAllActiveNotifications(
        callback?: AsyncCallback<Array<NotificationRequest>>): Promise<Array<NotificationRequest>>;
    export native function nativeGetActiveNotificationByFilter(filter: NotificationFilter,
        callback?: AsyncCallback<NotificationRequest|null>): Promise<NotificationRequest|null>;
    export native function nativeAddDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeAddDoNotDisturbProfileByUserId(templates: Array<DoNotDisturbProfile>, userId : int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeRemoveDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeRemoveDoNotDisturbProfileByUserId(templates: Array<DoNotDisturbProfile>, userId: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSubscribeSystemLiveView(subscriber: SystemLiveViewSubscriber,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeTriggerSystemLiveView(bundle: BundleOption, notificationId: int,
        buttonOptions: ButtonOptions, callback?: AsyncCallback<void>): Promise<void>;

    export native function nativePublishWithUserId(request: NotificationRequest, userId: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativePublish(request: NotificationRequest, callback?: AsyncCallback<void>): Promise<void>;

    export native function nativeGetSlotFlagsByBundle(bundle: BundleOption,
        callback?: AsyncCallback<long>): Promise<long>;

    export native function nativeSetSlotFlagsByBundle(bundle: BundleOption, slotFlags: long,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetSlotsByBundle(bundle: BundleOption,
        callback?: AsyncCallback<Array<NotificationSlot>>): Promise<Array<NotificationSlot>>;
    export native function nativeGetSlotByBundle(bundle: BundleOption, type: SlotType,
         callback?: AsyncCallback<NotificationSlot|null>): Promise<NotificationSlot|null>;

    export native function nativeIsNotificationSlotEnabled(bundle: BundleOption, type: SlotType,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeSetNotificationEnableSlot(bundle: BundleOption, type: SlotType, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetNotificationEnableSlotWithForce(enableSlotParameter: EnableSlotParameter,
        callback?: AsyncCallback<void>): Promise<void>;

    export native function nativeIsNotificationEnabled(callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeIsNotificationEnabledWithId(userId : int,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeIsNotificationEnabledWithBundleOption(bundleOption: BundleOption,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeSetNotificationEnable(bundle: BundleOption, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeRequestEnableNotification(content: UIAbilityContext): Promise<int>;
    export native function nativeGetAllNotificationEnabledBundles(
        callback?: AsyncCallback<Array<BundleOption>>): Promise<Array<BundleOption>>;
    export native function nativeGetAllNotificationEnabledBundlesByUserId(userId : int,
        callback?: AsyncCallback<Array<BundleOption>>): Promise<Array<BundleOption>>;
    export native function nativeIsNotificationEnabledSync(): boolean;

    export native function  nativeRemoveGroupByBundle(bundle: BundleOption, groupName: string,
        callback?: AsyncCallback<void>): Promise<void>;

    export native function nativeAddSlotByNotificationSlot(slot: NotificationSlot,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeAddSlotBySlotType(type: SlotType,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeAddSlots(slots: Array<NotificationSlot>,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetSlot(slotType: SlotType,
        callback?: AsyncCallback<NotificationSlot|null>): Promise<NotificationSlot|null>;
    export native function nativeGetSlots(
        callback?: AsyncCallback<Array<NotificationSlot>>): Promise<Array<NotificationSlot>>;
    export native function nativeRemoveSlot(slotType: SlotType, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeRemoveAllSlots(callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetSlotByBundle(bundle: BundleOption, slot: NotificationSlot,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetSlotNumByBundle(bundle: BundleOption,
        callback?: AsyncCallback<long>): Promise<long>;
    export native function nativeIsSupportTemplate(templateName: string,
        callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativeSetDistributedEnable(enable: boolean, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsDistributedEnabled(callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeIsDistributedEnabledByBundle(bundle: BundleOption,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeIsDistributedEnabledByBundleType(bundle: BundleOption, deviceType: string,
        callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativeGetDeviceRemindType(
        callback?: AsyncCallback<DeviceRemindType>): Promise<DeviceRemindType>;
    export native function nativeSetSyncNotificationEnabledWithoutApp(userId: int, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetSyncNotificationEnabledWithoutApp(userId: int,
        callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativePublishAsBundle(request: NotificationRequest, representativeBundle: string,
        userId: int, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativePublishAsBundleWithBundleOption(representativeBundle: BundleOption,
        request: NotificationRequest, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelAsBundle(id: int, representativeBundle: string, userId: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelAsBundleWithBundleOption(representativeBundle: BundleOption,
        userId: int, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeCancelGroup(groupName: string, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetDoNotDisturbDate(date: DoNotDisturbDate, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetDoNotDisturbDateWithId(date: DoNotDisturbDate, userId: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetDoNotDisturbDate(
        callback?: AsyncCallback<DoNotDisturbDate>): Promise<DoNotDisturbDate>;
    export native function nativeGetDoNotDisturbDateWithId(userId: int,
        callback?: AsyncCallback<DoNotDisturbDate>): Promise<DoNotDisturbDate>;
    export native function nativeIsSupportDoNotDisturbMode(callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativeGetDoNotDisturbProfile(id: long,
        callback?: AsyncCallback<DoNotDisturbProfile>): Promise<DoNotDisturbProfile>;
    export native function nativeGetDoNotDisturbProfileByUserId(id: long, userId: int,
        callback?: AsyncCallback<DoNotDisturbProfile>): Promise<DoNotDisturbProfile>;

    export native function nativeOpenNotificationSettings(content: UIAbilityContext): Promise<int>;

    export native function nativesetTargetDeviceStatus(deviceType: string, status: long,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativesetDistributedEnabledByBundle(bundle: BundleOption, deviceType: string, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativesetSmartReminderEnabled(deviceType: string, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeisSmartReminderEnabled(deviceType: string,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativesetDistributedEnabledBySlot(slot: SlotType, deviceType: string, enabled: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeisDistributedEnabledBySlot(slot: SlotType, deviceType: string,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativesetAdditionalConfig(key: string, value: string,
        callback?: AsyncCallback<int>): Promise<int>;

    export native function nativesetDistributedEnableByBundle(bundle: BundleOption, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativedisableNotificationFeature(disabled:boolean, bundleList: Array<string>,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeOn(
        type: 'checkNotification', callback: CallbackForCheckInfo, checkRequest?: NotificationCheckRequest): int;
    export native function nativeOff(
        type: 'checkNotification', callback?: CallbackForCheckInfo): int;
    export native function nativeGetNotificationSetting(
        callback?: AsyncCallback<NotificationSetting>): Promise<NotificationSetting>;
    export native function nativeSetRingtoneInfoByBundle(bundle: BundleOption, ringtoneInfo: RingtoneInfo,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetRingtoneInfoByBundle(bundle: BundleOption,
        callback?: AsyncCallback<RingtoneInfo>): Promise<RingtoneInfo>;

    export native function nativeSetGeofenceEnabled(enabled: boolean, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsGeofenceEnabled(callback?: AsyncCallback<boolean>): Promise<boolean>;

    export native function nativeIsDistributedEnabledByDeviceType(deviceType: string,
        callback?: AsyncCallback<boolean>): Promise<boolean>;
    export native function nativeSetDistributedEnabledByDeviceType(enable: boolean, deviceType: string,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetDistributedEnableByBundles(bundleEnableInfos: Array<DistributedBundleEnableInfo>,
        deviceType: string, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetDistributedDeviceList(
        callback?: AsyncCallback<Array<string>>): Promise<Array<string>>;

    export native function nativeDisableNotificationFeatureWithId(disabled:boolean, bundleList: Array<string>, userId: int,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeSetSilentReminderEnabled(bundle: BundleOption, enable: boolean,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsSilentReminderEnabled(bundle: BundleOption,
        callback?: AsyncCallback<SwitchState>): Promise<SwitchState>;
    export native function nativeSetReminderInfoByBundles(reminderInfos: Array<NotificationReminderInfo>,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetReminderInfoByBundles(bundles: Array<BundleOption>,
        callback?: AsyncCallback<Array<NotificationReminderInfo>>): Promise<Array<NotificationReminderInfo>>;
    export native function nativeGetBadgeDisplayStatusByBundles(bundles: Array<BundleOption>,
        callback?: AsyncCallback<Map<BundleOption, boolean>>): Promise<Map<BundleOption, boolean>>;
    export native function nativeSetBadgeDisplayStatusByBundles(badges: Map<BundleOption, boolean>,
        callback?: AsyncCallback<void>): Promise<void>;

    export native function nativeSetBundlePriorityConfig(bundle: BundleOption, value: string,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeGetBundlePriorityConfig(bundle: BundleOption,
        callback?: AsyncCallback<string>): Promise<string>;
    export native function nativeSetPriorityEnabledByBundle(bundle: BundleOption, enableStatus: PriorityEnableStatus,
        callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsPriorityEnabledByBundle(bundle: BundleOption,
        callback?: AsyncCallback<PriorityEnableStatus>): Promise<PriorityEnableStatus>;
    export native function nativeSetPriorityEnabled(enable: boolean, callback?: AsyncCallback<void>): Promise<void>;
    export native function nativeIsPriorityEnabled(callback?: AsyncCallback<boolean>): Promise<boolean>;

    function isInvalidParameter(doNotDisturbDate: DoNotDisturbDate): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (doNotDisturbDate == null) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }

    function isInvalidParameter(slot: NotificationSlot): BusinessError
    {
        if (slot == null) {
            return errorParamInvalid;
        }
        if (slot.lockscreenVisibility !== undefined && typeof slot.lockscreenVisibility === 'int') {
            const num = slot.lockscreenVisibility ?? -1;
            if (num < 0) {
                return errorParamInvalid;
            }
        }
        if (slot.lightColor !== undefined && typeof slot.lightColor === 'int') {
            const num = slot.lightColor ?? -1;
            if (num < 0) {
                return errorParamInvalid;
            }
        }
        if (slot.desc !== undefined && slot.desc?.trim() === '') {
            return errorParamInvalid;
        }
        if (slot.sound !== undefined && slot.sound?.trim() === '') {
            return errorParamInvalid;
        }
        if (slot.vibrationValues !== undefined && slot.vibrationValues?.length === 0) {
            return errorParamInvalid;
        }
        return successCallbackError;
    }

    function isInvalidParameter(bundle: BundleOption): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (bundle == null) {
            error = errorParamInvalid
            return error;
        }
        if (bundle.bundle == null || bundle.bundle === undefined || bundle.bundle?.length === 0) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }

    function isInvalidParameter(option: ButtonOptions): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (option == null) {
            error = errorParamInvalid
            return error;
        }
        if (option.buttonName == null || option.buttonName?.length === 0) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }
    function isInvalidParameter(filter: NotificationFilter): BusinessError
    {
        let error: BusinessError = successCallbackError;
        if (filter == null) {
            return errorParamInvalid;
        }
        error = isInvalidParameter(filter.bundle);
        if (error.code != 0) {
            return error;
        }
        if (filter.notificationKey?.label !== undefined && filter.notificationKey?.label?.trim() === '') {
            return errorParamInvalid;
        }
        if (filter?.extraInfoKeys !== undefined && filter?.extraInfoKeys?.length === 0) {
            return errorParamInvalid;
        }
        return error;
    }
    function isInvalidContent(normal?: NotificationBasicContent): boolean
    {
        if (normal !== undefined) {
            if (!normal?.title || normal?.title?.trim() === '') {
                return false;
            }
            if (!normal?.text || normal?.text?.trim() === '') {
                return false;
            }
            if (normal?.lockscreenPicture != undefined && !(normal?.lockscreenPicture instanceof image.PixelMap)) {
                return false;
            }
        }
        return true;
    }
    function isInvalidLongText(longText?: NotificationLongTextContent): boolean
    {
        if (!isInvalidContent(longText)) {
            return false;
        }
        if (!longText?.longText || longText?.longText?.trim() === '') {
            return false;
        }
        if (!longText?.briefText || longText?.briefText?.trim() === '') {
            return false;
        }
        if (!longText?.expandedTitle || longText?.expandedTitle?.trim() === '') {
            return false;
        }
        return true;
    }
    function isInvalidMultiLine(multiLine?: NotificationMultiLineContent): boolean
    {
        if (!isInvalidContent(multiLine)) {
            return false;
        }
        if (!multiLine?.briefText || multiLine?.briefText.trim() === '') {
            return false;
        }
        if (!multiLine?.longTitle || multiLine?.longTitle.trim() === '') {
            return false;
        }
        if (multiLine?.lines?.length === 0) {
            return false;
        }
        return true;
    }
    function isInvalidPicture(picture?: NotificationPictureContent): boolean
    {
        if (!isInvalidContent(picture)) {
            return false;
        }
        if (!picture?.briefText || picture?.briefText?.trim() === '') {
            return false;
        }
        if (!picture?.expandedTitle || picture?.expandedTitle?.trim() === '') {
            return false;
        }
        if (!(picture?.picture instanceof image.PixelMap)) {
            return false;
        }
        return true;
    }
    function isInvalidSystemLiveView(systemLiveView?: NotificationSystemLiveViewContent): boolean
    {
        if (!isInvalidContent(systemLiveView)) {
            return false;
        }
        if (systemLiveView?.capsule !== undefined) {
            if (systemLiveView?.capsule?.icon != undefined && !(systemLiveView?.capsule?.icon instanceof image.PixelMap)) {
                return false;
            }
            if (systemLiveView?.capsule?.capsuleButtons != undefined && systemLiveView?.capsule?.capsuleButtons?.length === 0) {
                return false;
            }
        }
        if (systemLiveView?.button !== undefined && systemLiveView?.button === null) {
            return false;
        }
        if (systemLiveView?.button?.names != undefined && systemLiveView?.button?.names?.length === 0) {
            return false;
        }
        if (systemLiveView?.button?.icons != undefined && systemLiveView?.button?.icons?.length === 0) {
            return false;
        }
        if (systemLiveView?.button?.iconsResource != undefined && systemLiveView?.button?.iconsResource?.length === 0) {
            return false;
        }
        
        if (systemLiveView?.cardButtons !== undefined && systemLiveView?.cardButtons?.length === 0) {
            return false;
        }
        return true;
    }
    function isInvalidLiveView(liveView?: NotificationLiveViewContent): boolean
    {
        if (!isInvalidContent(liveView)) {
            return false;
        }
        if (liveView?.extraInfo !== undefined && liveView?.extraInfo === null) {
            return false;
        }
        if (liveView?.pictureInfo !== undefined && liveView?.pictureInfo === null) {
            return false;
        }
        return true;
    }

    function isInvalidParameter(ringtoneInfo: RingtoneInfo): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (ringtoneInfo == null) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }

    function isInvalidTemplate(template?: NotificationTemplate): boolean
    {
        if (template === null) {
            return false;
        }
        if (template?.name == undefined) {
            return false;
        }
        if (template?.data !== undefined && typeof template?.data !== 'object') {
            return false;
        }
        return true;
    }
    function isInvalidDistributedOption(distributedOption?: DistributedOptions): boolean
    {
        if (distributedOption === null) {
            return false
        }
        if (distributedOption?.supportDisplayDevices != undefined && distributedOption?.supportDisplayDevices?.length === 0) {
            return false;
        }
        if (distributedOption?.supportOperateDevices != undefined && distributedOption?.supportOperateDevices?.length === 0) {
            return false;
        }
        return true;
    }
    function isInvalidBundleOption(bundleOption?: BundleOption): boolean
    {
        if (bundleOption === null) {
            return false;
        }
        if (bundleOption?.bundle != undefined && bundleOption?.bundle?.trim() === '') {
            return false;
        }
        return true;
    }
    function checkContentType(content: NotificationContent): boolean
    {
        let contentType = content.notificationContentType;
        if (contentType !== undefined) {
            let type:ContentType = contentType as ContentType;
            if (type == ContentType.NOTIFICATION_CONTENT_BASIC_TEXT
                && content.normal == undefined) {
                return false;
            } else if (type == ContentType.NOTIFICATION_CONTENT_LONG_TEXT
                && content.longText == undefined) {
                return false;
            } else if (type == ContentType.NOTIFICATION_CONTENT_PICTURE
                && content.picture == undefined) {
                return false;
            } else if (type == ContentType.NOTIFICATION_CONTENT_MULTILINE
                && content.multiLine == undefined) {
                return false;
            } else if (type == ContentType.NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW
                && content.systemLiveView == undefined) {
                return false;
            } else if (type == ContentType.NOTIFICATION_CONTENT_LIVE_VIEW
                && content.liveView == undefined) {
                return false;
            }
        }
        return true;
    }
    function isInvalidParameter(request: NotificationRequest): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (request == null) {
            error = errorParamInvalid
            return error;
        }
        if (request.content == null || request.content == undefined) {
            error = errorParamInvalid
            return error;
        }
        if (request.content?.notificationContentType == undefined) {
            return errorParamInvalid;
        }
        if (!checkContentType(request.content)) {
            return errorParamInvalid;
        }
        if (request.content?.normal !== undefined && !isInvalidContent(request.content.normal)) {
            return errorParamInvalid;
        }
        if (request.content?.longText !== undefined && !isInvalidLongText(request.content.longText)) {
            return errorParamInvalid;
        }
        if (request.content?.multiLine !== undefined && !isInvalidMultiLine(request.content.multiLine)) {
            return errorParamInvalid;
        }
        if (request.content?.picture !== undefined && !isInvalidPicture(request.content.picture)) {
            return errorParamInvalid;
        }
        if (request.content?.systemLiveView !== undefined && !isInvalidSystemLiveView(request.content.systemLiveView)) {
            return errorParamInvalid;
        }
        if (request.content?.liveView !== undefined && !isInvalidLiveView(request.content.liveView)) {
            return errorParamInvalid;
        }
        if (request?.wantAgent !== undefined && request.wantAgent == null) {
            return errorParamInvalid;
        }
        if(request?.extendInfo !== undefined && request?.extendInfo == null) {
            return errorParamInvalid;
        }
        if (request.smallIcon !== undefined && request.smallIcon == null) {
            return errorParamInvalid;
        }
        if (request?.largeIcon !== undefined && request.largeIcon == null) {
            return errorParamInvalid;
        }
        if (request?.overlayIcon !== undefined && request.overlayIcon == null) {
            return errorParamInvalid;
        }
        if (request?.template !== undefined && !isInvalidTemplate(request.template)) {
            return errorParamInvalid;
        }
        if (request?.distributedOption !== undefined && !isInvalidDistributedOption(request.distributedOption)) {
            return errorParamInvalid;
        }
        if (request?.removalWantAgent !== undefined && request.removalWantAgent == null) {
            return errorParamInvalid;
        }
        if (request?.representativeBundle !== undefined && !isInvalidBundleOption(request.representativeBundle)) {
            return errorParamInvalid;
        }
        if (request?.agentBundle !== undefined && !isInvalidBundleOption(request.agentBundle)) {
            return errorParamInvalid;
        }
        if (request?.color !== undefined && typeof request.color === 'long') {
            const num = request.color ?? -1;
            if (num < 0) {
                return errorParamInvalid;
            }
        }
        if (request?.badgeNumber !== undefined && typeof request.badgeNumber === 'long') {
            const num = request.badgeNumber ?? -1;
            if (num < 0) {
                return errorParamInvalid;
            }
        }
        return error;
    }

    export function getSlotNumByBundle(bundle: BundleOption): Promise<long> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<long>;
        try {
            result = nativeGetSlotNumByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSlotNumByBundle(bundle: BundleOption, callback: AsyncCallback<long>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetSlotNumByBundle(bundle, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setSlotByBundle(bundle: BundleOption, slot: NotificationSlot, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeSetSlotByBundle(bundle, slot, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setSlotByBundle(bundle: BundleOption, slot: NotificationSlot): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        let result: Promise<void>;
        try {
            result = nativeSetSlotByBundle(bundle, slot, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function removeAllSlots(callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeRemoveAllSlots(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function removeAllSlots(): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeRemoveAllSlots(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function removeSlot(slotType: SlotType, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeRemoveSlot(slotType, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function removeSlot(slotType: SlotType): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeRemoveSlot(slotType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSlots(): Promise<Array<NotificationSlot>> {
        let result: Promise<Array<NotificationSlot>>;
        try {
            result = nativeGetSlots(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSlots(callback: AsyncCallback<Array<NotificationSlot>>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetSlots(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getSlot(slotType: SlotType): Promise<NotificationSlot|null> {
        let result: Promise<NotificationSlot|null>;
        try {
            result = nativeGetSlot(slotType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSlot(slotType: SlotType, callback: AsyncCallback<NotificationSlot|null>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetSlot(slotType, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getSlotByBundle(bundle: BundleOption, slotType: SlotType): Promise<NotificationSlot|null> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<NotificationSlot|null>;
        try {
            result = nativeGetSlotByBundle(bundle, slotType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function addSlots(slots: Array<NotificationSlot>): Promise<void> {
        if (!slots || slots.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeAddSlots(slots, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function addSlots(slots: Array<NotificationSlot>, callback: AsyncCallback<void>): void {
        if (!slots || slots.length === 0) {
            throw errorParamInvalid;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeAddSlots(slots, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function addSlot(slot: NotificationSlot): Promise<void> {
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        let result: Promise<void>;
        try {
            result = nativeAddSlotByNotificationSlot(slot, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function addSlot(slot: NotificationSlot, callback: AsyncCallback<void>): void {
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeAddSlotByNotificationSlot(slot, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function addSlot(type: SlotType, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeAddSlotBySlotType(type, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function addSlot(type: SlotType): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeAddSlotBySlotType(type, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setNotificationEnable(bundle: BundleOption, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetNotificationEnable(bundle, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setNotificationEnable(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeSetNotificationEnable(bundle, enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isNotificationEnabled(bundleOption: BundleOption, callback: AsyncCallback<boolean>): void
    {
        let error: BusinessError = isInvalidParameter(bundleOption);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsNotificationEnabledWithBundleOption(bundleOption, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isNotificationEnabled(bundleOption: BundleOption): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundleOption);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeIsNotificationEnabledWithBundleOption(bundleOption, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isNotificationEnabled(userId: int, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsNotificationEnabledWithId(userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isNotificationEnabled(userId: int): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsNotificationEnabledWithId(userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isNotificationEnabled(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsNotificationEnabled(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isNotificationEnabled(): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsNotificationEnabled(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption,
        type: SlotType,
        enable: boolean,
        isForceControl: boolean,
        callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let enableSlotParameter: EnableSlotParameter = {
            bundle: bundle,
            type: type,
            enable: enable,
            isForceControl: isForceControl,
        } as EnableSlotParameter;
        try {
            nativeSetNotificationEnableSlotWithForce(enableSlotParameter, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, isForceControl?: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        let enableSlotParameter: EnableSlotParameter;
        if (isForceControl == undefined) {
            enableSlotParameter = {
                bundle: bundle,
                type: type,
                enable: enable,
                isForceControl: false,
            } as EnableSlotParameter;
        } else {
            enableSlotParameter = {
                bundle: bundle,
                type: type,
                enable: enable,
                isForceControl: isForceControl as boolean,
            } as EnableSlotParameter;
        }
        try {
            result = nativeSetNotificationEnableSlotWithForce(enableSlotParameter, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        try {
            nativeSetNotificationEnableSlot(bundle, type, enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeIsNotificationSlotEnabled(bundle, type, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType, callback: AsyncCallback<boolean>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsNotificationSlotEnabled(bundle, type, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getSlotsByBundle(bundle: BundleOption, callback: AsyncCallback<Array<NotificationSlot>>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetSlotsByBundle(bundle, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getSlotsByBundle(bundle: BundleOption): Promise<Array<NotificationSlot>>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<Array<NotificationSlot>>;
        try {
            result = nativeGetSlotsByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setSlotFlagsByBundle(bundle: BundleOption, slotFlags: long): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetSlotFlagsByBundle(bundle, slotFlags, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSlotFlagsByBundle(bundle: BundleOption): Promise<long> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<long>;
        try {
            result = nativeGetSlotFlagsByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function publish(request: NotificationRequest, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativePublish(request, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function publish(request: NotificationRequest): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativePublish(request, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function publish(request: NotificationRequest, userId: int, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativePublishWithUserId(request, userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function publish(request: NotificationRequest, userId: int): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativePublishWithUserId(request, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function triggerSystemLiveView(
        bundle: BundleOption, notificationId: int, buttonOptions: ButtonOptions): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        error = isInvalidParameter(buttonOptions);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeTriggerSystemLiveView(bundle, notificationId, buttonOptions, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function subscribeSystemLiveView(subscriber: SystemLiveViewSubscriber): Promise<void>
    {
        if(subscriber === null) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeSubscribeSystemLiveView(subscriber, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function removeDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeRemoveDoNotDisturbProfile(templates, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function removeDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>, userId: int): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeRemoveDoNotDisturbProfileByUserId(templates, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function addDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeAddDoNotDisturbProfile(templates, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function addDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>, userId : int): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeAddDoNotDisturbProfileByUserId(templates, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getAllActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            throw errorParamInvalid;
        }
        try {
            nativeGetAllActiveNotifications(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getAllActiveNotifications(): Promise<Array<NotificationRequest>> {
        let result: Promise<Array<NotificationRequest>>;
        try {
            result = nativeGetAllActiveNotifications(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getActiveNotifications(): Promise<Array<NotificationRequest>> {
        let result: Promise<Array<NotificationRequest>>;
        try {
            result = nativeGetActiveNotifications(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            throw errorParamInvalid;
        }
        try {
            nativeGetActiveNotifications(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getActiveNotificationCount(callback: AsyncCallback<long>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetActiveNotificationCount(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getActiveNotificationCount(): Promise<long> {
        let result: Promise<long>;
        try {
            result = nativeGetActiveNotificationCount(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function displayBadge(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeDisplayBadge(bundle, enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function displayBadge(bundle: BundleOption, enable: boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeDisplayBadge(bundle, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isBadgeDisplayed(bundle: BundleOption, callback: AsyncCallback<boolean>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        try {
            nativeIsBadgeDisplayed(bundle, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isBadgeDisplayed(bundle: BundleOption): Promise<boolean> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeIsBadgeDisplayed(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancel(bundle: BundleOption, id: int): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeCancelWithBundle(bundle, id, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancel(id: int, label?: string): Promise<void> {
        let result: Promise<void>;
        try {
            if (label == undefined) {
                result = nativeCancelWithId(id, undefined);
            } else if (label?.length === 0) {
                throw errorParamInvalid;
            } else {
                result = nativeCancelWithIdLabel(id, label as string, undefined);
            }
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        } catch (err: BusinessError) {
            throw err;
        }
        return result;
    }

    export function cancel(id: int, label: string, callback: AsyncCallback<void>): void {
        if (label == null || label?.length === 0) {
            throw errorParamInvalid;
            return;
        }
        if (callback == null) {
            throw errorParamInvalid;
            return;
        }
        try {
            nativeCancelWithIdLabel(id, label, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function cancel(id: int, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeCancelWithId(id, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function cancel(id: int): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeCancelWithId(id, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancelAll(): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeCancelAll(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancelAll(callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeCancelAll(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function requestEnableNotification(context: UIAbilityContext): Promise<void>
    {
        if (context == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => { return nativeRequestEnableNotification(context); });
            p.then(
                (data: Any): void => {
                    if (data == undefined) {
                        reject(rejectInternalError);
                    } else {
                        let result: int = data as int;
                        if (result == 0) {
                            resolve(undefined);
                        } else {
                            reject(rejectInternalError);
                        }
                    }
                },
                (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function requestEnableNotification(context: UIAbilityContext, callback: AsyncCallback<void>): void
    {
        if (context == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): Promise<int> => { return nativeRequestEnableNotification(context); });
        p.then(
            (data: Any): void => {
                if (data == undefined) {
                    callback(callbackInternalError, undefined);
                } else {
                    let result: int = data as int;
                    if (result == 0) {
                        callback(null, undefined);
                    } else {
                        callback(callbackInternalError, undefined);
                    }
                }
            },
            (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export interface NotificationCheckResult {
        code: int;
        message: string;
    }

    class NotificationCheckResultInner implements NotificationCheckResult {
        public code: int = -1;
        public message: string = '';
    }

    export function onCheckNotification(
        callback: (checkInfo: NotificationCheckInfo) => NotificationCheckResult): void
    {
        let errCode = nativeOn('checkNotification', callback);
        if (errCode != 0) {
            const error: BusinessError = {code: errCode, message: "unknown error"};
            throw error;
        }
    }

    export function onCheckNotification(checkRequest: NotificationCheckRequest,
        callback: (checkInfo: NotificationCheckInfo) => Promise<NotificationCheckResult>): void
    {
        let onFuncCallback: CallbackForCheckInfo =
            (checkInfo: notificationManager.NotificationCheckInfo): notificationManager.NotificationCheckResult => {
                let result: notificationManager.NotificationCheckResult = {
                    code: -1,
                    message: 'unknown error'
                };
                let p = callback(checkInfo);
                await p.then(
                    (e: Any): void => {
                        result = e as notificationManager.NotificationCheckResult;
                    }, (error: Error): void => {
                        let err: BusinessError = error as BusinessError;
                        result = {
                            code: err.code as int,
                            message: err.message
                        };
                    }
                );
                return result;
            };
        let errCode = nativeOn('checkNotification', onFuncCallback, checkRequest);
        if (errCode != 0) {
            const error: BusinessError = {code: errCode, message: "unknown error"};
            throw error;
        }
    }

    export function offCheckNotification(
        callback?: (checkInfo: NotificationCheckInfo) => NotificationCheckResult
    ): void
    {
        let errCode = -1;
        if (callback === undefined) {
            errCode = nativeOff('checkNotification');
        } else {
            errCode = nativeOff('checkNotification', callback);
        }
        if (errCode != 0) {
            const error: BusinessError = {code: errCode, message: "unknown error"};
            throw error;
        }
    }

    export interface NotificationCheckInfo {
        bundleName: string;
        notificationId: int;
        label?: string;
        contentType: ContentType;
        creatorUserId: int;
        slotType: SlotType;
        extraInfos?: Record<string, RecordData>;
    }

    class NotificationCheckInfoInner implements NotificationCheckInfo {
        public bundleName: string = '';
        public notificationId: int = -1;
        public label?: string;
        public contentType: ContentType = ContentType.NOTIFICATION_CONTENT_BASIC_TEXT;
        public creatorUserId: int = -1;
        public slotType: SlotType = SlotType.UNKNOWN_TYPE;
        public extraInfos?: Record<string, RecordData>;
    }

    export function getAllNotificationEnabledBundles(): Promise<Array<BundleOption>>
    {
        let result: Promise<Array<BundleOption>>;
        try {
            result = nativeGetAllNotificationEnabledBundles(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getAllNotificationEnabledBundles(userId : int): Promise<Array<BundleOption>>
    {
        let result: Promise<Array<BundleOption>>;
        try {
            result = nativeGetAllNotificationEnabledBundlesByUserId(userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isNotificationEnabledSync(): boolean
    {
        return nativeIsNotificationEnabledSync();
    }

    export function getBadgeNumber(): Promise<long> {
        let result: Promise<long>;
        try {
            result = nativeGetBadgeNumber(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function onBadgeNumberQuery(callback: (bundle: BundleOption) => Promise<long>): void {
        if (callback == undefined || callback == null) {
            throw errorParamInvalid;
        }

        let funcCallback: CallbackForBadgeQuery = (bundle: BundleOption): Promise<long> => {
            return callback(bundle)
                .then((num: Any) => {
                    const result = num as long;
                    nativeHandleBadgeNumberPromise(bundle, result);
                    return result;
                })
                .catch((error: Error) => {
                    const result: long = -1;
                    nativeHandleBadgeNumberPromise(bundle, result);
                    return result;
                });
        };
        
        return nativeOnBadgeNumberQuery(funcCallback);
    }

    export function offBadgeNumberQuery(): void
    {
        return nativeOffBadgeNumberQuery();
    }

    export function setBadgeNumber(badgeNumber: int, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
           throw errorParamInvalid;
        }
        try {
            nativeSetBadgeNumber(badgeNumber, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setBadgeNumber(badgeNumber: int): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeSetBadgeNumber(badgeNumber, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setBadgeNumberByBundle(bundle: BundleOption, badgeNumber: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetBadgeNumberByBundle(bundle, badgeNumber, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getActiveNotificationByFilter(filter: NotificationFilter, callback: AsyncCallback<NotificationRequest|null>): void
    {
        let error: BusinessError = isInvalidParameter(filter);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback === null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetActiveNotificationByFilter(filter, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getActiveNotificationByFilter(filter: NotificationFilter): Promise<NotificationRequest|null>
    {
        let error: BusinessError = isInvalidParameter(filter);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<NotificationRequest|null>;
        try {
            result = nativeGetActiveNotificationByFilter(filter, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isSupportTemplate(templateName: string): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsSupportTemplate(templateName, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function removeGroupByBundle(bundle: BundleOption, groupName: string, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (groupName === '') {
            throw errorParamInvalid;
        }
        if (!callback) {
            throw errorParamInvalid;
        }
        try {
            nativeRemoveGroupByBundle(bundle, groupName, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function removeGroupByBundle(bundle: BundleOption, groupName: string): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (groupName === '') {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeRemoveGroupByBundle(bundle, groupName, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function publishAsBundle(request: NotificationRequest, representativeBundle: string, userId: int, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }

        if (callback == null) {
            throw errorParamInvalid;
        }
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        try {
            nativePublishAsBundle(request, representativeBundle, userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function publishAsBundle(request: NotificationRequest, representativeBundle: string, userId: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativePublishAsBundle(request, representativeBundle, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function publishAsBundle(representativeBundle: BundleOption, request: NotificationRequest): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let err: BusinessError = isInvalidParameter(representativeBundle);
        if (err.code !== ERROR_OK) {
            throw err;
        }
        let result: Promise<void>;
        try {
            result = nativePublishAsBundleWithBundleOption(representativeBundle, request, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancelAsBundle(id: int, representativeBundle: string, userId: int, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        try {
            nativeCancelAsBundle(id, representativeBundle, userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function cancelAsBundle(id: int, representativeBundle: string, userId: int): Promise<void>
    {
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeCancelAsBundle(id, representativeBundle, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancelAsBundle(representativeBundle: BundleOption, userId: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(representativeBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeCancelAsBundleWithBundleOption(representativeBundle, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function cancelGroup(groupName: string, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        if (groupName == null || groupName?.length === 0) {
            throw errorParamInvalid;
        }
        try {
            nativeCancelGroup(groupName, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function cancelGroup(groupName: string): Promise<void>
    {
        if (groupName == null || groupName?.length === 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeCancelGroup(groupName, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        try {
            nativeSetDoNotDisturbDate(date, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetDoNotDisturbDate(date, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate, userId: int, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        try {
            nativeSetDoNotDisturbDateWithId(date, userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate, userId: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetDoNotDisturbDateWithId(date, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDoNotDisturbDate(callback: AsyncCallback<DoNotDisturbDate>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetDoNotDisturbDate(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getDoNotDisturbDate(): Promise<DoNotDisturbDate>
    {
        let result: Promise<DoNotDisturbDate>;
        try {
            result = nativeGetDoNotDisturbDate(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDoNotDisturbDate(userId: int, callback: AsyncCallback<DoNotDisturbDate>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetDoNotDisturbDateWithId(userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getDoNotDisturbDate(userId: int): Promise<DoNotDisturbDate>
    {
        let result: Promise<DoNotDisturbDate>;
        try {
            result = nativeGetDoNotDisturbDateWithId(userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isSupportDoNotDisturbMode(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsSupportDoNotDisturbMode(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isSupportTemplate(templateName: string, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsSupportTemplate(templateName, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isSupportDoNotDisturbMode(): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsSupportDoNotDisturbMode(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDoNotDisturbProfile(id: long): Promise<DoNotDisturbProfile>
    {
        let result: Promise<DoNotDisturbProfile>;
        try {
            result = nativeGetDoNotDisturbProfile(id, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDoNotDisturbProfile(id: long, userId: int): Promise<DoNotDisturbProfile>
    {
        let result: Promise<DoNotDisturbProfile>;
        try {
            result = nativeGetDoNotDisturbProfileByUserId(id, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function openNotificationSettings(context: UIAbilityContext): Promise<void>
    {
        if (context == undefined || context === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => { return nativeOpenNotificationSettings(context); });
            p.then(
                (data: Any): void => {
                    if (data == undefined) {
                        reject(rejectInternalError);
                    } else {
                        let result: int = data as int;
                        if (result == 0) {
                            resolve(undefined);
                        } else {
                            reject(rejectInternalError);
                        }
                    }
                },
                (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function setTargetDeviceStatus(deviceType: string, status: long): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativesetTargetDeviceStatus(deviceType,status, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnabledByBundle(bundle: BundleOption, deviceType: string, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativesetDistributedEnabledByBundle(bundle, deviceType, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnableByBundle(bundle: BundleOption, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativesetDistributedEnableByBundle(bundle, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setSmartReminderEnabled(deviceType: string, enable: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativesetSmartReminderEnabled(deviceType, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isSmartReminderEnabled(deviceType: string): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeisSmartReminderEnabled(deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnabledBySlot(slot: SlotType, deviceType: string, enabled: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativesetDistributedEnabledBySlot(slot, deviceType, enabled, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isDistributedEnabledBySlot(slot: SlotType, deviceType: string): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeisDistributedEnabledBySlot(slot, deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setAdditionalConfig(key: string, value: string): Promise<int>{
        let result: Promise<int>;
        try {
            result = nativesetAdditionalConfig(key, value, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function disableNotificationFeature(disabled:boolean, bundleList: Array<string>): Promise<void> {
        if (bundleList.length == 0) {
            throw errorParamInvalid;
        }
        bundleList.forEach((value, index, bundleList) => {
            if (value.trim().isEmpty()) {
                throw errorParamInvalid;
            }
        });
        let result: Promise<void>;
        try {
            result = nativedisableNotificationFeature(disabled, bundleList, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnableByBundle(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void
    {
        try {
            nativesetDistributedEnableByBundle(bundle, enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setDistributedEnable(enable: boolean, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeSetDistributedEnable(enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setDistributedEnable(enable: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativeSetDistributedEnable(enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isDistributedEnabled(): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsDistributedEnabled(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isDistributedEnabled(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsDistributedEnabled(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isDistributedEnabledByBundle(bundle: BundleOption): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeIsDistributedEnabledByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isDistributedEnabledByBundle(bundle: BundleOption, callback: AsyncCallback<boolean>): void
    {

        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeIsDistributedEnabledByBundle(bundle, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function isDistributedEnabledByBundle(bundle: BundleOption, deviceType: string): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeIsDistributedEnabledByBundleType(bundle, deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDeviceRemindType(): Promise<DeviceRemindType>
    {
        let result: Promise<DeviceRemindType>;
        try {
            result = nativeGetDeviceRemindType(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDeviceRemindType(callback: AsyncCallback<DeviceRemindType>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetDeviceRemindType(callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setSyncNotificationEnabledWithoutApp
        (userId: int, enable: boolean, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeSetSyncNotificationEnabledWithoutApp(userId, enable, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function setSyncNotificationEnabledWithoutApp(userId: int, enable: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativeSetSyncNotificationEnabledWithoutApp(userId, enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSyncNotificationEnabledWithoutApp(userId: int): Promise<boolean> {
        let result: Promise<boolean>;
        try {
            result = nativeGetSyncNotificationEnabledWithoutApp(userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getSyncNotificationEnabledWithoutApp(userId: int, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        try {
            nativeGetSyncNotificationEnabledWithoutApp(userId, callback);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
    }

    export function getNotificationSetting(): Promise<NotificationSetting> {
        let result: Promise<NotificationSetting>;
        try {
            result = nativeGetNotificationSetting(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export interface RingtoneInfo {
        ringtoneType: RingtoneType;
        ringtoneTitle?: string;
        ringtoneFileName?: string;
        ringtoneUri?: string;
    }

    class RingtoneInfoInner implements RingtoneInfo {
        public ringtoneType: RingtoneType = RingtoneType.RINGTONE_TYPE_NONE;
        public ringtoneTitle?: string;
        public ringtoneFileName?: string;
        public ringtoneUri?: string;
    }

    export function setRingtoneInfoByBundle(bundle: BundleOption, ringtoneInfo: RingtoneInfo): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        error = isInvalidParameter(ringtoneInfo);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        return nativeSetRingtoneInfoByBundle(bundle, ringtoneInfo, undefined);
    }

    export function getRingtoneInfoByBundle(bundle: BundleOption): Promise<RingtoneInfo> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<RingtoneInfo>;
        try {
            result = nativeGetRingtoneInfoByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setGeofenceEnabled(enable: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativeSetGeofenceEnabled(enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isGeofenceEnabled(): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsGeofenceEnabled(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export interface NotificationReminderInfo {
        bundle: BundleOption;
        reminderFlags: long;
        silentReminderEnabled: boolean;
    }

    class NotificationReminderInfoInner implements NotificationReminderInfo {
        public bundle: BundleOption = { bundle: '', uid: undefined };
        public reminderFlags: long = -1;
        public silentReminderEnabled: boolean = false;
    }

    export function getReminderInfoByBundles(bundles: Array<BundleOption>): Promise<Array<NotificationReminderInfo>> {
        if (!bundles || bundles.length == 0) {
            throw errorParamInvalid;
        }
        let result: Promise<Array<NotificationReminderInfo>>;
        try {
            result = nativeGetReminderInfoByBundles(bundles, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setReminderInfoByBundles(reminderInfos: Array<NotificationReminderInfo>): Promise<void> {
        if (!reminderInfos || reminderInfos.length == 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeSetReminderInfoByBundles(reminderInfos, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isDistributedEnabled(deviceType: string): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsDistributedEnabledByDeviceType(deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function disableNotificationFeature(disabled: boolean, bundleList: Array<string>, userId: int): Promise<void>
    {
        if (bundleList.length == 0) {
            throw errorParamInvalid;
        }
        bundleList.forEach((value, index, bundleList) => {
            if (value.trim().isEmpty()) {
                throw errorParamInvalid;
            }
        });
        if (userId < 0 || userId > MAX_USER_ID) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeDisableNotificationFeatureWithId(disabled, bundleList, userId, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnabled(enabled: boolean, deviceType: string): Promise<void>
    {
        if (deviceType.trim().isEmpty()) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeSetDistributedEnabledByDeviceType(enabled, deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setDistributedEnableByBundles(bundleEnableInfos: Array<DistributedBundleEnableInfo>, deviceType: string): Promise<void>
    {
        if (bundleEnableInfos.length == 0 || deviceType.trim().isEmpty()) {
            throw errorParamInvalid;
        }
        bundleEnableInfos.forEach((value, index, bundleEnableInfos) => {
            if (value.bundleName.trim().isEmpty()) {
                throw errorParamInvalid;
            }
        });
        let result: Promise<void>;
        try {
            result = nativeSetDistributedEnableByBundles(bundleEnableInfos, deviceType, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getDistributedDeviceList(): Promise<Array<string>>
    {
        let result: Promise<Array<string>>;
        try {
            result = nativeGetDistributedDeviceList(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setBundlePriorityConfig(bundle: BundleOption, value: string): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetBundlePriorityConfig(bundle, value, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getBundlePriorityConfig(bundle: BundleOption): Promise<string>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<string>;
        try {
            result = nativeGetBundlePriorityConfig(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setPriorityEnabledByBundle(bundle: BundleOption, enableStatus: PriorityEnableStatus): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetPriorityEnabledByBundle(bundle, enableStatus, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isPriorityEnabledByBundle(bundle: BundleOption): Promise<PriorityEnableStatus>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<PriorityEnableStatus>;
        try {
            result = nativeIsPriorityEnabledByBundle(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setPriorityEnabled(enable: boolean): Promise<void>
    {
        let result: Promise<void>;
        try {
            result = nativeSetPriorityEnabled(enable, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function isPriorityEnabled(): Promise<boolean>
    {
        let result: Promise<boolean>;
        try {
            result = nativeIsPriorityEnabled(undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setSilentReminderEnabled(bundle: BundleOption, enabled: boolean): Promise<void>
    {
        if (bundle.bundle.trim().isEmpty()) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeSetSilentReminderEnabled(bundle, enabled, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result; 
    }

    export function isSilentReminderEnabled(bundle: BundleOption): Promise<SwitchState>
    {
        if (bundle.bundle.trim().isEmpty()) {
            throw errorParamInvalid;
        }
        let result: Promise<SwitchState>;
        try {
            result = nativeIsSilentReminderEnabled(bundle, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function setBadgeDisplayStatusByBundles(badges: Map<BundleOption, boolean>): Promise<void> {
        if (!badges || badges.size == 0) {
            throw errorParamInvalid;
        }
        let result: Promise<void>;
        try {
            result = nativeSetBadgeDisplayStatusByBundles(badges, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    export function getBadgeDisplayStatusByBundles(bundles: Array<BundleOption>): Promise<Map<BundleOption, boolean>> {
        if (!bundles || bundles.length == 0) {
            throw errorParamInvalid;
        }
        let result: Promise<Map<BundleOption, boolean>>;
        try {
            result = nativeGetBadgeDisplayStatusByBundles(bundles, undefined);
        } catch (err: Error) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }
}