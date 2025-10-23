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

const ERROR_OK = 0;
const ERROR_PARAM_INVALID = 401;
const ERROR_INTERNAL_ERROR = 160001;

const rejectInternalError: BusinessError<string> = {code: ERROR_INTERNAL_ERROR, data: "Internal error."};
const callbackInternalError: BusinessError = {code: ERROR_INTERNAL_ERROR, data: undefined};
const successCallbackError: BusinessError = {code: ERROR_OK, data: undefined};

const errorParamInvalid: BusinessError = {code: ERROR_PARAM_INVALID, message: "Invalid parameter"};

export default namespace notificationManager {
    loadLibrary("notification_manager_ani.z")
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

    export native function nativeCancelAll(): void;
    export native function nativeCancelWithId(id: int): void;
    export native function nativeCancelWithIdLabel(id: int, label: string): void;
    export native function nativeCancelWithIdOptionalLabel(id: int, label?: string): void;
    export native function nativeCancelWithBundle(bundle: BundleOption, id: int): void;

    export native function nativeDisplayBadge(bundle: BundleOption, enable: boolean): void;
    export native function nativeIsBadgeDisplayed(bundle: BundleOption): boolean;
    export native function nativeSetBadgeNumber(badgeNumber: int): void;
    export native function nativeSetBadgeNumberByBundle(bundle: BundleOption, badgeNumber: int): void;

    export native function nativeGetActiveNotificationCount(): long;
    export native function nativeGetActiveNotifications():Array<NotificationRequest>;
    export native function nativeGetAllActiveNotifications():Array<NotificationRequest>;
    export native function nativeGetActiveNotificationByFilter(filter: NotificationFilter): NotificationRequest|null;

    export native function nativeAddDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;
    export native function nativeRemoveDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;

    export native function nativeSubscribeSystemLiveView(subscriber: SystemLiveViewSubscriber): void;
    export native function nativeTriggerSystemLiveView(
        bundle: BundleOption, notificationId: int, buttonOptions: ButtonOptions): void;

    export native function nativePublishWithUserId(request: NotificationRequest, userId: int):void;
    export native function nativePublish(request: NotificationRequest):void;

    export native function nativeGetSlotFlagsByBundle(bundle: BundleOption): long;
    export native function nativeSetSlotFlagsByBundle(bundle: BundleOption, slotFlags: long): void;
    export native function nativeGetSlotsByBundle(bundle: BundleOption): Array<NotificationSlot>;
    export native function nativeGetSlotByBundle(bundle: BundleOption, type: SlotType): NotificationSlot|null;

    export native function nativeIsNotificationSlotEnabled(bundle: BundleOption, type: SlotType): boolean;
    export native function nativeSetNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean): void;
    export native function nativeSetNotificationEnableSlotWithForce(
        bundle: BundleOption, type: SlotType, enable: boolean, isForceControl: boolean): void;

    export native function nativeIsNotificationEnabled(): boolean;
    export native function nativeIsNotificationEnabledWithId(userId : int): boolean;
    export native function nativeIsNotificationEnabledWithBundleOption(bundleOption: BundleOption): boolean;
    export native function nativeSetNotificationEnable(bundle: BundleOption, enable: boolean): void;
    export native function nativeRequestEnableNotification(content: UIAbilityContext): Promise<int>;
    export native function nativeGetAllNotificationEnabledBundles(): Array<BundleOption>;
    export native function nativeIsNotificationEnabledSync(): boolean;

    export native function  nativeRemoveGroupByBundle(bundle: BundleOption, groupName: string): void;

    export native function nativeAddSlotByNotificationSlot(slot: NotificationSlot): void;
    export native function nativeAddSlotBySlotType(type: SlotType): void;
    export native function nativeAddSlots(slots: Array<NotificationSlot>): void;
    export native function nativeGetSlot(slotType: SlotType): NotificationSlot|null;
    export native function nativeGetSlots(): Array<NotificationSlot>;
    export native function nativeRemoveSlot(slotType: SlotType): void;
    export native function nativeRemoveAllSlots(): void;
    export native function nativeSetSlotByBundle(bundle: BundleOption, slot: NotificationSlot): void;
    export native function nativeGetSlotNumByBundle(bundle: BundleOption): long;
    export native function nativeIsSupportTemplate(templateName: string): boolean;
    export native function nativeSetDistributedEnable(enable: boolean): void;
    export native function nativeIsDistributedEnabled(): boolean;
    export native function nativeIsDistributedEnabledByBundle(bundle: BundleOption): boolean;
    export native function nativeIsDistributedEnabledByBundleType(bundle: BundleOption, deviceType: string): boolean;
    export native function nativeGetDeviceRemindType(): DeviceRemindType;
    export native function nativeSetSyncNotificationEnabledWithoutApp(userId: int, enable: boolean): void;
    export native function nativeGetSyncNotificationEnabledWithoutApp(userId: int): boolean;

    export native function nativePublishAsBundle(request: NotificationRequest, representativeBundle: string, userId: int): void;
    export native function nativePublishAsBundleWithBundleOption(representativeBundle: BundleOption, request: NotificationRequest): void;
    export native function nativeCancelAsBundle(id: int, representativeBundle: string, userId: int): void;
    export native function nativeCancelAsBundleWithBundleOption(representativeBundle: BundleOption, id: int): void;
    export native function nativeCancelGroup(groupName: string): void;
    export native function nativeSetDoNotDisturbDate(date: DoNotDisturbDate): void;
    export native function nativeSetDoNotDisturbDateWithId(date: DoNotDisturbDate, userId: int): void;
    export native function nativeGetDoNotDisturbDate(): DoNotDisturbDate;
    export native function nativeGetDoNotDisturbDateWithId(userId: int): DoNotDisturbDate;
    export native function nativeIsSupportDoNotDisturbMode(): boolean;
    export native function nativeGetDoNotDisturbProfile(id: long): DoNotDisturbProfile;

    export native function nativeOpenNotificationSettings(content: UIAbilityContext): Promise<int>;

    export native function nativesetTargetDeviceStatus(deviceType: string, status: long): void;
    export native function nativesetDistributedEnabledByBundle(bundle: BundleOption, deviceType: string, enable: boolean): void;
    export native function nativesetSmartReminderEnabled(deviceType: string, enable: boolean): void;
    export native function nativeisSmartReminderEnabled(deviceType: string): boolean;
    export native function nativesetDistributedEnabledBySlot(slot: SlotType, deviceType: string, enabled: boolean): void;
    export native function nativeisDistributedEnabledBySlot(slot: SlotType, deviceType: string): boolean;
    export native function nativesetAdditionalConfig(key: string, value: string): int;
    export native function nativesetDistributedEnableByBundle(bundle: BundleOption, enable: boolean):void;
    export native function nativedisableNotificationFeature(disabled:boolean, bundleList: Array<string>):void;
    export native function nativeOn(
        type: 'checkNotification', callback: CallbackForCheckInfo, checkRequest?: NotificationCheckRequest): int;
    export native function nativeOff(
        type: 'checkNotification', callback?: CallbackForCheckInfo): int;
    export native function nativeGetNotificationSetting(): NotificationSetting;

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
        if (bundle.bundle == null || bundle.bundle?.length === 0) {
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
        let pPromise = new Promise<long>((resolve: ResolveCallback<long>, reject: RejectCallback): void => {
            let p = taskpool.execute((): long => { return nativeGetSlotNumByBundle(bundle); });
            p.then((data: NullishType): void => {
                let ret : long = data as long;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlotNumByBundle(bundle: BundleOption, callback: AsyncCallback<long>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): long => { return nativeGetSlotNumByBundle(bundle); });
        p.then((data: NullishType): void => {
            let ret : long = data as long;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
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
        let p = taskpool.execute((): void => { nativeSetSlotByBundle(bundle, slot); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetSlotByBundle(bundle, slot); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function removeAllSlots(callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeRemoveAllSlots(); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function removeAllSlots(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeRemoveAllSlots(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function removeSlot(slotType: SlotType, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeRemoveSlot(slotType); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function removeSlot(slotType: SlotType): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeRemoveSlot(slotType); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlots(): Promise<Array<NotificationSlot>> {
        let pPromise = new Promise<Array<NotificationSlot>>((resolve: ResolveCallback<Array<NotificationSlot>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlots(); });
            p.then((data: NullishType): void => {
                let ret : Array<NotificationSlot> = data as Array<NotificationSlot>;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlots(callback: AsyncCallback<Array<NotificationSlot>>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlots(); });
        p.then((data: NullishType): void => {
            let ret : Array<NotificationSlot> = data as Array<NotificationSlot>;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function getSlot(slotType: SlotType): Promise<NotificationSlot|null> {
        let pPromise = new Promise<NotificationSlot|null>((resolve: ResolveCallback<NotificationSlot|null>, reject: RejectCallback): void => {
            let p = taskpool.execute((): NotificationSlot|null => { return nativeGetSlot(slotType); });
            p.then((data: NullishType): void => {
                resolve(data as NotificationSlot|null);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlot(slotType: SlotType, callback: AsyncCallback<NotificationSlot|null>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): NotificationSlot|null => { return nativeGetSlot(slotType); });
        p.then((data: NullishType): void => {
            callback(null, data as NotificationSlot|null);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function getSlotByBundle(bundle: BundleOption, slotType: SlotType): Promise<NotificationSlot|null> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<NotificationSlot|null>((resolve: ResolveCallback<NotificationSlot|null>, reject: RejectCallback): void => {
            let p = taskpool.execute((): NotificationSlot|null => { return nativeGetSlotByBundle(bundle, slotType); });
            p.then((data: NullishType): void => {
                resolve(data as NotificationSlot|null);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function addSlots(slots: Array<NotificationSlot>): Promise<void> {
        if (!slots || slots.length === 0) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeAddSlots(slots); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function addSlots(slots: Array<NotificationSlot>, callback: AsyncCallback<void>): void {
        if (!slots || slots.length === 0) {
            throw errorParamInvalid;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeAddSlots(slots); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function addSlot(slot: NotificationSlot): Promise<void> {
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeAddSlotByNotificationSlot(slot); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function addSlot(slot: NotificationSlot, callback: AsyncCallback<void>): void {
        let slotError: BusinessError = isInvalidParameter(slot);
        if (slotError.code !== ERROR_OK) {
            throw slotError;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeAddSlotByNotificationSlot(slot); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function addSlot(type: SlotType, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeAddSlotBySlotType(type); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function addSlot(type: SlotType): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeAddSlotBySlotType(type); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setNotificationEnable(bundle: BundleOption, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetNotificationEnable(bundle, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): void => { nativeSetNotificationEnable(bundle, enable); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
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
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithBundleOption(bundleOption); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isNotificationEnabled(bundleOption: BundleOption): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundleOption);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute(
                (): boolean => { return nativeIsNotificationEnabledWithBundleOption(bundleOption);
                });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabled(userId: int, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithId(userId); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isNotificationEnabled(userId: int): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithId(userId); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabled(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isNotificationEnabled(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute(
            (): void => { nativeSetNotificationEnableSlotWithForce(bundle, type, enable, isForceControl);
        });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, isForceControl?: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let forceControl: boolean = false;
        if (isForceControl != undefined) {
            forceControl = isForceControl;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute(
                (): void => { nativeSetNotificationEnableSlotWithForce(bundle, type, enable, forceControl);
                });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeSetNotificationEnableSlot(bundle, type, enable); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationSlotEnabled(bundle, type); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): boolean => { return nativeIsNotificationSlotEnabled(bundle, type); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
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
        let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
        p.then((data: NullishType): void => {
            let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
            callback(null, slots);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getSlotsByBundle(bundle: BundleOption): Promise<Array<NotificationSlot>>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<Array<NotificationSlot>>(
            (resolve: ResolveCallback<Array<NotificationSlot>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
            p.then((data: NullishType): void => {
                let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
                resolve(slots);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setSlotFlagsByBundle(bundle: BundleOption, slotFlags: long): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetSlotFlagsByBundle(bundle, slotFlags); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlotFlagsByBundle(bundle: BundleOption): Promise<long> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<long>((resolve: ResolveCallback<long>, reject: RejectCallback): void => {
            let p = taskpool.execute((): long => { return nativeGetSlotFlagsByBundle(bundle); });
            p.then((data: NullishType): void => {
                let ret : long = data as long;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function publish(request: NotificationRequest, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativePublish(request); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function publish(request: NotificationRequest): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativePublish(request); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function publish(request: NotificationRequest, userId: int, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativePublishWithUserId(request, userId); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function publish(request: NotificationRequest, userId: int): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativePublishWithUserId(request, userId); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => {
                nativeTriggerSystemLiveView(bundle, notificationId, buttonOptions);
            });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function subscribeSystemLiveView(subscriber: SystemLiveViewSubscriber): Promise<void>
    {
        if(subscriber === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSubscribeSystemLiveView(subscriber); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function removeDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeRemoveDoNotDisturbProfile(templates); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function addDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeAddDoNotDisturbProfile(templates); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getAllActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetAllActiveNotifications(); });
        p.then((data: NullishType): void => {
            let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getAllActiveNotifications(): Promise<Array<NotificationRequest>> {
        let pPromise
        = new Promise<Array<NotificationRequest>>(
            (resolve: ResolveCallback<Array<NotificationRequest>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetAllActiveNotifications(); });
            p.then((data: NullishType): void => {
		    	let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getActiveNotifications(): Promise<Array<NotificationRequest>> {
        let pPromise = new Promise<Array<NotificationRequest>>((resolve: ResolveCallback<Array<NotificationRequest>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetActiveNotifications(); });
            p.then((data: NullishType): void => {
		    	let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetActiveNotifications(); });
        p.then((data: NullishType): void => {
            let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getActiveNotificationCount(callback: AsyncCallback<long>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): long => { return nativeGetActiveNotificationCount(); });
        p.then((data: NullishType): void => {
            let ret : long = data as long;
            callback(null, ret);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getActiveNotificationCount(): Promise<long> {
        let pPromise = new Promise<long>((resolve: ResolveCallback<long>, reject: RejectCallback):void => {
            let p = taskpool.execute((): long => { return nativeGetActiveNotificationCount(); });
            p.then((data :NullishType): void => {
                let ret : long = data as long;
                resolve(ret);
            }, (err:Error): void => {
                reject(err);
            });
        });
        return pPromise;
    }

    export function displayBadge(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeDisplayBadge(bundle, enable); });
        p.then((e: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function displayBadge(bundle: BundleOption, enable: boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeDisplayBadge(bundle, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isBadgeDisplayed(bundle: BundleOption, callback: AsyncCallback<boolean>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isBadgeDisplayed(bundle: BundleOption): Promise<boolean> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(bundle: BundleOption, id: int): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelWithBundle(bundle, id); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(id: int, label?: string): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelWithIdOptionalLabel(id, label); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(id: int, label: string, callback: AsyncCallback<void>): void {
        if (label == null || label?.length === 0) {
            throw errorParamInvalid;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeCancelWithIdLabel(id, label); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function cancel(id: int, callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeCancelWithId(id); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function cancelAll(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelAll(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancelAll(callback: AsyncCallback<void>): void {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeCancelAll(); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
    	    let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function requestEnableNotification(context: UIAbilityContext): Promise<void>
    {
        if (context == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => { return nativeRequestEnableNotification(context); });
            p.then(
                (data: NullishType): void => {
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
            (data: NullishType): void => {
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
                    (e: NullishType): void => {
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
        let pPromise = new Promise<Array<BundleOption>>(
            (resolve: ResolveCallback<Array<BundleOption>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<BundleOption> => { return nativeGetAllNotificationEnabledBundles(); });
            p.then((data: NullishType): void => {
                let options : Array<BundleOption> = data as Array<BundleOption>;
                resolve(options);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabledSync(): boolean
    {
        return nativeIsNotificationEnabledSync();
    }

    export function setBadgeNumber(badgeNumber: int, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
           throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeSetBadgeNumber(badgeNumber); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function setBadgeNumber(badgeNumber: int): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetBadgeNumber(badgeNumber); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setBadgeNumberByBundle(bundle: BundleOption, badgeNumber: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetBadgeNumberByBundle(bundle, badgeNumber); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): NotificationRequest|null => { return nativeGetActiveNotificationByFilter(filter); });
        p.then((data: NullishType): void => {
            callback(null, data as NotificationRequest|null);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getActiveNotificationByFilter(filter: NotificationFilter): Promise<NotificationRequest|null>
    {
        let error: BusinessError = isInvalidParameter(filter);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<NotificationRequest|null>((resolve: ResolveCallback<NotificationRequest|null>, reject: RejectCallback): void => {
            let p = taskpool.execute((): NotificationRequest|null => { return nativeGetActiveNotificationByFilter(filter); });
            p.then((data: NullishType): void => {
                resolve(data as NotificationRequest|null);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isSupportTemplate(templateName: string): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsSupportTemplate(templateName); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): void => { nativeRemoveGroupByBundle(bundle, groupName); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeRemoveGroupByBundle(bundle, groupName); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): void => { nativePublishAsBundle(request, representativeBundle, userId); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativePublishAsBundle(request, representativeBundle, userId); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativePublishAsBundleWithBundleOption(representativeBundle, request); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancelAsBundle(id: int, representativeBundle: string, userId: int, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeCancelAsBundle(id, representativeBundle, userId); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function cancelAsBundle(id: int, representativeBundle: string, userId: int): Promise<void>
    {
        if (representativeBundle == null || representativeBundle?.length === 0) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelAsBundle(id, representativeBundle, userId); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancelAsBundle(representativeBundle: BundleOption, id: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(representativeBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }

        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelAsBundleWithBundleOption(representativeBundle, id); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancelGroup(groupName: string, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        if (groupName == null || groupName?.length === 0) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeCancelGroup(groupName); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function cancelGroup(groupName: string): Promise<void>
    {
        if (groupName == null || groupName?.length === 0) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeCancelGroup(groupName); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): void => { nativeSetDoNotDisturbDate(date); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetDoNotDisturbDate(date); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): void => { nativeSetDoNotDisturbDateWithId(date, userId); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setDoNotDisturbDate(date: DoNotDisturbDate, userId: int): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(date);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetDoNotDisturbDateWithId(date, userId); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getDoNotDisturbDate(callback: AsyncCallback<DoNotDisturbDate>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): DoNotDisturbDate => { return nativeGetDoNotDisturbDate(); });
        p.then((data: NullishType): void => {
            let doNotDisturbDate : DoNotDisturbDate = data as DoNotDisturbDate;
            callback(null, doNotDisturbDate);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getDoNotDisturbDate(): Promise<DoNotDisturbDate>
    {
        let pPromise = new Promise<DoNotDisturbDate>((resolve: ResolveCallback<DoNotDisturbDate>, reject: RejectCallback): void => {
            let p = taskpool.execute((): DoNotDisturbDate => { return nativeGetDoNotDisturbDate(); });
            p.then((data: NullishType): void => {
                let doNotDisturbDate : DoNotDisturbDate = data as DoNotDisturbDate;
                resolve(doNotDisturbDate);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getDoNotDisturbDate(userId: int, callback: AsyncCallback<DoNotDisturbDate>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): DoNotDisturbDate => { return nativeGetDoNotDisturbDateWithId(userId); });
        p.then((data: NullishType): void => {
            let doNotDisturbDate : DoNotDisturbDate = data as DoNotDisturbDate;
            callback(null, doNotDisturbDate);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function getDoNotDisturbDate(userId: int): Promise<DoNotDisturbDate>
    {
        let pPromise = new Promise<DoNotDisturbDate>((resolve: ResolveCallback<DoNotDisturbDate>, reject: RejectCallback): void => {
            let p = taskpool.execute((): DoNotDisturbDate => { return nativeGetDoNotDisturbDateWithId(userId); });
            p.then((data: NullishType): void => {
                let doNotDisturbDate : DoNotDisturbDate = data as DoNotDisturbDate;
                resolve(doNotDisturbDate);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isSupportDoNotDisturbMode(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeIsSupportDoNotDisturbMode(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isSupportTemplate(templateName: string, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeIsSupportTemplate(templateName); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isSupportDoNotDisturbMode(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsSupportDoNotDisturbMode(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getDoNotDisturbProfile(id: long): Promise<DoNotDisturbProfile>
    {
        let pPromise = new Promise<DoNotDisturbProfile>((resolve: ResolveCallback<DoNotDisturbProfile>, reject: RejectCallback): void => {
            let p = taskpool.execute((): DoNotDisturbProfile => { return nativeGetDoNotDisturbProfile(id); });
            p.then((data: NullishType): void => {
                let ret : DoNotDisturbProfile = data as DoNotDisturbProfile;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function openNotificationSettings(context: UIAbilityContext): Promise<void>
    {
        if (context == undefined || context === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => { return nativeOpenNotificationSettings(context); });
            p.then(
                (data: NullishType): void => {
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { nativesetTargetDeviceStatus(deviceType,status); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Error): void => {
            reject(error);
        });
        });
        return pPromise;
    }

	export function setDistributedEnabledByBundle(bundle: BundleOption, deviceType: string, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativesetDistributedEnabledByBundle(bundle, deviceType, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }


    export function setDistributedEnableByBundle(bundle: BundleOption, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativesetDistributedEnableByBundle(bundle, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setSmartReminderEnabled(deviceType: string, enable: boolean): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativesetSmartReminderEnabled(deviceType, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isSmartReminderEnabled(deviceType: string): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeisSmartReminderEnabled(deviceType); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setDistributedEnabledBySlot(slot: SlotType, deviceType: string, enabled: boolean): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => {
                nativesetDistributedEnabledBySlot(slot, deviceType, enabled);
            });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isDistributedEnabledBySlot(slot: SlotType, deviceType: string): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeisDistributedEnabledBySlot(slot, deviceType); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setAdditionalConfig(key: string, value: string): Promise<int>{
        let pPromise = new Promise<int>((resolve: ResolveCallback<int>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return nativesetAdditionalConfig(key,value); });
            p.then((data: NullishType): void => {
                let ret : int = data as int;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => {
                nativedisableNotificationFeature(disabled,bundleList);
            });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setDistributedEnableByBundle(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativesetDistributedEnableByBundle(bundle, enable); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setDistributedEnable(enable: boolean, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { nativeSetDistributedEnable(enable); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setDistributedEnable(enable: boolean): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { nativeSetDistributedEnable(enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isDistributedEnabled(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsDistributedEnabled(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isDistributedEnabled(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeIsDistributedEnabled(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isDistributedEnabledByBundle(bundle: BundleOption): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsDistributedEnabledByBundle(bundle); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
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
        let p = taskpool.execute((): boolean => { return nativeIsDistributedEnabledByBundle(bundle); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isDistributedEnabledByBundle(bundle: BundleOption, deviceType: string): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsDistributedEnabledByBundleType(bundle, deviceType); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getDeviceRemindType(): Promise<DeviceRemindType>
    {
        let pPromise = new Promise<DeviceRemindType>(
            (resolve: ResolveCallback<DeviceRemindType>, reject: RejectCallback): void => {
            let p = taskpool.execute((): DeviceRemindType => { return nativeGetDeviceRemindType(); });
            p.then((data: NullishType): void => {
                let ret : DeviceRemindType = data as DeviceRemindType;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getDeviceRemindType(callback: AsyncCallback<DeviceRemindType>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): DeviceRemindType => { return nativeGetDeviceRemindType(); });
        p.then((data: NullishType): void => {
            let ret : DeviceRemindType = data as DeviceRemindType;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function setSyncNotificationEnabledWithoutApp
        (userId: int, enable: boolean, callback: AsyncCallback<void>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void =>
            { nativeSetSyncNotificationEnabledWithoutApp(userId, enable); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function setSyncNotificationEnabledWithoutApp(userId: int, enable: boolean): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void =>
                { nativeSetSyncNotificationEnabledWithoutApp(userId, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSyncNotificationEnabledWithoutApp(userId: int): Promise<boolean> {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean =>
                { return nativeGetSyncNotificationEnabledWithoutApp(userId); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSyncNotificationEnabledWithoutApp(userId: int, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): boolean => { return nativeGetSyncNotificationEnabledWithoutApp(userId); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function getNotificationSetting(): Promise<NotificationSetting> {
        let pPromise = new Promise<NotificationSetting>(
            (resolve: ResolveCallback<NotificationSetting>, reject: RejectCallback): void => {
            let p = taskpool.execute((): NotificationSetting =>
                { return nativeGetNotificationSetting(); });
            p.then((data: NullishType): void => {
                let ret : NotificationSetting = data as NotificationSetting;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }
}
