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
import { BusinessError, AsyncCallback } from '@ohos.base';
import { NotificationSlot } from 'notification.notificationSlot';
import { NotificationRequest } from 'notification.notificationRequest';
import UIAbilityContext from 'application.UIAbilityContext';
import { NotificationBasicContent } from 'notification.notificationContent';
import { NotificationLongTextContent } from 'notification.notificationContent';
import { NotificationMultiLineContent } from 'notification.notificationContent';
import { NotificationPictureContent } from 'notification.notificationContent';
import { NotificationSystemLiveViewContent } from 'notification.notificationContent';
import { NotificationTemplate } from 'notification.notificationTemplate';
import { DistributedOptions } from 'notification.notificationRequest';
import { NotificationLiveViewContent } from 'notification.notificationContent';
import { UnifiedGroupInfo } from 'notification.notificationRequest';
import image from '@ohos.multimedia.image';

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Object) => void;

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

    export interface DoNotDisturbProfile {
        id: number;
        name: string;
        trustlist?: Array<BundleOption>;
    }

    class DoNotDisturbProfileInner implements DoNotDisturbProfile {
        id: number = -1;
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
        onResponse?: (notificationId: number, buttonOptions: ButtonOptions) => void;
    }

    class SystemLiveViewSubscriberInner implements SystemLiveViewSubscriber {
        onResponse?: (notificationId: number, buttonOptions: ButtonOptions) => void;
    }

    export native function nativeCancelAll(): void;
    export native function nativeCancelWithId(id: number): void;
    export native function nativeCancelWithIdLabel(id: number, label: string): void;
    export native function nativeCancelWithIdOptionalLabel(id: number, label?: string): void;
    export native function nativeCancelWithBundle(bundle: BundleOption, id: number): void;

    export native function nativeDisplayBadge(bundle: BundleOption, enable: boolean): void;
    export native function nativeIsBadgeDisplayed(bundle: BundleOption): boolean;

    export native function nativeGetActiveNotificationCount(): number;
    export native function nativeGetActiveNotifications():Array<NotificationRequest>;
    export native function nativeGetAllActiveNotifications():Array<NotificationRequest>;

    export native function nativeAddDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;
    export native function nativeRemoveDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;

    export native function nativeSubscribeSystemLiveView(subscriber: SystemLiveViewSubscriber): void;
    export native function nativeTriggerSystemLiveView(
        bundle: BundleOption, notificationId: number, buttonOptions: ButtonOptions): void;

    export native function nativePublishWithUserId(request: NotificationRequest, userId: number):void;
    export native function nativePublish(request: NotificationRequest):void;

    export native function nativeGetSlotFlagsByBundle(bundle: BundleOption): int;
    export native function nativeSetSlotFlagsByBundle(bundle: BundleOption, slotFlags: number): void;
    export native function nativeGetSlotsByBundle(bundle: BundleOption): Array<NotificationSlot>;

    export native function nativeIsNotificationSlotEnabled(bundle: BundleOption, type: SlotType): boolean;
    export native function nativeSetNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean): void;
    export native function nativeSetNotificationEnableSlotWithForce(
        bundle: BundleOption, type: SlotType, enable: boolean, isForceControl: boolean): void;

    export native function nativeIsNotificationEnabled(): boolean;
    export native function nativeIsNotificationEnabledWithId(userId : number): boolean;
    export native function nativeIsNotificationEnabledWithBundleOption(bundleOption: BundleOption): boolean;
    export native function nativeSetNotificationEnable(bundle: BundleOption, enable: boolean): void;
    export native function nativeRequestEnableNotification(content: UIAbilityContext): Promise<int>;

    function isInvalidParameter(bundle: BundleOption): BusinessError
    {
        let error: BusinessError = {
            code: 0,
            message: ""
        }
        if (bundle == null) {
            error = {
                code: 401,
                message: "BundleOption must be not Null"
            }
            return error;
        }
        if (bundle.bundle == null || bundle.bundle?.length === 0) {
            error = {
                code: 401,
                message: "Incorrect parameter types. The type of bundle must be string."
            }
            return error;
        }
        return error;
    }

    function isInvalidParameter(option: ButtonOptions): BusinessError
    {
        let error: BusinessError = {
            code: 0,
            message: ""
        }
        if (option == null) {
            error = {
                code: 401,
                message: "ButtonOptions must be not Null"
            }
            return error;
        }
        if (option.buttonName == null || option.buttonName?.length === 0) {
            error = {
                code: 401,
                message: "Incorrect parameter types. The type of buttonName must be string."
            }
            return error;
        }
        return error;
    }
    function isInvalidContent(normal?: NotificationBasicContent): boolean
    {
        if(normal === null) {
			return false;
		}
		if(!normal?.title || normal?.title?.trim() === '') {
			return false;
		}
		if(!normal?.text || normal?.text?.trim() === '') {
			return false;
		}
		if(normal?.additionalText !== undefined && normal?.additionalText?.trim() === '') {
			return false;
		}
		if(normal?.lockscreenPicture != undefined && !(normal?.lockscreenPicture instanceof image.PixelMap)) {
			return false;
		}
        
        return true;
    }
    function isInvalidLongText(longText?: NotificationLongTextContent): boolean
    {
        if(longText === null) {
			return false;
		}
		if(!longText?.longText || longText?.longText?.trim() === '') {
			return false;
		}
		if(!longText?.briefText || longText?.briefText?.trim() === '') {
			return false;
		}
		if(!longText?.expandedTitle || longText?.expandedTitle?.trim() === '') {
			return false;
		}
        return true;
    }
    function isInvalidMultiLine(multiLine?: NotificationMultiLineContent): boolean
    {
        if(multiLine === null) {
			return false
		}
		if(!multiLine?.briefText || multiLine?.briefText.trim() === '') {
			return false;
		}
		if(!multiLine?.longTitle || multiLine?.longTitle.trim() === '') {
			return false;
		}
		if(multiLine?.lines?.length === 0) {
			return false;
		}
        
        return true;
    }
    function isInvalidPicture(picture?: NotificationPictureContent): boolean
    {
        if(picture === null) {
			return false;
		}
		if(!picture?.briefText || picture?.briefText?.trim() === '') {
			return false;
		}
		if(!picture?.expandedTitle || picture?.expandedTitle?.trim() === '') {
			return false;
		}
		if(!(picture?.picture instanceof image.PixelMap)) {
			return false;
		}
        return true;
    }
    function isInvalidSystemLiveView(systemLiveView?: NotificationSystemLiveViewContent): boolean
    {
        if(systemLiveView === null) {
			return false
		}
		if(systemLiveView?.capsule !== undefined && systemLiveView?.capsule === null) {
			return false
		}
		if(systemLiveView?.capsule?.title !== undefined && systemLiveView?.capsule?.title?.trim() === '') {
			return false;
		}
		if(systemLiveView?.capsule?.icon != undefined && !(systemLiveView?.capsule?.icon instanceof image.PixelMap)) {
			return false;
		}
		if(systemLiveView?.capsule?.backgroundColor != undefined && systemLiveView?.capsule?.backgroundColor?.trim() === '') {
			return false;
		}
		if(systemLiveView?.capsule?.content != undefined && systemLiveView?.capsule?.content?.trim() === '') {
			return false;
		}
		if(systemLiveView?.capsule?.capsuleButtons != undefined && systemLiveView?.capsule?.capsuleButtons?.length === 0) {
			return false;
		}
		if(systemLiveView?.button !== undefined && systemLiveView?.button === null) {
			return false;
		}
		if(systemLiveView?.button?.names != undefined && systemLiveView?.button?.names?.length === 0) {
			return false;
		}
		if(systemLiveView?.button?.icons != undefined && systemLiveView?.button?.icons?.length === 0) {
			return false;
		}
		if(systemLiveView?.button?.iconsResource != undefined && systemLiveView?.button?.iconsResource?.length === 0) {
			return false;
		}
		
		if(systemLiveView?.cardButtons !== undefined && systemLiveView?.cardButtons?.length === 0) {
			return false;
		}
        
        return true;
    }
    function isInvalidLiveView(liveView?: NotificationLiveViewContent): boolean
    {
        if(liveView === null) {
			return false;
		}
		if(liveView?.extraInfo !== undefined && liveView?.extraInfo === null) {
			return false;
		}
		if(liveView?.pictureInfo !== undefined && liveView?.pictureInfo === null) {
			return false;
		}
        return true;
    }
    function isInvalidTemplate(template?: NotificationTemplate): boolean
    {
        if(template === null) {
			return false;
		}
		if(template?.name != undefined && template?.name?.trim() === '') {
			return false;
		}
		if(template?.data != undefined && template?.data === null) {
			return false;
		}
        return true;
    }
    function isInvalidDistributedOption(distributedOption?: DistributedOptions): boolean
    {
        if(distributedOption === null) {
			return false
		}
		if(distributedOption?.supportDisplayDevices != undefined && distributedOption?.supportDisplayDevices?.length === 0) {
			return false;
		}
		if(distributedOption?.supportOperateDevices != undefined && distributedOption?.supportOperateDevices?.length === 0) {
			return false;
		}
        return true;
    }
    function isInvalidUnifiedGroupInfo(unifiedGroupInfo?: UnifiedGroupInfo): boolean
    {
        if(unifiedGroupInfo === null) {
			return false;
		}
		if(unifiedGroupInfo?.key != undefined && unifiedGroupInfo?.key?.trim() === '') {
			return false;
		}
		if(unifiedGroupInfo?.title != undefined && unifiedGroupInfo?.title?.trim() === '') {
			return false;
		}
		if(unifiedGroupInfo?.content != undefined && unifiedGroupInfo?.content?.trim() === '') {
			return false;
		}
		if(unifiedGroupInfo?.sceneName != undefined && unifiedGroupInfo?.sceneName?.trim() === '') {
			return false;
		}
		if(unifiedGroupInfo?.extraInfo != undefined && unifiedGroupInfo?.extraInfo == null) {
			return false;
		}
        return true;
    }
    function isInvalidBundleOption(bundleOption?: BundleOption): boolean
    {
        if(bundleOption === null) {
			return false;
		}
		if(bundleOption?.bundle != undefined && bundleOption?.bundle?.trim() === '') {
			return false;
		}
        return true;
    }
    function isInvalidParameter(request: NotificationRequest): BusinessError
    {
        let error: BusinessError = {
            code: 0,
            message: ""
        }
        if (request == null) {
            error = {
                code: 401,
                message: "request must be not Null"
            }
            return error;
        }
        if(request.content == null || request.content == undefined) {
            error = {
                code: 401,
                message: "request.content must be not Null"
            }
            return error;
        }
        if(request.content?.normal !== undefined && !isInvalidContent(request.content.normal)) {
            return errorParamInvalid;
        }
        if(request.content?.longText !== undefined && !isInvalidLongText(request.content.longText)) {
            return errorParamInvalid;
        }
        if(request.content?.multiLine !== undefined && !isInvalidMultiLine(request.content.multiLine)) {
            return errorParamInvalid;
        }
        if(request.content?.picture !== undefined && !isInvalidPicture(request.content.picture)) {
            return errorParamInvalid;
        }
        if(request.content?.systemLiveView !== undefined && !isInvalidSystemLiveView(request.content.systemLiveView)) {
            return errorParamInvalid;
        }
        if(request.content?.liveView !== undefined && !isInvalidLiveView(request.content.liveView)) {
            return errorParamInvalid;
        }
        if(request?.appMessageId !== undefined && request?.appMessageId?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.wantAgent !== undefined && request.wantAgent == null) {
            return errorParamInvalid;
        }
        if(request?.extraInfo !== undefined && request?.extraInfo == null) {
            return errorParamInvalid;
        }
        if(request?.actionButtons !== undefined && request?.actionButtons?.length === 0) {
            return errorParamInvalid;
        }
        if(request.smallIcon !== undefined && request.smallIcon == null) {
            return errorParamInvalid;
        }
        if(request?.largeIcon !== undefined && request.largeIcon == null) {
            return errorParamInvalid;
        }
        if(request?.overlayIcon !== undefined && request.overlayIcon == null) {
            return errorParamInvalid;
        }
        if(request?.groupName !== undefined && request?.groupName?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.creatorBundleName !== undefined && request?.creatorBundleName?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.sound !== undefined && request?.sound?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.classification !== undefined && request?.classification?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.hashCode !== undefined && request?.hashCode?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.template !== undefined && !isInvalidTemplate(request.template)) {
            return errorParamInvalid;
        }
        if(request?.distributedOption !== undefined && !isInvalidDistributedOption(request.distributedOption)) {
            return errorParamInvalid;
        }
        if(request?.deviceId !== undefined && request?.deviceId?.trim() === '') {
            return errorParamInvalid;
        }
        if(request?.removalWantAgent !== undefined && request.removalWantAgent == null) {
            return errorParamInvalid;
        }
        if(request?.representativeBundle !== undefined && !isInvalidBundleOption(request.representativeBundle)) {
            return errorParamInvalid;
        }
        if(request?.agentBundle !== undefined && !isInvalidBundleOption(request.agentBundle)) {
            return errorParamInvalid;
        }
        if (request?.unifiedGroupInfo !== undefined && !isInvalidUnifiedGroupInfo(request.unifiedGroupInfo)) {
            return errorParamInvalid;
        }
        if(request?.appInstanceKey !== undefined && request?.appInstanceKey?.trim() === '') {
            return errorParamInvalid;
        }
        return error;
    }

    export function setNotificationEnable(bundle: BundleOption, enable: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeSetNotificationEnable(bundle, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }
    
    export function setNotificationEnable(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeSetNotificationEnable(bundle, enable); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function isNotificationEnabled(bundleOption: BundleOption, callback: AsyncCallback<boolean>): void
    {
        let error: BusinessError = isInvalidParameter(bundleOption);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithBundleOption(bundleOption); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(bundleOption: BundleOption): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundleOption);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute(
                (): boolean => { return nativeIsNotificationEnabledWithBundleOption(bundleOption);
                });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabled(userId: number, callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            let error: BusinessError = {
                code: 410,
                message : "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithId(userId); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(userId: number): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabledWithId(userId); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabled(callback: AsyncCallback<boolean>): void
    {
        if (callback == null) {
            let error: BusinessError = {
                code: 410,
                message : "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Object): void => {
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
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute(
            (): void => { return nativeSetNotificationEnableSlotWithForce(bundle, type, enable, isForceControl);
        });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, isForceControl?: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let forceControl: boolean = false;
        if (isForceControl != undefined) {
            forceControl = isForceControl;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute(
                (): void => { return nativeSetNotificationEnableSlotWithForce(bundle, type, enable, forceControl);
                });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setNotificationEnableSlot(
        bundle: BundleOption, type: SlotType, enable: boolean, callback: AsyncCallback<void>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeSetNotificationEnableSlot(bundle, type, enable); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType): Promise<boolean>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsNotificationSlotEnabled(bundle, type); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType, callback: AsyncCallback<boolean>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsNotificationSlotEnabled(bundle, type); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
             let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function getSlotsByBundle(bundle: BundleOption, callback: AsyncCallback<Array<NotificationSlot>>): void
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
        p.then((data: NullishType): void => {
            let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, slots);
        }, (error: Object): void => {
            let slots : Array<NotificationSlot> = [];
            let err: BusinessError = error as BusinessError;
            callback(err, slots);
        })             
    }
    
    export function getSlotsByBundle(bundle: BundleOption): Promise<Array<NotificationSlot>>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<Array<NotificationSlot>>(
            (resolve: ResolveCallback<Array<NotificationSlot>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
            p.then((data: NullishType): void => {
                let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
                resolve(slots);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setSlotFlagsByBundle(bundle: BundleOption, slotFlags: number): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeSetSlotFlagsByBundle(bundle, slotFlags); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSlotFlagsByBundle(bundle: BundleOption): Promise<number> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<number>((resolve: ResolveCallback<number>, reject: RejectCallback): void => {
            let p = taskpool.execute((): number => { return nativeGetSlotFlagsByBundle(bundle); });
            p.then((data: NullishType): void => {
                let ret : Double = data as Double;
                resolve(ret);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function publish(request: NotificationRequest, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): void => { return nativePublish(request); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function publish(request: NotificationRequest): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativePublish(request); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function publish(request: NotificationRequest, userId: number, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): void => { return nativePublishWithUserId(request, userId); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }
    
    export function publish(request: NotificationRequest, userId: number): Promise<void> {
        let error: BusinessError = isInvalidParameter(request);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativePublishWithUserId(request, userId); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function triggerSystemLiveView(
        bundle: BundleOption, notificationId: number, buttonOptions: ButtonOptions): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        error = isInvalidParameter(buttonOptions);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => {
                return nativeTriggerSystemLiveView(bundle, notificationId, buttonOptions); 
            });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
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
            let p = taskpool.execute((): void => { return nativeSubscribeSystemLiveView(subscriber); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function removeDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            let error: BusinessError = {
                code: 401,
                message: "templates must be not null"
            }
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeRemoveDoNotDisturbProfile(templates); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function addDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        if (!templates || templates.length === 0) {
            let error: BusinessError = {
                code: 401,
                message: "templates must be not null"
            }
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeAddDoNotDisturbProfile(templates); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getAllActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            let error: BusinessError = {
                code: 401,
                message: "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetAllActiveNotifications(); });
        p.then((data: NullishType): void => {
            let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let retData : Array<NotificationRequest> = [];
            let err: BusinessError = error as BusinessError;
            callback(err, retData);
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
            }, (error: Object): void => {
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
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getActiveNotifications(callback: AsyncCallback<Array<NotificationRequest>>): void {
        if (!callback) {
            let error: BusinessError = {
                code: 401,
                message: "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): Array<NotificationRequest> => { return nativeGetActiveNotifications(); });
        p.then((data: NullishType): void => {
            let ret : Array<NotificationRequest> = data as Array<NotificationRequest>;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let retData : Array<NotificationRequest> = [];
            let err: BusinessError = error as BusinessError;
            callback(err, retData);
        })
    }

    export function getActiveNotificationCount(): Promise<number> {
        let pPromise = new Promise<number>((resolve: ResolveCallback<number>, reject: RejectCallback):void => {
            let p = taskpool.execute((): number => { return nativeGetActiveNotificationCount(); });
            p.then((data :NullishType): void => {
                let ret : number = data as number;
                resolve(ret);
            }, (err:Object): void => {
                reject(err);
            });
        });
        return pPromise;
    }

    export function displayBadge(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        if (callback == null) {
            error.code = 401;
            error.message = "callback must be not null";
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeDisplayBadge(bundle, enable); });
        p.then((e: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }
    
    export function displayBadge(bundle: BundleOption, enable: boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeDisplayBadge(bundle, enable); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isBadgeDisplayed(bundle: BundleOption, callback: AsyncCallback<boolean>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }
    
    export function isBadgeDisplayed(bundle: BundleOption): Promise<boolean> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(bundle: BundleOption, id: number): Promise<void> {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== 0) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeCancelWithBundle(bundle, id); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(id: number, label?: string): Promise<void> {
        if (label == null || label?.length === 0) {
            let error: BusinessError = {
                code: 401,
                message: "Incorrect parameter types. The type of label must be string."
            }
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeCancelWithIdOptionalLabel(id, label); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancel(id: number, label: string, callback: AsyncCallback<void>): void {
        if (label == null || label?.length === 0) {
            let error: BusinessError = {
                code: 401,
                message: "Incorrect parameter types. The type of label must be string."
            }
            throw error;
        }
        if (callback == null) {
            let error: BusinessError = {
                code: 410,
                message : "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeCancelWithIdLabel(id, label); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function cancel(id: number, callback: AsyncCallback<void>): void {
        if (callback == null) {
            let error: BusinessError = {
                code: 410,
                message : "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeCancelWithId(id); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    export function cancelAll(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeCancelAll(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function cancelAll(callback: AsyncCallback<void>): void {
        if (callback == null) {
            let error: BusinessError = {
                code: 410,
                message : "callback must be not null"
            }
            throw error;
        }
        let p = taskpool.execute((): void => { return nativeCancelAll(); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
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
                (error: Object): void => {
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
                        callback(successCallbackError, undefined);
                    } else {
                        callback(callbackInternalError, undefined);
                    }
                }
            },
            (error: Object): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }
}